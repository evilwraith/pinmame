// license:BSD-3-Clause

// PinMAME procgame subsystem - ProcBridge owns the game process and the shared state block.
//
// Free of PinMAME headers, SDL and any logger: src/wpc/procgame.c reaches it through the plain C
// contract in procgame_public.h. It came from the 10.8.0 VPX fork, where a COM object drove it; the
// Changed*() getters, the switch shadow and the settings helper are still that object's, and stay
// until the fork's own copy is retired.
//
// Threading: every method is called from one thread and none of them waits on the child, except
// Start()/WaitReady(), which run once at machine start.

#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include "ProcShm.h"

namespace procgame {

// (VP number, state) -- the shape VPinMAME's ChangedLamps/ChangedSolenoids
// hand to a table script.
typedef std::pair<int, int> Change;

// One value from a SkeletonGame game's settings, typed the way the YAML had it.
struct ProcSetting
{
   enum class Kind { Integer, Real, Flag, Text } kind = Kind::Text;
   int64_t i = 0;
   double f = 0.0;
   std::string s;
};
// [section][key] -> value.
typedef std::map<std::string, std::map<std::string, ProcSetting>> ProcSettings;

class ProcBridge final
{
public:
   ProcBridge();
   ~ProcBridge();

   ProcBridge(const ProcBridge&) = delete;
   ProcBridge& operator=(const ProcBridge&) = delete;

   // Is there a pyprocgame game of this name installed? Cheap, no side
   // effects: this is what decides whether a table goes to P-ROC or to
   // libpinmame, so it is called before anything is started.
   static bool GameInstalled(const std::string& procRoot, const std::string& gameName);
   // Is this directory itself a pyprocgame game?
   static bool IsGameDir(const std::string& dir);
   static std::string GameDir(const std::string& procRoot, const std::string& gameName);

   // The game's operator settings, as horseyhorsey's VPROC bridge returned them
   // from Controller.GetSettings: config/game_default_settings.yaml, overlaid
   // by config/game_user_settings.yaml. Table scripts call it before Run --
   // Gremlins does, to decide whether to start B2S -- so this cannot go through
   // the child: it runs `python3 procbridge_host.py --settings` once and
   // parses what it prints. Blocks, so call it at table load only.
   static bool LoadSettings(const std::string& gameDir, ProcSettings& out, std::string& error);

   // Starts the child and maps the block. Does not wait for the game.
   bool Start(const std::string& gameDir);
   // Blocks until the game's setup() has returned, or the timeout expires.
   // Called once, from Run(), never per frame.
   bool WaitReady(uint32_t timeoutMs);
   void Stop();

   bool IsStarted() const { return m_pShm != nullptr; }
   bool IsReady() const;
   bool ChildAlive();

   const std::string& LastError() const { return m_lastError; }

   // --- per frame, none of these wait --------------------------------------

   // Publishes a VP switch change to the child. Drops the event if the ring is
   // full rather than blocking.
   void SetSwitch(int vpNumber, bool value);
   bool GetSwitch(int vpNumber) const;

   // Refreshes the local copy of the child's state. Call once per frame before
   // the Changed* getters. Returns false if the child was mid-write, in which
   // case the previous copy is kept and the getters report no changes.
   bool Poll();

   const std::vector<Change>& ChangedLamps();
   const std::vector<Change>& ChangedSolenoids();
   const std::vector<Change>& ChangedGIStrings();

   bool GetLamp(int vpNumber) const;
   bool GetSolenoid(int vpNumber) const;
   bool GetGIString(int index) const;

   // Copies the newest DMD frame if it changed since the last call.
   // dst must hold PROC_DMD_BYTES. Returns false when nothing is new.
   bool CopyDmdFrame(uint8_t* dst, uint32_t& width, uint32_t& height);

   // The same frame expanded to RGB24 through the game's palette.
   // dst must hold PROC_DMD_BYTES * 3.
   bool CopyDmdFrameRGB24(uint8_t* dst, uint32_t& width, uint32_t& height);

   // A SkeletonGame game's full-colour display. Zero size for a pyprocgame
   // game; fixed once the child is ready. CopyHdFrame copies the newest frame
   // if it changed; dst must hold PROC_HD_MAX_BYTES.
   uint32_t HdWidth() const { return m_pShm ? m_pShm->hdWidth : 0u; }
   uint32_t HdHeight() const { return m_pShm ? m_pShm->hdHeight : 0u; }
   bool CopyHdFrame(uint8_t* dst);

   // The format the child mixes at. Zero until it has started.
   uint32_t AudioRate() const { return m_pShm ? m_pShm->audioRate : 0u; }
   uint32_t AudioChannels() const { return m_pShm ? m_pShm->audioChannels : 0u; }
   // Drains up to maxBytes of mixed PCM. Returns bytes taken; 0 when the child
   // has produced nothing new, which is not an error.
   uint32_t ReadAudio(uint8_t* dst, uint32_t maxBytes);

   // Diagnostics only.
   uint32_t Heartbeat() const;
   // The VP switch numbers that changed since the last call, as text. Answers
   // "does the table ever set switch 35" without a trace of every frame.
   std::string TakeSwitchTrace();
   uint32_t TornReads() const { return m_tornReads; }
   // How often stale audio had to be thrown away to stay in sync, and how much.
   uint32_t AudioResyncs() const { return m_audioResyncs; }
   uint32_t AudioDroppedBytes() const { return m_audioDroppedBytes; }

private:
   void LoadPalette(const std::string& gameDir);
   bool MapShm();
   void UnmapShm();
   bool SpawnChild(const std::string& gameDir);
   static std::string FindHost(const std::string& gameDir);
   static std::vector<std::string> ChildEnvironment();
   void ReapChild();

   ProcShm* m_pShm = nullptr;
   int m_shmFd = -1;
   std::string m_shmName;
   std::string m_gameDir;
   int m_childPid = -1;
   std::string m_lastError;

   // The host's own copies. Poll() refreshes these; the Changed* getters diff
   // against what the script was last told, which is how VPinMAME behaves.
   uint8_t m_lamps[PROC_LAMP_COUNT] = { 0 };
   uint8_t m_coils[PROC_COIL_COUNT] = { 0 };
   uint8_t m_gi[PROC_GI_COUNT] = { 0 };
   uint8_t m_reportedLamps[PROC_LAMP_COUNT] = { 0 };
   uint8_t m_reportedCoils[PROC_COIL_COUNT] = { 0 };
   uint8_t m_reportedGi[PROC_GI_COUNT] = { 0 };
   bool m_haveState = false;

   uint8_t m_switches[256] = { 0 };

   std::vector<Change> m_changedLamps;
   std::vector<Change> m_changedCoils;
   std::vector<Change> m_changedGi;

   uint32_t m_lastDmdSeq = 0;
   uint32_t m_lastHdSeq = 0;
   uint8_t m_dmdScratch[PROC_DMD_BYTES] = { 0 };
   // [colour][brightness] -> RGB. Loaded from the game's dmd_palette.bin; a
   // plain white ramp if it has none, which is right for a game whose frames
   // carry brightness only.
   uint8_t m_palette[17 * 16 * 3] = { 0 };
   uint32_t m_tornReads = 0;
   uint8_t m_switchChanged[256] = { 0 };
   uint32_t m_audioResyncs = 0;
   uint32_t m_audioDroppedBytes = 0;
};

}
