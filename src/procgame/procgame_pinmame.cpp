// license:BSD-3-Clause

// PinMAME procgame subsystem - the contract with src/wpc/procgame.c (procgame_public.h), over one
// ProcBridge. One machine runs at a time, so one bridge serves it.

#include "procgame_public.h"
#include "ProcBridge.h"

#include <cstdio>
#include <cstring>
#include <memory>

static_assert(PROCGAME_LAMPS == PROC_LAMP_COUNT && PROCGAME_COILS == PROC_COIL_COUNT && PROCGAME_GI == PROC_GI_COUNT,
              "the contract's output counts are the shared block's");
static_assert(PROCGAME_MAX_WIDTH == PROC_HD_MAX_WIDTH && PROCGAME_MAX_HEIGHT == PROC_HD_MAX_HEIGHT,
              "the contract's display limit is the shared block's");

namespace {

std::unique_ptr<procgame::ProcBridge> bridge;
// Set when the game process is seen gone, with why; procgame_running() keeps answering it
std::string stopped;
// The frame as the game drew it, before the palette (pyprocgame) or as RGB24 (SkeletonGame)
unsigned char frame[PROC_HD_MAX_BYTES];

void copy_text(const std::string &text, char *dst, unsigned size)
{
   if (dst && size)
      snprintf(dst, size, "%s", text.c_str());
}

}

extern "C" int procgame_is_game_dir(const char *dir)
{
   return dir && procgame::ProcBridge::IsGameDir(dir) ? 1 : 0;
}

extern "C" int procgame_start(const char *game_dir, unsigned timeout_ms, char *error, unsigned error_size)
{
   procgame_stop();
   stopped.clear();
   bridge = std::make_unique<procgame::ProcBridge>();
   if (!bridge->Start(game_dir ? game_dir : "") || !bridge->WaitReady(timeout_ms)) {
      copy_text(bridge->LastError(), error, error_size);
      bridge.reset();
      return 0;
   }
   return 1;
}

extern "C" void procgame_stop(void)
{
   if (bridge) {
      bridge->Stop();
      bridge.reset();
   }
}

extern "C" int procgame_running(char *reason, unsigned reason_size)
{
   if (bridge && stopped.empty()) {
      const bool alive = bridge->ChildAlive();
      if (alive && bridge->IsReady())
         return 1;
      stopped = alive ? "the game reported an error" : "the game process exited";
   }
   copy_text(stopped.empty() ? "not started" : stopped, reason, reason_size);
   return 0;
}

extern "C" int procgame_poll(void)
{
   return bridge && bridge->Poll() ? 1 : 0;
}

extern "C" int procgame_lamp(int number) { return bridge && bridge->GetLamp(number) ? 1 : 0; }
extern "C" int procgame_coil(int number) { return bridge && bridge->GetSolenoid(number) ? 1 : 0; }
extern "C" int procgame_gi(int index) { return bridge && bridge->GetGIString(index) ? 1 : 0; }

extern "C" void procgame_set_switch(int number, int closed)
{
   if (bridge)
      bridge->SetSwitch(number, closed != 0);
}

extern "C" void procgame_display_size(unsigned *width, unsigned *height)
{
   unsigned w = 0, h = 0;
   if (bridge) {
      w = bridge->HdWidth();
      h = bridge->HdHeight();
      if (!w || !h) {
         w = PROC_DMD_WIDTH;
         h = PROC_DMD_HEIGHT;
      }
   }
   if (width) *width = w;
   if (height) *height = h;
}

extern "C" int procgame_display_frame(unsigned char *rgb)
{
   if (!bridge || !rgb)
      return 0;
   if (bridge->HdWidth() && bridge->HdHeight()) {
      if (!bridge->CopyHdFrame(frame))
         return 0;
      memcpy(rgb, frame, (size_t)bridge->HdWidth() * bridge->HdHeight() * 3u);
      return 1;
   }
   uint32_t w = 0, h = 0;
   return bridge->CopyDmdFrameRGB24(rgb, w, h) ? 1 : 0;
}

extern "C" unsigned procgame_audio_rate(void) { return bridge ? bridge->AudioRate() : 0u; }
extern "C" unsigned procgame_audio_channels(void) { return bridge ? bridge->AudioChannels() : 0u; }

extern "C" unsigned procgame_audio(short *dst, unsigned frames)
{
   const unsigned channels = procgame_audio_channels();
   if (!bridge || !dst || !channels)
      return 0;
   const uint32_t frameBytes = channels * (uint32_t)sizeof(short);
   // ReadAudio counts bytes. The game writes whole frames and every bound it applies is a whole
   // number of them, so a frame is never split between two calls
   return bridge->ReadAudio((uint8_t *)dst, frames * frameBytes) / frameBytes;
}

extern "C" void procgame_stats(unsigned *heartbeat, unsigned *torn_reads, unsigned *audio_resyncs, unsigned *audio_dropped_bytes)
{
   if (heartbeat) *heartbeat = bridge ? bridge->Heartbeat() : 0u;
   if (torn_reads) *torn_reads = bridge ? bridge->TornReads() : 0u;
   if (audio_resyncs) *audio_resyncs = bridge ? bridge->AudioResyncs() : 0u;
   if (audio_dropped_bytes) *audio_dropped_bytes = bridge ? bridge->AudioDroppedBytes() : 0u;
}
