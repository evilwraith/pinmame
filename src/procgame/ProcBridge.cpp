#include "ProcBridge.h"

#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <algorithm>
#include <cstring>
#include <vector>

#include <dlfcn.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace procgame {

// register_vpcom.py's ChangedSolenoids prefixes (0, True) before the first
// real change of every batch. It looks like an accident, but CCC's VP table
// was written and tested against it, so it is reproduced rather than quietly
// corrected. Flip this to drop it if a table is ever shown to mind.
static constexpr bool kEmulateRegisterVpcomCoilZero = true;

// The child is Python and starts a 40k-line game; setup() on a cabinet is far
// slower than in a devcontainer, and this runs behind the loading screen.
static constexpr uint32_t kDefaultReadyTimeoutMs = 30000;

static std::string EnvOr(const char* name, const char* fallback)
{
   const char* v = getenv(name);
   return (v && *v) ? std::string(v) : std::string(fallback);
}

static bool DirExists(const std::string& path)
{
   struct stat st;
   return stat(path.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
}

static bool FileExists(const std::string& path)
{
   struct stat st;
   return stat(path.c_str(), &st) == 0 && S_ISREG(st.st_mode);
}

std::string ProcBridge::GameDir(const std::string& procRoot, const std::string& gameName)
{
   if (procRoot.empty() || gameName.empty())
      return std::string();
   std::string dir = procRoot;
   if (dir.back() != '/')
      dir += '/';
   dir += gameName;
   return dir;
}

bool ProcBridge::IsGameDir(const std::string& dir)
{
   // A directory is a game if it holds a config the host can load. Two layouts
   // exist in the wild and neither is more correct than the other:
   //
   //   config.yaml at the root      pyprocgame's own convention -- CCCforVP
   //   config/machine.yaml          Dutch Pinball's BOP 2.0 and its framework
   //
   // Testing only the first made this check CCC-shaped, and BOP was rejected
   // with "no P-ROC game installed" when the directory was plainly there.
   if (dir.empty() || !DirExists(dir))
      return false;
   return FileExists(dir + "/config.yaml") || FileExists(dir + "/config/machine.yaml");
}

bool ProcBridge::GameInstalled(const std::string& procRoot, const std::string& gameName)
{
   return IsGameDir(GameDir(procRoot, gameName));
}

// `procbridge_host.py --settings <game>` prints one setting per line:
//   section US key US kind US value LF        (US = 0x1f; kind is i, f, b or s)
// Unit separators rather than tabs or '=' because SkeletonGame keys contain
// spaces ("VPTable Config Enabled") and nothing stops a value containing either.
static constexpr uint32_t kSettingsTimeoutMs = 15000;

bool ProcBridge::LoadSettings(const std::string& gameDir, ProcSettings& out, std::string& error)
{
   out.clear();
   const std::string python = EnvOr("VPX_PROC_PYTHON", "python3");
   const std::string host = FindHost(gameDir);
   if (host.empty()) {
      error = "procbridge_host.py not found beside libpinmame or " + gameDir;
      return false;
   }

   std::vector<std::string> envStrings = ChildEnvironment();
   std::vector<char*> envp;
   envp.reserve(envStrings.size() + 1);
   for (std::string& s : envStrings)
      envp.push_back(const_cast<char*>(s.c_str()));
   envp.push_back(nullptr);

   int fds[2];
   if (pipe2(fds, O_CLOEXEC) != 0) {
      error = std::string("pipe failed: ") + strerror(errno);
      return false;
   }

   const pid_t pid = fork();
   if (pid < 0) {
      close(fds[0]);
      close(fds[1]);
      error = std::string("fork failed: ") + strerror(errno);
      return false;
   }
   if (pid == 0) {
      // Async-signal-safe calls only, as in SpawnChild.
      dup2(fds[1], STDOUT_FILENO);
      const int devnull = open("/dev/null", O_WRONLY);
      if (devnull >= 0)
         dup2(devnull, STDERR_FILENO);
      const char* argv[] = { python.c_str(), host.c_str(), "--settings", gameDir.c_str(), nullptr };
      execvpe(python.c_str(), (char* const*)argv, envp.data());
      _exit(127);
   }
   close(fds[1]);

   // Bounded: a wedged interpreter must not hang table load forever.
   std::string text;
   char buf[4096];
   uint32_t waited = 0;
   bool timedOut = false;
   for (;;) {
      struct pollfd pfd = { fds[0], POLLIN, 0 };
      const int r = poll(&pfd, 1, 100);
      if (r < 0 && errno == EINTR)
         continue;
      if (r == 0) {
         waited += 100;
         if (waited >= kSettingsTimeoutMs) {
            timedOut = true;
            break;
         }
         continue;
      }
      const ssize_t n = read(fds[0], buf, sizeof(buf));
      if (n < 0 && errno == EINTR)
         continue;
      if (n <= 0)
         break;
      text.append(buf, (size_t)n);
   }
   close(fds[0]);
   if (timedOut)
      kill(pid, SIGKILL);
   int status = 0;
   while (waitpid(pid, &status, 0) < 0 && errno == EINTR) { }
   if (timedOut) {
      error = "settings helper timed out";
      return false;
   }
   if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
      error = "settings helper failed (exit " + std::to_string(WIFEXITED(status) ? WEXITSTATUS(status) : -1) + ")";
      return false;
   }

   size_t start = 0;
   while (start < text.size()) {
      size_t end = text.find('\n', start);
      if (end == std::string::npos)
         end = text.size();
      const std::string line = text.substr(start, end - start);
      start = end + 1;
      std::string field[4];
      size_t f = 0, pos = 0;
      for (; f < 3; f++) {
         const size_t us = line.find('\x1f', pos);
         if (us == std::string::npos)
            break;
         field[f] = line.substr(pos, us - pos);
         pos = us + 1;
      }
      if (f != 3)
         continue;
      field[3] = line.substr(pos);
      ProcSetting v;
      switch (field[2].empty() ? 's' : field[2][0]) {
      case 'i': v.kind = ProcSetting::Kind::Integer; v.i = strtoll(field[3].c_str(), nullptr, 10); break;
      case 'f': v.kind = ProcSetting::Kind::Real; v.f = strtod(field[3].c_str(), nullptr); break;
      case 'b': v.kind = ProcSetting::Kind::Flag; v.i = (field[3] == "1") ? 1 : 0; break;
      default: v.kind = ProcSetting::Kind::Text; v.s = field[3]; break;
      }
      out[field[0]][field[1]] = v;
   }
   return true;
}

ProcBridge::ProcBridge() = default;

ProcBridge::~ProcBridge()
{
   Stop();
}

// ---------------------------------------------------------------------------
// setup and teardown
// ---------------------------------------------------------------------------

bool ProcBridge::MapShm()
{
   char name[64];
   snprintf(name, sizeof(name), "/vpx-proc-%d", (int)getpid());
   m_shmName = name;

   // Unlink first: a previous run that was killed leaves the segment behind,
   // and re-using it would inherit its state.
   shm_unlink(m_shmName.c_str());

   m_shmFd = shm_open(m_shmName.c_str(), O_CREAT | O_EXCL | O_RDWR, 0600);
   if (m_shmFd < 0) {
      m_lastError = std::string("shm_open failed: ") + strerror(errno);
      return false;
   }
   if (ftruncate(m_shmFd, (off_t)sizeof(ProcShm)) != 0) {
      m_lastError = std::string("ftruncate failed: ") + strerror(errno);
      UnmapShm();
      return false;
   }

   void* p = mmap(nullptr, sizeof(ProcShm), PROT_READ | PROT_WRITE, MAP_SHARED, m_shmFd, 0);
   if (p == MAP_FAILED) {
      m_lastError = std::string("mmap failed: ") + strerror(errno);
      UnmapShm();
      return false;
   }

   m_pShm = (ProcShm*)p;
   memset(m_pShm, 0, sizeof(ProcShm));
   m_pShm->magic = PROC_SHM_MAGIC;
   m_pShm->version = PROC_SHM_VERSION;
   m_pShm->structSize = (uint32_t)sizeof(ProcShm);
   m_pShm->dmdWidth = PROC_DMD_WIDTH;
   m_pShm->dmdHeight = PROC_DMD_HEIGHT;
   return true;
}

void ProcBridge::UnmapShm()
{
   if (m_pShm) {
      munmap(m_pShm, sizeof(ProcShm));
      m_pShm = nullptr;
   }
   if (m_shmFd >= 0) {
      close(m_shmFd);
      m_shmFd = -1;
   }
   if (!m_shmName.empty()) {
      shm_unlink(m_shmName.c_str());
      m_shmName.clear();
   }
}

// The directory of the library this code is linked into: libpinmame, in the VPX cart's root.
static std::string OwnLibraryDir()
{
   Dl_info info;
   if (!dladdr((const void*)&OwnLibraryDir, &info) || !info.dli_fname)
      return std::string();
   const std::string path = info.dli_fname;
   const size_t slash = path.find_last_of('/');
   return (slash == std::string::npos) ? std::string(".") : path.substr(0, slash);
}

std::string ProcBridge::FindHost(const std::string& gameDir)
{
   // The runtime -- procbridge_host.py with procbridge/, the pygame and cv2 stand-ins, pySDL2 --
   // ships once, beside libpinmame, so a game tree holds only its game. A tree from before that
   // carried the runtime itself, beside the games or inside one; those are still found, after.
   // Resolved here rather than left to the child's cwd, because execvp resolves argv[1] against
   // the host's working directory, which is not the game's.
   std::string host = EnvOr("VPX_PROC_HOST", "");
   if (!host.empty())
      return host;
   const std::string libDir = OwnLibraryDir();
   if (!libDir.empty() && FileExists(libDir + "/procgame/procbridge_host.py"))
      return libDir + "/procgame/procbridge_host.py";
   const size_t slash = gameDir.find_last_of('/');
   const std::string procRoot = (slash == std::string::npos) ? gameDir : gameDir.substr(0, slash);
   const char* const candidates[] = { "/procbridge_host.py", "/../procbridge_host.py" };
   for (const char* suffix : candidates) {
      const std::string candidate = procRoot + suffix;
      if (FileExists(candidate))
         return candidate;
   }
   if (FileExists(gameDir + "/procbridge_host.py"))
      return gameDir + "/procbridge_host.py";
   return std::string();
}

// Built BEFORE fork: after fork in a multithreaded process only
// async-signal-safe calls are allowed, and building strings allocates.
std::vector<std::string> ProcBridge::ChildEnvironment()
{
   // The child must NOT inherit VPX's library path. VPX runs out of a cart
   // that ships its own libSDL2, and that build has no ALSA driver at all --
   // only "dummy" -- because VPX does not use SDL for audio on this device.
   // The child, which does, then loaded the cart's SDL2 and failed with
   // "No such audio device". The system libSDL2 has ALSA, and the child is an
   // ordinary python3 process with no business in the cart's Mali/SDL stack.
   //
   // Stripping LD_LIBRARY_PATH is only safe while the child touches no GL or
   // EGL. The cart's Mali blob must be first on that path for every process
   // that does: a bare eglInitialize through the system libmali Oopsed the
   // kernel in drm_setversion on an RK3588 cabinet and left it tainted until
   // a reboot.
   //
   // A SkeletonGame child does load an SDL2 (the cart's, by path -- see
   // procbridge_host.py guard_sdl) to draw its HD display, and SDL dlopens
   // libEGL for any GL renderer. So the
   // environment pins it to the paths that cannot reach one: the dummy video
   // driver, the software renderer, and EGL/GL library paths that do not
   // exist, so even a code path that asks for GL fails to load anything
   // rather than finding the system libmali. procbridge_host.py sets the same
   // again before SDL is imported; this is the copy that holds even if it
   // does not.
   //
   // LD_PRELOAD is the env var only; the virtiofs hole-bug workaround is
   // installed through /etc/ld.so.preload and is unaffected.
   static const char* const kStripped[] = {
      "LD_LIBRARY_PATH", "LD_PRELOAD", "SDL_AUDIODRIVER", "SDL_VIDEODRIVER",
      "SDL_RENDER_DRIVER", "SDL_VIDEO_EGL_DRIVER", "SDL_VIDEO_GL_DRIVER"
   };
   std::vector<std::string> envStrings;
   for (char** e = environ; e && *e; e++) {
      const char* const eq = strchr(*e, '=');
      const size_t nameLen = eq ? (size_t)(eq - *e) : strlen(*e);
      bool strip = false;
      for (const char* name : kStripped) {
         if (strlen(name) == nameLen && strncmp(*e, name, nameLen) == 0) {
            strip = true;
            break;
         }
      }
      if (!strip)
         envStrings.emplace_back(*e);
   }
   envStrings.emplace_back("SDL_VIDEODRIVER=dummy");
   envStrings.emplace_back("SDL_AUDIODRIVER=dummy");
   envStrings.emplace_back("SDL_RENDER_DRIVER=software");
   envStrings.emplace_back("SDL_VIDEO_EGL_DRIVER=/nonexistent/libEGL.so");
   envStrings.emplace_back("SDL_VIDEO_GL_DRIVER=/nonexistent/libGL.so");
   return envStrings;
}

// The interpreter for a game. A port (skeleton/port.py, port.sh) says so on its config.yaml's
// first line and runs on the system's python3. Anything else is a game as it was distributed --
// pyprocgame and SkeletonGame were Python 2 frameworks -- and runs on the Python 2.7 the runtime
// carries beside the host script (py27/), when it carries one. VPX_PROC_PYTHON overrides both.
std::string ProcBridge::PythonFor(const std::string& gameDir, const std::string& host)
{
   const std::string forced = EnvOr("VPX_PROC_PYTHON", "");
   if (!forced.empty())
      return forced;
   bool ported = false;
   if (FILE* f = fopen((gameDir + "/config.yaml").c_str(), "r")) {
      char line[256] = { 0 };
      if (fgets(line, sizeof(line), f))
         ported = strstr(line, "Rewritten by backport/proc/") != nullptr;
      fclose(f);
   }
   if (!ported) {
      const size_t slash = host.find_last_of('/');
      const std::string py27 = (slash == std::string::npos ? std::string(".") : host.substr(0, slash)) + "/py27/bin/python2.7";
      if (FileExists(py27))
         return py27;
   }
   return "python3";
}

bool ProcBridge::SpawnChild(const std::string& gameDir)
{
   // Where the host script lives and which interpreter runs it are settings,
   // not constants: the cart layout differs between the trees and the desktop.
   const std::string host = FindHost(gameDir);
   const std::string python = PythonFor(gameDir, host);
   if (host.empty()) {
      m_lastError = "procbridge_host.py not found beside libpinmame or " + gameDir;
      return false;
   }
   // pyprocgame's run loop has no limiter and spins as fast as the CPU allows
   // (~20k iterations/s measured). The game only has to keep up with a 60 Hz
   // DMD, so cap it -- a whole core spent spinning is a core VPX does not get.
   const std::string tickHz = EnvOr("VPX_PROC_TICK_HZ", "250");

   // The child's stdout and stderr belong to VPX, which does not keep them --
   // so a Python traceback, or "sound disabled, SDL_mixer unavailable", goes
   // nowhere. Give it its own log beside the game.
   const std::string logPath = gameDir + "/procbridge_host.log";

   std::vector<std::string> envStrings = ChildEnvironment();
   std::vector<char*> envp;
   envp.reserve(envStrings.size() + 1);
   for (std::string& s : envStrings)
      envp.push_back(const_cast<char*>(s.c_str()));
   envp.push_back(nullptr);

   const pid_t pid = fork();
   if (pid < 0) {
      m_lastError = std::string("fork failed: ") + strerror(errno);
      return false;
   }

   if (pid == 0) {
      // Child. Nothing here may allocate or take a lock that the parent's
      // other threads might hold at fork time, so this is execvp and little
      // else. If exec fails there is nothing sensible to report: _exit.
      setpgid(0, 0);   // so Stop() can kill the whole group, not just python
      const char* argv[] = {
         python.c_str(), host.c_str(),
         "--tree", gameDir.c_str(),
         "--shm", m_shmName.c_str(),
         "--tick-hz", tickHz.c_str(),
         "--log", logPath.c_str(),
         nullptr
      };
      execvpe(python.c_str(), (char* const*)argv, envp.data());
      _exit(127);
   }

   m_childPid = (int)pid;
   return true;
}

void ProcBridge::LoadPalette(const std::string& gameDir)
{
   // Default: white, brightness in the low nibble, no colour. Correct for any
   // pyprocgame game that does not colour its dots.
   memset(m_palette, 0, sizeof(m_palette));
   for (int level = 0; level < 16; level++) {
      const uint8_t v = (uint8_t)((255 * level + 7) / 15);
      uint8_t* const p = &m_palette[(16 * 16 + level) * 3];
      p[0] = p[1] = p[2] = v;
   }

   const std::string path = gameDir + "/dmd_palette.bin";
   FILE* const f = fopen(path.c_str(), "rb");
   if (!f)
      return;
   uint8_t loaded[sizeof(m_palette)];
   const size_t got = fread(loaded, 1, sizeof(loaded), f);
   fclose(f);
   if (got == sizeof(loaded))
      memcpy(m_palette, loaded, sizeof(m_palette));
}

bool ProcBridge::Start(const std::string& gameDir)
{
   if (m_pShm)
      return true;
   if (!DirExists(gameDir)) {
      m_lastError = "game directory not found: " + gameDir;
      return false;
   }
   m_gameDir = gameDir;
   LoadPalette(gameDir);
   if (!MapShm())
      return false;
   if (!SpawnChild(gameDir)) {
      UnmapShm();
      return false;
   }
   m_pShm->hostAlive = 1;
   return true;
}

bool ProcBridge::WaitReady(uint32_t timeoutMs)
{
   if (!m_pShm)
      return false;
   if (timeoutMs == 0)
      timeoutMs = kDefaultReadyTimeoutMs;

   // The only wait in this class, and it runs once, at table load, behind the
   // loading screen -- never on a frame.
   for (uint32_t waited = 0; waited < timeoutMs; waited += 10) {
      if (m_pShm->gameError) {
         m_lastError = "pyprocgame child reported an error during setup";
         return false;
      }
      if (m_pShm->gameReady) {
         // Again now: a game run as distributed derives its palette from its dot images during
         // setup (the runtime's procbridge/palette.py), after Start() first looked for one
         LoadPalette(m_gameDir);
         return true;
      }
      if (!ChildAlive()) {
         m_lastError = "pyprocgame child exited before the game was ready";
         return false;
      }
      usleep(10 * 1000);
   }
   m_lastError = "timed out waiting for the pyprocgame child";
   return false;
}

bool ProcBridge::IsReady() const
{
   return m_pShm && m_pShm->gameReady && !m_pShm->gameError;
}

bool ProcBridge::ChildAlive()
{
   if (m_childPid <= 0)
      return false;
   int status = 0;
   const pid_t r = waitpid(m_childPid, &status, WNOHANG);
   if (r == 0)
      return true;
   if (r == m_childPid)
      m_childPid = -1;
   return false;
}

void ProcBridge::ReapChild()
{
   if (m_childPid <= 0)
      return;

   // Ask first: hostStop lets the game leave its run loop and flush whatever
   // it keeps on disk (CCC writes high scores and settings on the way out).
   if (m_pShm)
      m_pShm->hostStop = 1;

   for (int i = 0; i < 200; i++) {   // up to 2s
      int status = 0;
      if (waitpid(m_childPid, &status, WNOHANG) == m_childPid) {
         m_childPid = -1;
         return;
      }
      usleep(10 * 1000);
   }

   kill(-m_childPid, SIGTERM);
   for (int i = 0; i < 100; i++) {
      int status = 0;
      if (waitpid(m_childPid, &status, WNOHANG) == m_childPid) {
         m_childPid = -1;
         return;
      }
      usleep(10 * 1000);
   }

   kill(-m_childPid, SIGKILL);
   int status = 0;
   waitpid(m_childPid, &status, 0);
   m_childPid = -1;
}

void ProcBridge::Stop()
{
   ReapChild();
   UnmapShm();
   m_haveState = false;
}

// ---------------------------------------------------------------------------
// per frame
// ---------------------------------------------------------------------------

void ProcBridge::SetSwitch(int vpNumber, bool value)
{
   if (vpNumber < 0 || vpNumber >= (int)sizeof(m_switches))
      return;
   const uint8_t newValue = value ? 1 : 0;
   if (m_switches[vpNumber] != newValue)
      m_switchChanged[vpNumber] = 1;
   m_switches[vpNumber] = newValue;
   if (!m_pShm)
      return;

   const uint32_t head = m_pShm->swHead;
   const uint32_t tail = m_pShm->swTail;
   // Full means the child has fallen a whole ring behind. Dropping the event
   // is wrong, but blocking the frame to wait for it is worse, and 1024
   // pending switch changes means the game is already gone.
   if (head - tail >= PROC_SW_RING)
      return;

   m_pShm->swRing[head & PROC_SW_MASK] = PROC_SW_PACK((uint16_t)vpNumber, value);
   // The event must be visible before the index that publishes it.
   std::atomic_thread_fence(std::memory_order_release);
   m_pShm->swHead = head + 1;
}

bool ProcBridge::GetSwitch(int vpNumber) const
{
   if (vpNumber < 0 || vpNumber >= (int)sizeof(m_switches))
      return false;
   return m_switches[vpNumber] != 0;
}

bool ProcBridge::Poll()
{
   if (!m_pShm)
      return false;

   // Read-modify-write on a volatile is deprecated in C++20 and says less
   // than it looks: this is a liveness counter the child only compares
   // against its own last sample, so a lost increment costs nothing.
   m_pShm->hostAlive = m_pShm->hostAlive + 1;

   const uint32_t s0 = m_pShm->seq;
   if (s0 & 1u) {
      // Child is mid-write. Keep what we have; do not spin.
      m_tornReads++;
      return false;
   }
   std::atomic_thread_fence(std::memory_order_acquire);

   uint8_t lamps[PROC_LAMP_COUNT];
   uint8_t coils[PROC_COIL_COUNT];
   uint8_t gi[PROC_GI_COUNT];
   memcpy(lamps, (const void*)m_pShm->lamps, sizeof(lamps));
   memcpy(coils, (const void*)m_pShm->coils, sizeof(coils));
   memcpy(gi, (const void*)m_pShm->gi, sizeof(gi));

   std::atomic_thread_fence(std::memory_order_acquire);
   if (m_pShm->seq != s0) {
      m_tornReads++;
      return false;
   }

   memcpy(m_lamps, lamps, sizeof(lamps));
   memcpy(m_coils, coils, sizeof(coils));
   memcpy(m_gi, gi, sizeof(gi));
   m_haveState = true;
   return true;
}

const std::vector<Change>& ProcBridge::ChangedLamps()
{
   m_changedLamps.clear();
   if (m_haveState) {
      for (int i = 0; i < PROC_LAMP_COUNT; i++) {
         if (m_lamps[i] != m_reportedLamps[i]) {
            m_changedLamps.emplace_back(i, m_lamps[i] ? 1 : 0);
            m_reportedLamps[i] = m_lamps[i];
         }
      }
   }
   return m_changedLamps;
}

const std::vector<Change>& ProcBridge::ChangedSolenoids()
{
   m_changedCoils.clear();
   if (m_haveState) {
      bool first = true;
      for (int i = 0; i < PROC_COIL_COUNT; i++) {
         if (m_coils[i] != m_reportedCoils[i]) {
            if (first && kEmulateRegisterVpcomCoilZero) {
               m_changedCoils.emplace_back(0, 1);
               first = false;
            }
            m_changedCoils.emplace_back(i, m_coils[i] ? 1 : 0);
            m_reportedCoils[i] = m_coils[i];
         }
      }
   }
   return m_changedCoils;
}

const std::vector<Change>& ProcBridge::ChangedGIStrings()
{
   m_changedGi.clear();
   if (m_haveState) {
      for (int i = 0; i < PROC_GI_COUNT; i++) {
         if (m_gi[i] != m_reportedGi[i]) {
            m_changedGi.emplace_back(i, m_gi[i] ? 1 : 0);
            m_reportedGi[i] = m_gi[i];
         }
      }
   }
   return m_changedGi;
}

bool ProcBridge::GetLamp(int vpNumber) const
{
   return vpNumber >= 0 && vpNumber < PROC_LAMP_COUNT && m_lamps[vpNumber] != 0;
}

bool ProcBridge::GetSolenoid(int vpNumber) const
{
   return vpNumber >= 0 && vpNumber < PROC_COIL_COUNT && m_coils[vpNumber] != 0;
}

bool ProcBridge::GetGIString(int index) const
{
   return index >= 0 && index < PROC_GI_COUNT && m_gi[index] != 0;
}

bool ProcBridge::CopyDmdFrame(uint8_t* dst, uint32_t& width, uint32_t& height)
{
   if (!m_pShm || !dst)
      return false;

   const uint32_t s0 = m_pShm->dmdSeq;
   if ((s0 & 1u) || s0 == m_lastDmdSeq)
      return false;
   std::atomic_thread_fence(std::memory_order_acquire);

   const uint32_t w = m_pShm->dmdWidth;
   const uint32_t h = m_pShm->dmdHeight;
   if (w == 0 || h == 0 || w * h > PROC_DMD_BYTES)
      return false;
   memcpy(dst, (const void*)m_pShm->dmd, w * h);

   std::atomic_thread_fence(std::memory_order_acquire);
   if (m_pShm->dmdSeq != s0) {
      m_tornReads++;
      return false;
   }

   m_lastDmdSeq = s0;
   width = w;
   height = h;
   return true;
}

bool ProcBridge::CopyDmdFrameRGB24(uint8_t* dst, uint32_t& width, uint32_t& height)
{
   if (!dst || !CopyDmdFrame(m_dmdScratch, width, height))
      return false;

   // One byte per dot: low nibble brightness, high nibble colour index. The
   // bucketing is not ours -- it is what the game's own renderer does
   // (ep/ep_desktop_pygame.py draw()), and a dot only reads correctly if the
   // same thresholds are used.
   const uint32_t count = width * height;
   for (uint32_t i = 0; i < count; i++) {
      const uint8_t v = m_dmdScratch[i];
      if (v == 0) {
         dst[i * 3 + 0] = dst[i * 3 + 1] = dst[i * 3 + 2] = 0;
         continue;
      }
      const int lo = v & 0x0f;
      const int hi = v >> 4;

      int colour, level;
      if (hi == 0) {
         // No colour index: white, at the full 0-15 brightness.
         colour = 16;
         level = lo;
      }
      else {
         colour = hi;
         level = (lo <= 3) ? 0 : (lo <= 8) ? 1 : (lo <= 13) ? 2 : 3;
      }

      const uint8_t* const p = &m_palette[(colour * 16 + level) * 3];
      dst[i * 3 + 0] = p[0];
      dst[i * 3 + 1] = p[1];
      dst[i * 3 + 2] = p[2];
   }
   return true;
}

bool ProcBridge::CopyHdFrame(uint8_t* dst)
{
   if (!m_pShm || !dst)
      return false;

   const uint32_t s0 = m_pShm->hdSeq;
   if ((s0 & 1u) || s0 == m_lastHdSeq)
      return false;
   std::atomic_thread_fence(std::memory_order_acquire);

   const uint32_t w = m_pShm->hdWidth;
   const uint32_t h = m_pShm->hdHeight;
   if (w == 0 || h == 0 || w > PROC_HD_MAX_WIDTH || h > PROC_HD_MAX_HEIGHT)
      return false;
   memcpy(dst, (const void*)m_pShm->hd, (size_t)w * h * 3u);

   std::atomic_thread_fence(std::memory_order_acquire);
   if (m_pShm->hdSeq != s0) {
      m_tornReads++;
      return false;
   }

   m_lastHdSeq = s0;
   return true;
}

uint32_t ProcBridge::ReadAudio(uint8_t* dst, uint32_t maxBytes)
{
   if (!m_pShm || !dst || maxBytes == 0)
      return 0;

   const uint32_t write = m_pShm->audioWrite;
   uint32_t read = m_pShm->audioRead;
   // Free-running counters, so this is the true fill even across a wrap.
   uint32_t available = write - read;
   if (available == 0)
      return 0;

   // Anything beyond a short backlog is stale and must be thrown away, not
   // played. When VPX's script thread stalls, the child keeps mixing at
   // wall-clock rate and the ring fills; handing all of that to the audio
   // stream on resume does not catch up, it becomes permanent latency --
   // every sound for the rest of the game arrives a ring-depth late. That is
   // the "audio was unsynced for the rest of the game" after a menu hang.
   // Dropping to the newest audio is what a device does after an underrun.
   const uint32_t rate = m_pShm->audioRate ? m_pShm->audioRate : 44100u;
   const uint32_t channels = m_pShm->audioChannels ? m_pShm->audioChannels : 2u;
   // 200 ms: comfortably above the child's 120 ms prebuffer, so ordinary
   // running never trips this, and well under the 370 ms the ring holds.
   const uint32_t maxBacklog = (rate * channels * 2u) / 5u;
   if (available > maxBacklog) {
      // Jump straight to the newest audio, in one step. An earlier version
      // clamped `available` to the ring size first and then advanced `read` by
      // only what that clamp allowed, so a gap larger than the ring was ground
      // down a ring-length at a time instead of resolved -- on the cabinet
      // that produced over a million resyncs and 1.8 GB "dropped" across one
      // session, at a steady ~8.9 MB/s, which is precisely the grind rate.
      // Setting read from write resolves any overrun, however large, at once.
      const uint32_t drop = available - maxBacklog;
      read = write - maxBacklog;
      m_pShm->audioRead = read;
      available = maxBacklog;
      m_audioResyncs++;
      m_audioDroppedBytes += drop;
   }

   // maxBacklog is well under the ring, so after a resync this always holds;
   // before one, the producer cannot have got ahead without tripping it.
   if (available > PROC_AUDIO_RING)
      available = PROC_AUDIO_RING;

   if (available > maxBytes)
      available = maxBytes;

   std::atomic_thread_fence(std::memory_order_acquire);

   const uint32_t start = read & PROC_AUDIO_MASK;
   const uint32_t first = std::min(available, (uint32_t)PROC_AUDIO_RING - start);
   memcpy(dst, (const void*)&m_pShm->audioRing[start], first);
   if (first < available)
      memcpy(dst + first, (const void*)&m_pShm->audioRing[0], available - first);

   // Publish the read index only after the copy, or the child may overwrite
   // bytes we have not taken yet.
   std::atomic_thread_fence(std::memory_order_release);
   m_pShm->audioRead = read + available;
   return available;
}

std::string ProcBridge::TakeSwitchTrace()
{
   std::string out;
   for (int i = 0; i < 256; i++) {
      if (!m_switchChanged[i])
         continue;
      m_switchChanged[i] = 0;
      if (!out.empty())
         out += ',';
      out += std::to_string(i);
      out += m_switches[i] ? '+' : '-';
   }
   return out;
}

uint32_t ProcBridge::Heartbeat() const
{
   return m_pShm ? m_pShm->heartbeat : 0u;
}

}
