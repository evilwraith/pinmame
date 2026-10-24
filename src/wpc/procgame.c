// license:BSD-3-Clause

/************************************************************************************************
  P-ROC games (pyprocgame, SkeletonGame)

  A P-ROC game is a Python program that ran a real machine through a P-ROC board in place of the
  machine's own CPU board: Cactus Canyon Continued on a Cactus Canyon, and the SkeletonGame titles
  Visual Pinball tables were made for. It has no ROM. src/procgame runs it as a separate process
  with a fake board that reads and writes a block of shared memory; this driver makes that a
  PinMAME machine, so a table drives it as it drives any other through the controller.

  The game is a directory, pinmame/proc/<set>/, beside roms/. The set's one ROM is a short
  manifest (backport tool procgame_manifest.py writes it), which gives the machine an identity and
  refuses a tree ported for another version of the shared block.

  Numbers are VPinMAME's for a WPC machine, which the game process already speaks (it was made to
  look like VPinMAME to the tables):
    switches 1-8            dedicated (SD1-SD8)
    switches 11-98          the matrix (S11-S98)
    switches 111-118        the flipper switches (SF1-SF8), in PinMAME's flipper column
    solenoids 1-63          as the game numbers them: 1-28 the machine's coils, 34/36/46/48 the
                            flipper hold coils, the rest as the machine has them (37-44 the WPC-95
                            extras, 51-63 others). The core reads every one of them from this
                            driver as numbered (GEN_PROCGAME), because its WPC paths fold some of
                            them together (37-40 onto 41-44) and the tables tell them apart
    lamps 11-88             the lamp matrix
    GI 0-4                  the GI strings, on or off: the tables set light states from them, so
                            they are 0 and 1 rather than WPC's 0-8 brightness
  The flippers are the game's: it fires them by its own rules, so the core fakes no flipper coils.

  The display is the game's, as video: a SkeletonGame game draws full colour at the size its
  config asks for (Gremlins 271x148), a pyprocgame game 128x32 dots of colour index and
  brightness, expanded through its palette. On the real machines these were screens in the DMD's
  place, so the layout says so (CORE_VIDEO_DMD) and a host shows them where it shows a DMD.
************************************************************************************************/

#include "driver.h"
#include "core.h"
#include "cpuintrf.h"
#include "usrintrf.h"
#include "procgame.h"
#include "../procgame/procgame_public.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if HAS_PROCGAME

#define PROCGAME_CPU_HZ     1000000 /* the CPU runs nothing; its clock only sizes MAME's slices */
#define PROCGAME_IOFREQ     1000    /* the I/O exchange: a switch change reaches the game within 1 ms */
#define PROCGAME_AUDIO_RATE 44100   /* the stream's rate until the game reports its own */
#define PROCGAME_MAXSW      96      /* the matrix entries the switch numbers reach, flipper column included */
#define PROCGAME_NCUSTSOLS  (CORE_MAXSOL - CORE_FIRSTCUSTSOL + 1) /* 51-64 */
/* The flipper outputs are the game's own (FLIP_SOL), without the core's end-of-stroke switches
   that FLIP_SOL also asks for: the game has its own EOS switch handling */
#define PROCGAME_FLIPPERS   (FLIP_SW(FLIP_L) | ((FLIP_L) << 24))

/* PROCGAME_LOG set in the environment: every five seconds, the game's heartbeat and what the sound
   stream asked for and got, and each switch change passed to the game */
static struct { int on; unsigned frames, asked, got, late, shortfalls, switches; } diag;

static struct {
  int running, warned;
  unsigned width, height;          /* the game's display, as it reported it */
  unsigned audioRate, channels;
  UINT8 swState[PROCGAME_MAXSW];   /* each switch as last handed to the game */
  UINT32 swSeen[PROCGAME_MAXSW];   /* the count of changes to it as of the last look */
  UINT8 swAgain[PROCGAME_MAXSW];   /* the last look found a change half made: the next one takes what it finds */
  UINT8 coil[PROCGAME_COILS];      /* each solenoid as the last I/O exchange took it */
} locals;

static int procgame_stream = -1; /* the sound stream's first channel, the left; the right follows */

/*-------------------------------------------------
/  the CPU: nothing to run, the game is a process of its own
/-------------------------------------------------*/
int procgamecpu_ICount;

void procgamecpu_init(void) {}
void procgamecpu_reset(void *param) { (void)param; }
void procgamecpu_exit(void) {}

int procgamecpu_execute(int cycles)
{
  procgamecpu_ICount = 0;
  return cycles;
}

/* cpuintrf_init_cpu() refuses a CPU without a context, though this one has none */
unsigned procgamecpu_get_context(void *dst) { (void)dst; return sizeof(void *); }
void procgamecpu_set_context(void *src) { (void)src; }
unsigned procgamecpu_get_reg(int regnum) { (void)regnum; return 0; }
void procgamecpu_set_reg(int regnum, unsigned val) { (void)regnum; (void)val; }
void procgamecpu_set_irq_line(int irqline, int state) { (void)irqline; (void)state; }
void procgamecpu_set_irq_callback(int (*callback)(int irqline)) { (void)callback; }

const char *procgamecpu_info(void *context, int regnum)
{
  (void)context;
  switch (regnum) {
  case CPU_INFO_NAME: return "P-ROC game";
  case CPU_INFO_FAMILY: return "P-ROC (pyprocgame, SkeletonGame)";
  case CPU_INFO_VERSION: return "1.0";
  case CPU_INFO_FILE: return __FILE__;
  case CPU_INFO_CREDITS: return "The game runs as a process of its own";
  }
  return "";
}

unsigned procgamecpu_dasm(char *buffer, unsigned pc) { (void)pc; strcpy(buffer, "???"); return 4; }

static MEMORY_READ32_START(procgame_readmem)
  { 0x00000000, 0x00000003, MRA32_NOP },
MEMORY_END

static MEMORY_WRITE32_START(procgame_writemem)
  { 0x00000000, 0x00000003, MWA32_NOP },
MEMORY_END

/*-------------------------------------------------
/  switch and lamp numbers <-> PinMAME's matrix: WPC's (col * 10 + row, both from 1; the
/  dedicated switches are column 0, the flipper switches column 11)
/-------------------------------------------------*/
static int procgame_sw2m(int no) { return (no / 10) * 8 + (no % 10 - 1); }
static int procgame_m2sw(int col, int row) { return col * 10 + row + 1; }

/*-------------------------------------------------
/  the I/O, every millisecond (PROCGAME_IOFREQ): switch changes go to the game, its outputs come
/  back. The game polls its switch queue every loop (250 Hz) and publishes its outputs as often
/-------------------------------------------------*/

/* A table sets switches from its own thread, and VPX runs a frame's physics in a burst: a fast ball
   through a trigger closes and opens it within a fraction of a millisecond, between two looks here.
   The core counts each change it makes (core_swChangedHook), so such a closure still reaches the
   game - closed, then open */
static volatile UINT32 procgame_swChanges[128];

static void procgame_swChanged(int m)
{
  if (m >= 0 && m < 128) procgame_swChanges[m]++;
}

static void procgame_sync_switches(void)
{
  int m;
  for (m = 0; m < PROCGAME_MAXSW; m++) {
    /* the count, then the level. core_setSw sets the level (clearing the bit first) and then counts,
       so a level that disagrees with the count's parity is a change half made, taken at the next
       look - as is a change made without core_setSw, taken then anyway */
    const int no = procgame_m2sw(m / 8, m % 8);
    const UINT32 changes = procgame_swChanges[m];
    const UINT8 closed = core_getSw(no) ? 1 : 0;
    const int moved = closed != locals.swState[m];
    if (moved != (int)((changes - locals.swSeen[m]) & 1) && !locals.swAgain[m]) {
      locals.swAgain[m] = 1;
      continue;
    }
    locals.swAgain[m] = 0;
    if (moved) {
      locals.swState[m] = closed;
      procgame_set_switch(no, closed);
      diag.switches++;
      if (diag.on) fprintf(stderr, "[procgame driver] switch %d %s\n", no, closed ? "closed" : "opened");
    } else if (changes != locals.swSeen[m]) { /* changed and changed back since the last look */
      procgame_set_switch(no, !closed);
      procgame_set_switch(no, closed);
      diag.switches += 2;
      if (diag.on) fprintf(stderr, "[procgame driver] switch %d %s and back\n", no, closed ? "opened" : "closed");
    }
    locals.swSeen[m] = changes;
  }
}

static void procgame_sync_outputs(void)
{
  UINT8 lamps[CORE_STDLAMPCOLS];
  UINT32 sols = 0;
  int n, col, row;
  if (!procgame_poll()) /* the game was writing them: the last ones stand */
    return;
  for (n = 1; n < PROCGAME_COILS; n++) {
    const int on = procgame_coil(n);
    locals.coil[n] = (UINT8)on;
    coreGlobals.physicOutputState[CORE_MODOUT_SOL0 + n - 1].value = on ? 1.0f : 0.0f;
    if (on && n <= 32) sols |= CORE_SOLBIT(n);
  }
  coreGlobals.solenoids = coreGlobals.pulsedSolState = sols;
  memset(lamps, 0, sizeof(lamps));
  for (col = 1; col <= CORE_STDLAMPCOLS; col++)
    for (row = 1; row <= 8; row++) {
      const int on = procgame_lamp(col * 10 + row);
      coreGlobals.physicOutputState[CORE_MODOUT_LAMP0 + (col - 1) * 8 + row - 1].value = on ? 1.0f : 0.0f;
      if (on) lamps[col - 1] |= 1 << (row - 1);
    }
  for (n = 0; n < CORE_STDLAMPCOLS; n++) coreGlobals.lampMatrix[n] = lamps[n];
  for (n = 0; n < PROCGAME_GI; n++) coreGlobals.gi[n] = procgame_gi(n);
}

static void procgame_io(int param)
{
  (void)param;
  if (!locals.running) return;
  procgame_sync_switches();
  procgame_sync_outputs();
}

static INTERRUPT_GEN(procgame_vblank)
{
  char reason[128];
  if (locals.running) {
    /* the sound stream at the game's rate */
    const unsigned rate = procgame_audio_rate();
    if (procgame_stream >= 0 && rate && rate != locals.audioRate) {
      stream_set_sample_rate(procgame_stream, rate);
      stream_set_sample_rate(procgame_stream + 1, rate);
      locals.audioRate = rate;
    }
    if (diag.on && ++diag.frames % 300 == 0) {
      unsigned heartbeat, torn, resyncs, dropped;
      procgame_stats(&heartbeat, &torn, &resyncs, &dropped);
      fprintf(stderr, "[procgame driver] heartbeat %u, torn reads %u; sound: stream asked %u frames, got %u, late %u times, "
              "short %u, %u resyncs (%u bytes dropped), the game's rate %u Hz; %u switch changes\n",
              heartbeat, torn, diag.asked, diag.got, diag.late, diag.shortfalls, resyncs, dropped, rate, diag.switches);
      diag.asked = diag.got = diag.late = diag.shortfalls = 0;
    }
    if (!locals.warned && !procgame_running(reason, sizeof(reason))) {
      locals.warned = 1;
      logerror("P-ROC game: %s\n", reason);
      usrintf_showmessage_secs(30, "P-ROC game: %s", reason);
    }
  }
  core_updateSw(0); /* the flippers are the game's own (PROCGAME_FLIPPERS) */
}

/* every solenoid as the game numbers it: the core reads them all here (GEN_PROCGAME) */
static int procgame_getSol(int solNo)
{
  return solNo >= 1 && solNo < PROCGAME_COILS ? locals.coil[solNo] : 0;
}

/*-------------------------------------------------
/  the display, into the 32-bit direct colour screen
/-------------------------------------------------*/
static PINMAME_VIDEO_UPDATE(procgame_video)
{
  static UINT8 rgb[PROCGAME_MAX_WIDTH * PROCGAME_MAX_HEIGHT * 3];
  const unsigned w = locals.width < (unsigned)layout->length ? locals.width : (unsigned)layout->length;
  const unsigned h = locals.height < (unsigned)layout->start ? locals.height : (unsigned)layout->start;
  unsigned x, y;
  (void)cliprect;
  if (!locals.running) return;
  procgame_display_frame(rgb); /* new or not, rgb holds the newest */
  for (y = 0; y < h; y++) {
    UINT32 *const dst = (UINT32 *)bitmap->line[layout->top + y] + layout->left;
    const UINT8 *src = rgb + (size_t)y * locals.width * 3;
    for (x = 0; x < w; x++, src += 3)
      dst[x] = ((UINT32)src[0] << 16) | ((UINT32)src[1] << 8) | src[2];
  }
}

/*-------------------------------------------------
/  sound: what the game mixes, 16-bit, at the rate it reports (procgame_vblank moves the stream to
/  it, the mixer resamples)
/-------------------------------------------------*/

/* The game mixes against the wall clock and the stream asks in emulated time, so the samples pass
   through a FIFO that starts playing only once 1/30 s is waiting; should it run dry anyway, the last
   sample is held - a gap of zeros would click - and the FIFO fills to its mark again. A backlog the
   game built up while the host stalled is dropped by the subsystem, not played late */
#define PROCGAME_FIFO 16384 /* stereo frames */
static struct { INT16 s[2 * PROCGAME_FIFO]; int head, count, primed; INT16 last[2]; } fifo;

static void procgame_snd_update(int num, INT16 **buffer, int length)
{
  static INT16 tmp[2 * 1024];
  const int mark = (int)(locals.audioRate ? locals.audioRate : PROCGAME_AUDIO_RATE) / 30;
  const unsigned channels = locals.running ? procgame_audio_channels() : 0;
  int i, got = 0;
  (void)num;
  while (channels >= 1 && channels <= 2 && fifo.count < PROCGAME_FIFO) {
    const int room = PROCGAME_FIFO - fifo.count, want = room > 1024 ? 1024 : room;
    const int n = (int)procgame_audio(tmp, (unsigned)want);
    for (i = 0; i < n; i++) {
      const int at = (fifo.head + fifo.count + i) % PROCGAME_FIFO;
      fifo.s[2 * at] = tmp[channels * i];
      fifo.s[2 * at + 1] = tmp[channels * i + channels - 1];
    }
    fifo.count += n;
    got += n;
    if (n < want) break;
  }
  diag.got += got;
  diag.asked += length;
  if (got < length) diag.late++;
  if (!fifo.primed && fifo.count >= length + mark) fifo.primed = 1;
  for (i = 0; i < length; i++) {
    if (fifo.primed && fifo.count) {
      fifo.last[0] = fifo.s[2 * fifo.head];
      fifo.last[1] = fifo.s[2 * fifo.head + 1];
      fifo.head = (fifo.head + 1) % PROCGAME_FIFO;
      fifo.count--;
    } else if (fifo.primed) { /* ran dry: hold, and wait for the mark again */
      fifo.primed = 0;
      diag.shortfalls++;
    }
    buffer[0][i] = fifo.last[0];
    buffer[1][i] = fifo.last[1];
  }
}

static int procgame_sh_start(const struct MachineSound *msound)
{
  const char *names[] = { "P-ROC game Left", "P-ROC game Right" };
  const int vol[2] = { MIXER(100, MIXER_PAN_LEFT), MIXER(100, MIXER_PAN_RIGHT) };
  (void)msound;
  procgame_stream = stream_init_multi(2, names, vol, PROCGAME_AUDIO_RATE, 0, procgame_snd_update);
  return procgame_stream < 0;
}

static void procgame_sh_stop(void) { procgame_stream = -1; }

static struct CustomSound_interface procgame_sndInt = { procgame_sh_start, procgame_sh_stop, 0 };

/*-------------------------------------------------
/  start and stop
/-------------------------------------------------*/

/* The game's directory: proc/<set> beside a ROM path's folder (pinmame/roms -> pinmame/proc/<set>) */
static int procgame_find_game(char *dir, size_t size)
{
  const int paths = osd_get_path_count(FILETYPE_ROM);
  int i;
  for (i = 0; i < paths; i++) {
    char roms[1024];
    size_t len;
    char *slash;
    if (!osd_get_full_path(FILETYPE_ROM, i, "", roms, sizeof(roms)))
      continue;
    len = strlen(roms);
    while (len > 1 && (roms[len - 1] == '/' || roms[len - 1] == '\\')) roms[--len] = 0;
    slash = strrchr(roms, '/');
    if (slash) *slash = 0; else strcpy(roms, ".");
    if (snprintf(dir, size, "%s/proc/%s", roms, Machine->gamedrv->name) < (int)size && procgame_is_game_dir(dir))
      return 1;
  }
  return 0;
}

static MACHINE_INIT(procgame)
{
  char dir[1100], error[256];
  int m;

  memset(&locals, 0, sizeof(locals));
  memset(&fifo, 0, sizeof(fifo));
  memset(&diag, 0, sizeof(diag));
  diag.on = getenv("PROCGAME_LOG") != NULL;

  /* every output is the game's level as it is: the core integrates none of them */
  coreGlobals.nSolenoids = CORE_MAXSOL;
  coreGlobals.nLamps = 8 * CORE_STDLAMPCOLS;
  coreGlobals.nGI = 0; /* coreGlobals.gi as set, not physical outputs: the tables expect 0 and 1 */
  core_set_pwm_output_type(CORE_MODOUT_SOL0, coreGlobals.nSolenoids, CORE_MODOUT_NONE);
  core_set_pwm_output_type(CORE_MODOUT_LAMP0, coreGlobals.nLamps, CORE_MODOUT_NONE);

  /* every switch starts open, as the game sees it: one closed now goes over at the first look */
  for (m = 0; m < PROCGAME_MAXSW; m++) locals.swSeen[m] = procgame_swChanges[m];
  core_swChangedHook = procgame_swChanged;

  if (!procgame_find_game(dir, sizeof(dir))) {
    logerror("P-ROC game: no proc/%s folder beside the ROM folder\n", Machine->gamedrv->name);
    usrintf_showmessage_secs(30, "P-ROC game: no proc/%s folder beside the ROM folder", Machine->gamedrv->name);
    return;
  }
  /* The game sets itself up here - seconds - before the machine reports it runs, so a host waiting
     for that (VPX's Controller.Run) starts the table on a game that is ready for its switches */
  if (!procgame_start(dir, 0, error, sizeof(error))) {
    logerror("P-ROC game: %s does not start: %s\n", dir, error);
    usrintf_showmessage_secs(30, "P-ROC game: the game does not start: %s", error);
    return;
  }
  procgame_display_size(&locals.width, &locals.height);
  if (locals.width != (unsigned)core_gameData->lcdLayout->length || locals.height != (unsigned)core_gameData->lcdLayout->start) {
    logerror("P-ROC game: the game's display is %ux%u, the set's %dx%d\n", locals.width, locals.height,
             core_gameData->lcdLayout->length, core_gameData->lcdLayout->start);
    usrintf_showmessage_secs(10, "P-ROC game: the game's display is %ux%u, the set's %dx%d", locals.width, locals.height,
                             core_gameData->lcdLayout->length, core_gameData->lcdLayout->start);
  }
  if (locals.width > PROCGAME_MAX_WIDTH) locals.width = PROCGAME_MAX_WIDTH;
  if (locals.height > PROCGAME_MAX_HEIGHT) locals.height = PROCGAME_MAX_HEIGHT;
  locals.running = 1;
}

static MACHINE_STOP(procgame)
{
  locals.running = 0;
  core_swChangedHook = NULL;
  procgame_stop(); /* the game saves its scores, audits and settings on the way out */
}

MACHINE_DRIVER_START(procgame)
  MDRV_IMPORT_FROM(PinMAME)
  MDRV_CORE_INIT_RESET_STOP(procgame, NULL, procgame)
  MDRV_CPU_ADD_TAG("mcpu", PROCGAME, PROCGAME_CPU_HZ)
  MDRV_CPU_MEMORY(procgame_readmem, procgame_writemem)
  MDRV_CPU_VBLANK_INT(procgame_vblank, 1)
  MDRV_TIMER_ADD(procgame_io, PROCGAME_IOFREQ)
  MDRV_SWITCH_CONV(procgame_sw2m, procgame_m2sw)
  MDRV_LAMP_CONV(procgame_sw2m, procgame_m2sw)
  MDRV_SOUND_ADD(CUSTOM, procgame_sndInt)
  MDRV_SOUND_ATTRIBUTES(SOUND_SUPPORTS_STEREO)
  /* the display in 32-bit direct colour, and room for the largest a game may have */
  MDRV_SCREEN_SIZE(PROCGAME_MAX_WIDTH, PROCGAME_MAX_HEIGHT)
  MDRV_VISIBLE_AREA(0, PROCGAME_MAX_WIDTH - 1, 0, PROCGAME_MAX_HEIGHT - 1)
  MDRV_VIDEO_ATTRIBUTES(VIDEO_TYPE_RASTER | VIDEO_RGB_DIRECT | VIDEO_NEEDS_6BITS_PER_GUN)
MACHINE_DRIVER_END

/*-------------------------------------------------
/  the games: one set each, its display's size, and the manifest procgame_manifest.py writes
/-------------------------------------------------*/
#define PROCGAME_INPUT_PORTS(name) \
  INPUT_PORTS_START(name) \
    CORE_PORTS \
    PORT_START /* 2: CORE_COREINPORT, unused: the table owns the cabinet's buttons */ \
      COREPORT_BIT(0x0001, "Unused", KEYCODE_NONE) \
  INPUT_PORTS_END

#define PROCGAME_INIT(name, width, height) \
  PROCGAME_INPUT_PORTS(name) \
  static core_tLCDLayout name##Disp[] = { {0, 0, height, width, CORE_VIDEO | CORE_VIDEO_DMD, (genf *)procgame_video, NULL}, {0} }; \
  static core_tGameData name##GameData = { GEN_PROCGAME, name##Disp, \
    { PROCGAME_FLIPPERS, 0, 0, PROCGAME_NCUSTSOLS, 0, 0, 0, 0, procgame_getSol } }; \
  static void init_##name(void) { core_gameData = &name##GameData; }

/*-------------------------------------------------------------------
/ Cactus Canyon Continued (Eric Priepke, 2013) - pyprocgame, on a Cactus Canyon (WPC-95)
/-------------------------------------------------------------------*/
PROCGAME_INIT(ccc, 128, 32)
ROM_START(ccc_proc)
  ROM_REGION(0x100, REGION_USER1, 0)
    ROM_LOAD("manifest", 0x0000, 0x0056, CRC(3b826d5f) SHA1(7c573fcf1d6fa754aaa36b3e1e657ee07d6a24bd))
ROM_END
CORE_GAMEDEF(ccc, proc, "Cactus Canyon Continued (P-ROC)", 2013, "Eric Priepke", procgame, 0)

/*-------------------------------------------------------------------
/ Gremlins - Mega Madness (2018) - SkeletonGame, for Visual Pinball (WPC)
/-------------------------------------------------------------------*/
PROCGAME_INIT(gremlins, 271, 148)
ROM_START(gremlins_proc)
  ROM_REGION(0x100, REGION_USER1, 0)
    ROM_LOAD("manifest", 0x0000, 0x0061, CRC(05aa5212) SHA1(6f2c945912aa3faf8fc1d9ba39c47362b6e47830))
ROM_END
CORE_GAMEDEF(gremlins, proc, "Gremlins - Mega Madness (P-ROC)", 2018, "Original", procgame, 0)

#endif /* HAS_PROCGAME */
