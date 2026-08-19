/************************************************************************************************
 Stern Pinball Arcade (SPA) — native core loader

 The games on Stern's SPIKE-era hardware are not emulated here. FarSight shipped a complete
 emulation core for each of them inside The Pinball Arcade, and this driver drives that core and
 bridges its output into PinMAME: switches and dips in; solenoids, lamps, a 128x32 DMD and 48 kHz
 stereo out.

 Based on DJRobX's VPinMAME driver of the same name, in turn based on Jannik Vogel (JayFoxRox)'s
 research:
   https://github.com/JayFoxRox/pba-tools
   https://github.com/JayFoxRox/stern-pba-emu

 Two things differ from that original. It loaded a 32-bit Windows DLL through LoadLibrary; this
 loads the native aarch64 core from the Android build through spa_elf (see spa_elf.c), so it runs
 on the RK3588 cabinets without emulation. And it carried a large set of hacks keyed to the CRC of
 one specific x86 DLL build — raw pointers into the core's memory found with CheatEngine, for the
 knocker, the flipper-enable flag, high score slots and a motor-speed workaround. None of those
 addresses mean anything in the ARM build, so this driver uses only the documented exports.

 Per-game data lives in the ROM directory: the core library and image.bin, e.g.
   roms/spagb_100/libSternGB.so
   roms/spagb_100/image.bin
************************************************************************************************/

#include "driver.h"
#include "core.h"
#include "sim.h"
#include "vpintf.h"
#include "spa_elf.h"

#define SPA_SOUNDFREQ    48000
#define SPA_SNDBUFSIZE   (SPA_SOUNDFREQ * 70 / 1000)
#define SPA_STEPRATE     120                       /* core steps per second */
#define SPA_DMD_W        128
#define SPA_DMD_H        32
#define SPA_DMD_SIZE     (SPA_DMD_W * SPA_DMD_H)

/*-- the core's exported interface, resolved at init --*/
static struct {
  int   (*set_rom_data)(UINT8 *, int);
  int   (*init)(void);
  int   (*reset)(int);
  int   (*term)(void);
  int   (*get_persistant_data)(void *, int *);
  void  (*set_free_play)(void);
  void  (*set_volume)(int, int);
  void *(*get_dmd_fbuffer)(void);
  void *(*get_dmd_bbuffer)(void);
  void  (*step_rate)(float);   /* Ghostbusters: delta time in seconds */
  void  (*step)(void);         /* every other title, as on Windows */
  void  (*set_switch_state)(int, int, int);
  void  (*set_dedicated_switch_state)(int, int, int);
  int   (*get_coil_state)(int);
  int   (*get_lamp_state)(int, int);
  INT16*(*get_sound_buffer)(int *);
} spa;

static struct {
  spa_object *core;
  UINT8  *fbuffer, *bbuffer;
  int     coindoor;
  int     loaded;
  /*-- audio ring, filled from the core and drained by the mixer --*/
  INT16   samplebuf[2][SPA_SNDBUFSIZE];
  INT16   lastsamp[2];
  int     sampout, sampnum;
} spalocals;

/*-- name of the core library for the running game, set by the game's init --*/
static const char *spa_corelib;

extern void *spa_bionic_resolve(const char *name, void *user);
extern void  spa_bionic_register(spa_object *o, const char *name);

/*-------------------
/  Machine driver
/--------------------*/
/*-- Common inports. Inherited from SAM; the SPIKE cabinet switches match. --*/
#define SPA_COMPORTS \
  PORT_START /* 0 */ \
    COREPORT_BITDEF(  0x0010, IPT_TILT,           KEYCODE_INSERT)  \
    COREPORT_BIT   (  0x0020, "Slam Tilt",        KEYCODE_HOME)  \
    COREPORT_BIT   (  0x0040, "Ticket Notch",     KEYCODE_K)  \
    COREPORT_BIT   (  0x0080, "Dedicated Sw#20",  KEYCODE_L) \
    COREPORT_BIT   (  0x0100, "Back",             KEYCODE_7) \
    COREPORT_BIT   (  0x0200, "Minus",            KEYCODE_8) \
    COREPORT_BIT   (  0x0400, "Plus",             KEYCODE_9) \
    COREPORT_BIT   (  0x0800, "Select",           KEYCODE_0) \
    COREPORT_BIT   (  0x8000, "Start Button",     KEYCODE_1) \
    COREPORT_BIT   (  0x4000, "Tournament Start", KEYCODE_2) \
    COREPORT_BITDEF(  0x0001, IPT_COIN1,          KEYCODE_3)  \
    COREPORT_BITDEF(  0x0002, IPT_COIN2,          KEYCODE_4)  \
    COREPORT_BITDEF(  0x0004, IPT_COIN3,          KEYCODE_5)  \
    COREPORT_BITDEF(  0x0008, IPT_COIN4,          KEYCODE_6)  \
    COREPORT_BITTOG(  0x1000, "Coin Door",        KEYCODE_END) \
  PORT_START /* 1 */ \
    COREPORT_DIPNAME( 0x001f, 0x0000, "Country") \
      COREPORT_DIPSET(0x0000, "USA" ) \
      COREPORT_DIPSET(0x0007, "Germany" ) \
      COREPORT_DIPSET(0x000e, "U.K." ) \
    COREPORT_DIPNAME( 0x0080, 0x0080, "Dip #8") \
      COREPORT_DIPSET(0x0000, "1" ) \
      COREPORT_DIPSET(0x0080, "0" )

#define SPA_INPUT_PORTS_START(name,balls) \
  INPUT_PORTS_START(name) \
    CORE_PORTS \
    SIM_PORTS(balls) \
    SPA_COMPORTS \
  INPUT_PORTS_END

#define SPA_COMINPORT CORE_COREINPORT

/*-----------
/  Sound
/------------*/
static int spa_sndbufferlength(void) {
  if (spalocals.sampnum >= spalocals.sampout)
    return spalocals.sampnum - spalocals.sampout;
  return spalocals.sampnum + SPA_SNDBUFSIZE - spalocals.sampout;
}

static void spa_sh_update(int num, INT16 *buffer[2], int length) {
  int ii, channel;

  for (ii = 0; ii < length && spalocals.sampout != spalocals.sampnum; ii++) {
    for (channel = 0; channel < 2; channel++)
      spalocals.lastsamp[channel] = buffer[channel][ii] = spalocals.samplebuf[channel][spalocals.sampout];
    if (++spalocals.sampout == SPA_SNDBUFSIZE) spalocals.sampout = 0;
  }
  /*-- ran dry: hold the last sample rather than click --*/
  for (; ii < length; ii++)
    for (channel = 0; channel < 2; channel++)
      buffer[channel][ii] = spalocals.lastsamp[channel];
}

static int spa_sh_start(const struct MachineSound *msound) {
  const char *stream_name[] = { "SPA Left", "SPA Right" };
  const int volume[2] = { MIXER(100,MIXER_PAN_LEFT), MIXER(100,MIXER_PAN_RIGHT) };
  return stream_init_multi(2, stream_name, volume, SPA_SOUNDFREQ, 0, spa_sh_update) < 0;
}

static void spa_sh_stop(void) { }

static struct CustomSound_interface spaCustInt = { spa_sh_start, spa_sh_stop, 0 };

/*---------------------
/  Loading the core
/----------------------*/
/*-- Read a whole file from the game's ROM directory. MAME's search path
    handling means the caller does not care where the ROM directory is. --*/
static UINT8 *spa_readfile(const char *filename, size_t *size) {
  mame_file *f = mame_fopen(Machine->gamedrv->name, (char *)filename, FILETYPE_ROM, 0);
  UINT8 *data;
  UINT64 len;

  if (!f) {
    printf("SPA: cannot find %s for %s\n", filename, Machine->gamedrv->name);
    return NULL;
  }
  len = mame_fsize(f);
  data = malloc((size_t)len);
  if (!data) { mame_fclose(f); return NULL; }
  if (mame_fread(f, data, (UINT32)len) != len) {
    printf("SPA: short read on %s\n", filename);
    free(data); mame_fclose(f); return NULL;
  }
  mame_fclose(f);
  *size = (size_t)len;
  return data;
}

static int spa_resolve_exports(void) {
  int missing = 0;
  struct { const char *name; void **slot; int required; } wanted[] = {
    { "stern_set_rom_data_fn",               (void **)&spa.set_rom_data, 1 },
    { "stern_init_fn",                       (void **)&spa.init, 1 },
    { "stern_reset_fn",                      (void **)&spa.reset, 1 },
    { "stern_term_fn",                       (void **)&spa.term, 0 },
    { "stern_get_persistant_data_fn",        (void **)&spa.get_persistant_data, 0 },
    { "stern_set_free_play_fn",              (void **)&spa.set_free_play, 0 },
    { "stern_set_volume_fn",                 (void **)&spa.set_volume, 0 },
    { "stern_get_dmd_fbuffer_fn",            (void **)&spa.get_dmd_fbuffer, 1 },
    { "stern_get_dmd_bbuffer_fn",            (void **)&spa.get_dmd_bbuffer, 0 },
    { "stern_step_rate_fn",                  (void **)&spa.step_rate, 0 },
    { "stern_step_fn",                       (void **)&spa.step, 0 },
    { "stern_set_switch_state_fn",           (void **)&spa.set_switch_state, 0 },
    { "stern_set_dedicated_switch_state_fn", (void **)&spa.set_dedicated_switch_state, 0 },
    { "stern_get_coil_state_fn",             (void **)&spa.get_coil_state, 0 },
    { "stern_get_lamp_state_fn",             (void **)&spa.get_lamp_state, 0 },
    { "stern_get_sound_buffer",              (void **)&spa.get_sound_buffer, 0 },
  };
  int i;

  for (i = 0; i < sizeof(wanted)/sizeof(wanted[0]); i++) {
    *wanted[i].slot = spa_sym(spalocals.core, wanted[i].name);
    if (!*wanted[i].slot && wanted[i].required) {
      printf("SPA: core is missing required export %s\n", wanted[i].name);
      missing++;
    }
  }
  /*-- Ghostbusters clocks with a delta time, the rest with a bare step --*/
  if (!spa.step_rate && !spa.step) {
    printf("SPA: core exports no step entry point\n");
    missing++;
  }
  return missing;
}

static MACHINE_INIT(spa) {
  UINT8 *lib = NULL, *rom = NULL;
  size_t libsize = 0, romsize = 0;

  /*-- The core cannot be torn down and reloaded: it owns background threads and
      a 130 MB image, and nothing in its interface unwinds either. A second
      machine init would leave the first copy running. Load it once and let
      MACHINE_RESET take the machine back to a known state instead. --*/
  if (spalocals.loaded) return;

  memset(&spa, 0, sizeof(spa));
  memset(&spalocals, 0, sizeof(spalocals));

  if (!spa_corelib) { printf("SPA: no core library named for this game\n"); return; }

  lib = spa_readfile(spa_corelib, &libsize);
  if (!lib) return;

  spalocals.core = spa_open_image(lib, libsize, spa_bionic_resolve, NULL);
  free(lib);
  if (!spalocals.core) { printf("SPA: failed to load %s\n", spa_corelib); return; }
  spa_bionic_register(spalocals.core, spa_corelib);

  if (spa_resolve_exports() != 0) return;

  rom = spa_readfile("image.bin", &romsize);
  if (!rom) return;

  /*-- The core keeps the image; it must stay alive for the whole session. --*/
  spa.set_rom_data(rom, (int)romsize);
  spa.init();

  spalocals.fbuffer = spa.get_dmd_fbuffer();
  spalocals.bbuffer = spa.get_dmd_bbuffer ? spa.get_dmd_bbuffer() : NULL;
  if (!spalocals.fbuffer) { printf("SPA: core produced no DMD buffer\n"); return; }

  core_dmd_pwm_init(core_gameData->lcdLayout, CORE_DMD_PWM_PREINTEGRATED_SAM,
                    CORE_DMD_PWM_PREINTEGRATED_SAM, 0);

  spalocals.loaded = 1;
  printf("SPA: %s running\n", spa_corelib);
}

static MACHINE_RESET(spa) {
  int i;
  if (!spalocals.loaded) return;

  if (spa.set_dedicated_switch_state)
    for (i = 0; i < 8; i++)
      spa.set_dedicated_switch_state(i, 0, core_getDip(0) & (1 << i));

  spa.reset(1);

  /*-- No settings are persisted yet (see the note on NVRAM below), so the
      machine comes up on free play at a sane volume. --*/
  if (spa.set_free_play) spa.set_free_play();
  if (spa.set_volume)    spa.set_volume(0, 80);
}

static MACHINE_STOP(spa) {
  if (spalocals.loaded && spa.term) spa.term();
  spalocals.loaded = 0;
}

/*-----------------
/  Switches
/------------------*/
static SWITCH_UPDATE(spa) {
  if (inports) {
    /*-- Col 9: coin slots --*/
    CORE_SETKEYSW(inports[SPA_COMINPORT], 0x0f, 9);
    /*-- Col 0: tilt, slam, coin door buttons --*/
    CORE_SETKEYSW(inports[SPA_COMINPORT] >> 4, 0xff, 0);
    /*-- Col 2: start --*/
    CORE_SETKEYSW(inports[SPA_COMINPORT] >> 8, 0xc0, 2);
    /*-- the coin door is not part of the switch matrix --*/
    spalocals.coindoor = (inports[SPA_COMINPORT] & 0x1000) ? 0 : 1;
  }
}

static int spa_getSol(int solNo) { return 0; }

/*----------------------------
/  Clocking the core
/-----------------------------*/
static void spa_vblank(int data) {
  UINT8 frame[SPA_DMD_SIZE];
  int i;

  if (!spalocals.loaded) return;

  core_updateSw(1);

  /*-- switches in --*/
  if (spa.set_dedicated_switch_state) {
    int sw = coreGlobals.swMatrix[0];
    for (i = 8; i < 12; i++)
      spa.set_dedicated_switch_state(i, 0, (sw & (1 << (i - 4))) ? 1 : 0);
    for (i = 0; i < 8; i++)
      spa.set_dedicated_switch_state(i, 0, core_getDip(0) & (1 << i));
  }
  if (spa.set_switch_state)
    for (i = 1; i < 90; i++)
      spa.set_switch_state(i % 16, i / 16, core_getSw(i));

  /*-- advance the core --*/
  if (spa.step_rate) spa.step_rate(1.0f / (float)SPA_STEPRATE);
  else               spa.step();

  /*-- solenoids out. Coils 2 and 3 are the flippers; mirror them into the
      dedicated flipper bits so the table sees them where VPX expects. --*/
  if (spa.get_coil_state) {
    coreGlobals.solenoids = 0;
    coreGlobals.solenoids2 = 0;
    for (i = 0; i < 32; i++) {
      if (spa.get_coil_state(i)) {
        coreGlobals.solenoids |= (1u << i);
        if (i == 2) coreGlobals.solenoids2 |= CORE_LLFLIPSOLBITS;
        if (i == 3) coreGlobals.solenoids2 |= CORE_LRFLIPSOLBITS;
      }
    }
  }

  /*-- lamps out. The core's lamps are RGB LEDs and this reduces them to the
      on/off matrix PinMAME carries; colour is not represented yet. --*/
  if (spa.get_lamp_state) {
    int col, row;
    for (col = 0; col < CORE_STDLAMPCOLS; col++) {
      UINT8 bits = 0;
      for (row = 0; row < 8; row++)
        if (spa.get_lamp_state(col, row)) bits |= (1 << row);
      coreGlobals.lampMatrix[col] = bits;
    }
  }

  /*-- DMD out. The front buffer holds 4 brightness bits plus 4 transparency
      bits; a dot with transparency set shows the background page through it.
      The result is exactly the pre-integrated 4-bit frame SAM submits. --*/
  for (i = 0; i < SPA_DMD_SIZE; i++) {
    UINT8 dot = spalocals.fbuffer[i];
    if (dot > 15 && spalocals.bbuffer) dot = spalocals.bbuffer[i];
    frame[i] = dot & 0x0f;   /* the decoder expects 4 bits, nothing wider */
  }
  core_dmd_submit_frame(core_gameData->lcdLayout, frame, 1);

  /*-- audio out --*/
  if (spa.get_sound_buffer) {
    while (spa_sndbufferlength() < SPA_SNDBUFSIZE - 800) {
      int count = 0;
      INT16 *audio = spa.get_sound_buffer(&count);
      if (!audio || count <= 0) break;
      for (i = 0; i < count; i++) {
        spalocals.samplebuf[0][spalocals.sampnum] = audio[i];
        spalocals.samplebuf[1][spalocals.sampnum] = audio[i];
        if (++spalocals.sampnum == SPA_SNDBUFSIZE) spalocals.sampnum = 0;
      }
    }
  }
}

/*-- The core keeps its state in a 128 MB buffer reached through
    stern_get_persistant_data_fn, not in a file, and it is far too large to
    write out wholesale. Settings and high scores have their own getters and
    should be persisted through those; nothing is saved yet. --*/
static NVRAM_HANDLER(spa) { }

static MACHINE_DRIVER_START(spa)
  MDRV_IMPORT_FROM(PinMAME)
  MDRV_SWITCH_UPDATE(spa)
  MDRV_TIMER_ADD(spa_vblank, SPA_STEPRATE)
  MDRV_CORE_INIT_RESET_STOP(spa, spa, spa)
  MDRV_DIPS(8)
  MDRV_NVRAM_HANDLER(spa)
  MDRV_SOUND_ADD(CUSTOM, spaCustInt)
  MDRV_SOUND_ATTRIBUTES(SOUND_SUPPORTS_STEREO)
MACHINE_DRIVER_END

#define INITSPAGAME(name, gen, disp, lampcol, corelib) \
  static core_tGameData name##GameData = { \
    gen, disp, {FLIP_SW(FLIP_L) | FLIP_SOL(FLIP_L), 0, lampcol, 14, 0, 0, 0, 0, spa_getSol}}; \
  static void init_##name(void) { core_gameData = &name##GameData; spa_corelib = corelib; }

static struct core_dispLayout spa_dmd128x32[] = {
  { 0, 0, SPA_DMD_H, SPA_DMD_W, CORE_DMD, NULL },
  { 0 }
};

/*-- There is no ROM to check: the core library and image.bin are read from the
    ROM directory at init. The region keeps MAME's loader happy. --*/
#define SPA_ROM(game) \
  ROM_START(game) \
    ROM_REGION(0x1000, REGION_USER1, 0) \
    ROM_FILL(0x0000, 0x1000, 0xff) \
  ROM_END

/*-------------------------------------------------------------------
/ Ghostbusters LE
/--------------------------------------------------------------------*/
INITSPAGAME(spagb, GEN_SAM, spa_dmd128x32, 8, "libSternGB.so")
SPA_ROM(spagb_100)
SPA_INPUT_PORTS_START(spagb, 1)
CORE_GAMEDEF(spagb, 100, "Ghostbusters LE (Stern Pinball Arcade)", 2016, "Stern", spa, 0)
