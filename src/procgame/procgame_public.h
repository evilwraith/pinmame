// license:BSD-3-Clause

/* PinMAME procgame subsystem - the contract with PinMAME's half of the build

   A P-ROC game (pyprocgame, SkeletonGame) is a Python program that drove a P-ROC board in a real
   machine. Here it runs as a separate process, with a fake board that reads and writes a block of
   shared memory (ProcShm.h). This header is the one crossing between that subsystem and
   src/wpc/procgame.c: plain C, and it includes no PinMAME header. src/procgame/procgame_pinmame.cpp
   implements it.

   Numbers are VPinMAME's for a WPC machine, which the game process already speaks: lamps 11-88,
   solenoids 1-63 (the flipper hold coils at 34, 36, 46, 48), GI strings 0-4, switches 1-8
   (dedicated), 11-98 (matrix) and 111-118 (flipper). Nothing here waits on the game process except
   procgame_start(), which runs once */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#define PROCGAME_LAMPS    90 /* lamp numbers 0-89, 11-88 used */
#define PROCGAME_COILS    64 /* solenoid numbers 0-63 */
#define PROCGAME_GI        5
/* The largest display a game may have: a SkeletonGame game draws at the size its config.yaml asks
   for (Gremlins 271x148, Evil Dead 520x290), a pyprocgame game 128x32 */
#define PROCGAME_MAX_WIDTH  640
#define PROCGAME_MAX_HEIGHT 360

/* 1 if dir holds a game: a config.yaml, or a config/machine.yaml */
int procgame_is_game_dir(const char *dir);

/* The game the machine runs: the host names its directory before it starts the machine
   (PinmameSetProcGameDir). Empty until then */
void procgame_set_game_dir(const char *dir);
const char *procgame_game_dir(void);

/* Starts the game in game_dir and waits until its setup has run, for at most timeout_ms (0: the
   default, 30 s). The game process loads a 40k-line Python program, so this is seconds. 0 on
   failure, with the reason in error */
int procgame_start(const char *game_dir, unsigned timeout_ms, char *error, unsigned error_size);
/* Asks the game to leave its loop, so it saves what it keeps on disk, and reaps it */
void procgame_stop(void);
/* 1 while the game process runs; when it has stopped, why, in reason */
int procgame_running(char *reason, unsigned reason_size);

/* Takes the game's outputs as they are now; 0 when the game was writing them, and the last ones
   stand. Then the getters below read what it took */
int procgame_poll(void);
int procgame_lamp(int number);
int procgame_coil(int number);
int procgame_gi(int index);

/* A switch change, queued for the game; dropped, not waited for, if the game is a queue behind */
void procgame_set_switch(int number, int closed);

/* The game's display, fixed once it has started: its size, and the newest frame as RGB24 rows
   into rgb (width * height * 3 bytes), 1 when it is new since the last call. A pyprocgame game's
   128x32 dots come through its palette (dmd_palette.bin beside the game, white when it has none) */
void procgame_display_size(unsigned *width, unsigned *height);
int procgame_display_frame(unsigned char *rgb);

/* Sound: what the game mixes, 16-bit interleaved at procgame_audio_rate() with
   procgame_audio_channels() channels (0 until it has started). Takes up to frames frames and
   returns how many it took; backlog beyond 200 ms is dropped, not played late */
unsigned procgame_audio_rate(void);
unsigned procgame_audio_channels(void);
unsigned procgame_audio(short *dst, unsigned frames);

/* Diagnostics: the game loop's heartbeat, torn reads, and the audio dropped to stay in step */
void procgame_stats(unsigned *heartbeat, unsigned *torn_reads, unsigned *audio_resyncs, unsigned *audio_dropped_bytes);

#ifdef __cplusplus
}
#endif
