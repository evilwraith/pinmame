// license:BSD-3-Clause

// PinMAME procgame subsystem - the shared-memory contract between the host and the game process
//
// Plain C, no PinMAME headers, no SDL: this file is the whole interface, and it is mirrored byte for
// byte by the runtime's procbridge/shm.py. Everything that has to be agreed between the two lives
// here and nowhere else. It came from the 10.8.0 VPX fork's bridge unchanged, so "host" and "VPX"
// below mean whoever maps the block: here, src/wpc/procgame.c.
//
// Design rule: nothing blocks the host. It polls this block and never waits on the child. If the
// child is mid-write or late, the host keeps the state it read last time -- a lamp one frame stale
// is invisible, a blocked emulation slice is not.

#pragma once

#include <stdint.h>

#define PROC_SHM_MAGIC   0x43505250u   // 'PRPC' little-endian
#define PROC_SHM_VERSION 3u

#define PROC_DMD_WIDTH   128
#define PROC_DMD_HEIGHT  32
#define PROC_DMD_BYTES   (PROC_DMD_WIDTH * PROC_DMD_HEIGHT)

// SkeletonGame (PyProcGameHD) draws a full-colour display at whatever size the
// game's config.yaml asks for -- 271x148 to 590x150 across the P-ROC games
// that ship one -- rather than pyprocgame's 128x32 nibbles. Sized for the
// largest with room to spare; a game that asks for more is refused at setup.
#define PROC_HD_MAX_WIDTH   640
#define PROC_HD_MAX_HEIGHT  360
#define PROC_HD_MAX_BYTES   (PROC_HD_MAX_WIDTH * PROC_HD_MAX_HEIGHT * 3)

// VP numbering, as register_vpcom.py produced it.
#define PROC_LAMP_COUNT  90
#define PROC_COIL_COUNT  64
#define PROC_GI_COUNT    5

// Power of two: the ring wraps with a mask, never a modulo.
#define PROC_SW_RING     1024
#define PROC_SW_MASK     (PROC_SW_RING - 1)

// Audio ring, child -> host. The child mixes; VPX plays what it produces
// through the same AudioPlayer stream PinMAME's audio already uses, so there
// is one audio device on the machine and VPX's volume applies. 64 KB is about
// 0.37s of 44.1 kHz stereo -- far more than the ~17 ms VPX pulls per frame,
// so a late frame costs nothing.
#define PROC_AUDIO_RING  65536
#define PROC_AUDIO_MASK  (PROC_AUDIO_RING - 1)

// One switch event: VP switch number in the high bits, new value in bit 0.
#define PROC_SW_PACK(num, val)  ((uint16_t)(((num) << 1) | ((val) ? 1u : 0u)))
#define PROC_SW_NUM(packed)     ((uint16_t)((packed) >> 1))
#define PROC_SW_VAL(packed)     (((packed) & 1u) != 0u)

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ProcShm
{
   // --- identity, written once by the host before the child starts ------
   uint32_t magic;
   uint32_t version;
   uint32_t structSize;      // both sides assert this against their own sizeof
   uint32_t reserved0;

   // --- child -> host: machine state ------------------------------------
   //
   // Seqlock. The child bumps seq to odd, writes, bumps to even. The host
   // reads seq, copies, re-reads seq; if either read is odd or they differ,
   // the copy is torn and the host keeps its previous one. It never retries
   // in a loop, because a loop is a wait.
   volatile uint32_t seq;
   volatile uint32_t heartbeat;   // child increments every loop iteration
   volatile uint32_t gameReady;   // 1 once the game's setup() has returned
   volatile uint32_t gameError;   // 1 if the child died in setup or the loop

   uint8_t lamps[PROC_LAMP_COUNT];
   uint8_t coils[PROC_COIL_COUNT];
   uint8_t gi[PROC_GI_COUNT];
   uint8_t reserved1[1];

   // --- child -> host: DMD ----------------------------------------------
   //
   // Its own seqlock so a 4 KB frame copy never stalls a lamp read. One byte
   // per dot: low nibble brightness, high nibble colour index -- the layout
   // procgame.dmd.Frame.get_data() already produces.
   volatile uint32_t dmdSeq;
   uint32_t dmdWidth;
   uint32_t dmdHeight;
   uint32_t reserved2;
   uint8_t dmd[PROC_DMD_BYTES];

   // --- host -> child: switches -----------------------------------------
   //
   // Single-producer (host) single-consumer (child) ring. The host only ever
   // writes swHead, the child only ever writes swTail, so neither needs a
   // lock. A full ring drops the oldest event rather than blocking.
   volatile uint32_t swHead;
   volatile uint32_t swTail;
   uint16_t swRing[PROC_SW_RING];

   // --- host -> child: control ------------------------------------------
   volatile uint32_t hostStop;    // 1 asks the child to leave its run loop
   volatile uint32_t hostAlive;   // host heartbeat, so the child can exit if
                                  // VPX disappears without stopping it

   // --- child -> host: mixed audio --------------------------------------
   //
   // Single producer (child), single consumer (host), so the indices need no
   // lock: the child only writes audioWrite, the host only writes audioRead.
   // Free-running byte counters, masked on use -- an empty ring and a full one
   // are then distinguishable, which they would not be if they wrapped.
   volatile uint32_t audioWrite;
   volatile uint32_t audioRead;
   uint32_t audioRate;            // what the child is producing, set once
   uint32_t audioChannels;
   uint8_t audioRing[PROC_AUDIO_RING];   // interleaved signed 16-bit

   // --- child -> host: HD display (v3) -----------------------------------
   //
   // Appended so every v2 offset above is unchanged. hdWidth/hdHeight are set
   // once, before gameReady, and stay 0 for a pyprocgame game -- which is how
   // the host tells the two kinds apart. Frames are tightly packed RGB24 rows
   // under their own seqlock, like the nibble DMD: a torn read keeps the last
   // frame, and the host never retries in a loop.
   volatile uint32_t hdSeq;
   uint32_t hdWidth;
   uint32_t hdHeight;
   uint32_t reserved3;
   uint8_t hd[PROC_HD_MAX_BYTES];
} ProcShm;

#ifdef __cplusplus
}
#endif
