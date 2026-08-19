//
// spa_elf — minimal aarch64 ELF loader for Android (Bionic) shared objects.
//
// Loads FarSight's native libStern*.so cores from the Pinball Arcade APK into a
// glibc process, without Bionic, box64 or qemu. Deliberately not a general
// dynamic linker: it handles exactly what these libraries need, which was
// measured first (backport/spa-port-plan.md §4):
//
//   - two PT_LOAD segments, no PT_TLS
//   - four relocation types: RELATIVE, ABS64, GLOB_DAT, JUMP_SLOT
//   - DT_BIND_NOW, so every relocation is resolved eagerly and there is no
//     lazy-binding PLT resolver to emulate
//   - a DT_INIT_ARRAY of C++ static constructors to run before first use
//
// Imports are resolved through a caller-supplied table (see spa_bionic.c),
// which is where the Bionic-vs-glibc ABI differences are absorbed.
//
#ifndef SPA_ELF_H
#define SPA_ELF_H

#include <stddef.h>

typedef struct spa_object spa_object;

// Resolve an undefined symbol by name. Return NULL if unknown; the loader then
// reports it rather than silently binding a crash.
typedef void *(*spa_resolver)(const char *name, void *user);

// Map, relocate and initialize an object already held in memory. `image` is
// only read during the call and may be freed afterwards. Returns NULL on
// failure and writes a reason to stderr; `resolver` is consulted for every
// undefined symbol.
spa_object *spa_open_image(const void *image, size_t size, spa_resolver resolver, void *user);

// Same, reading the object from a file. Convenience for standalone hosts;
// PinMAME goes through spa_open_image so the file can come from MAME's ROM
// search path rather than a filesystem path.
spa_object *spa_open(const char *path, spa_resolver resolver, void *user);

// Look up an exported symbol. Returns NULL if absent.
void *spa_sym(spa_object *obj, const char *name);

// Base address the object was mapped at, and its total span. Exposed so the
// host can register the object with a dl_iterate_phdr shim (the C++ unwinder
// needs to find .eh_frame_hdr for an object glibc's loader never saw).
void  *spa_base(spa_object *obj);
size_t spa_span(spa_object *obj);
const void *spa_phdr(spa_object *obj, size_t *phnum);

void spa_close(spa_object *obj);

#endif
