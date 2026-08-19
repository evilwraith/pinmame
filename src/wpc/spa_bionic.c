//
// spa_bionic — import resolution for Android shared objects loaded into glibc.
//
// 86 of the 93 symbols libSternGB.so imports exist in glibc and are forwarded
// verbatim. This file covers the rest, in three groups:
//
//  1. Bionic-only functions glibc simply lacks (__errno, the __*_chk variants
//     Android added, the liblog and abort-message entry points).
//
//  2. Types that exist in both but with different sizes. This is the dangerous
//     group: Bionic's pthread_mutex_t is 40 bytes where glibc's aarch64 one is
//     48, so handing a Bionic-allocated mutex to glibc's pthread_mutex_init
//     writes 8 bytes past it. Every such object is therefore indirected — the
//     Bionic-sized slot holds a pointer to a real glibc object allocated here.
//     Only the *_init entry points are imported (no attribute setters), so
//     default attributes are all that is needed.
//
//  3. Bionic's stdio, where stdin/stdout/stderr are &__sF[0..2] and the stride
//     is Bionic's FILE size. The library computes those addresses itself, so
//     the FILE* it hands back has to be translated to a glibc stream.
//
#define _GNU_SOURCE
#include "spa_elf.h"

#include <dlfcn.h>
#include <errno.h>
#include <link.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>


// ---------------------------------------------------------------- group 1

static int *shim___errno(void) { return __errno_location(); }

static int shim___android_log_print(int prio, const char *tag, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    flockfile(stderr);
    fprintf(stderr, "[stern:%d:%s] ", prio, tag ? tag : "?");
    int n = vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    funlockfile(stderr);
    va_end(ap);
    return n;
}

static void shim_android_set_abort_message(const char *msg)
{
    fprintf(stderr, "spa: abort message: %s\n", msg ? msg : "(null)");
}

static size_t shim___strlen_chk(const char *s, size_t len)
{
    size_t n = strlen(s);
    if (n >= len) { fprintf(stderr, "spa: __strlen_chk overflow\n"); abort(); }
    return n;
}

static char *shim___strrchr_chk(const char *p, int ch, size_t len)
{
    (void)len;
    return strrchr(p, ch);
}

static char *shim___strncpy_chk2(char *dst, const char *src, size_t n,
                                 size_t dst_len, size_t src_len)
{
    (void)src_len;
    if (n > dst_len) { fprintf(stderr, "spa: __strncpy_chk2 overflow\n"); abort(); }
    return strncpy(dst, src, n);
}

// ---------------------------------------------------------------- group 2
//
// Bionic-sized slots, indirected to real glibc objects. The first pointer-sized
// word of the caller's object holds the glibc object; a NULL word means the
// caller used a static initializer (all zeroes in Bionic) and never called
// init, so create it on first use.

static pthread_mutex_t indirect_lock = PTHREAD_MUTEX_INITIALIZER;

// The handle stored in the caller's slot is a 32-bit table index, not a
// pointer. Bionic's pthread_mutex_t is int32_t[10] and its cond_t int32_t[12],
// so these objects are only 4-byte aligned — an 8-byte atomic access on one
// takes SIGBUS on aarch64. A uint32_t index is always aligned where an int32
// array is. Index 0 means "not created yet", which is also what Bionic's
// all-zero static initializers leave behind.
#define MAX_SYNC 8192
static pthread_mutex_t *mutex_table[MAX_SYNC];
static pthread_cond_t  *cond_table[MAX_SYNC];
static uint32_t mutex_used, cond_used;

static pthread_mutex_t *real_mutex(void *slot)
{
    uint32_t *h = (uint32_t *)slot;
    uint32_t idx = __atomic_load_n(h, __ATOMIC_ACQUIRE);
    if (idx) return mutex_table[idx - 1];

    pthread_mutex_lock(&indirect_lock);
    idx = *h;
    if (!idx) {
        if (mutex_used >= MAX_SYNC) {
            fprintf(stderr, "spa: mutex table exhausted\n");
            abort();
        }
        pthread_mutex_t *m = calloc(1, sizeof *m);
        pthread_mutex_init(m, NULL);
        mutex_table[mutex_used] = m;
        idx = ++mutex_used;
        __atomic_store_n(h, idx, __ATOMIC_RELEASE);
    }
    pthread_mutex_unlock(&indirect_lock);
    return mutex_table[idx - 1];
}

static pthread_cond_t *real_cond(void *slot)
{
    uint32_t *h = (uint32_t *)slot;
    uint32_t idx = __atomic_load_n(h, __ATOMIC_ACQUIRE);
    if (idx) return cond_table[idx - 1];

    pthread_mutex_lock(&indirect_lock);
    idx = *h;
    if (!idx) {
        if (cond_used >= MAX_SYNC) {
            fprintf(stderr, "spa: cond table exhausted\n");
            abort();
        }
        pthread_cond_t *c = calloc(1, sizeof *c);
        pthread_cond_init(c, NULL);
        cond_table[cond_used] = c;
        idx = ++cond_used;
        __atomic_store_n(h, idx, __ATOMIC_RELEASE);
    }
    pthread_mutex_unlock(&indirect_lock);
    return cond_table[idx - 1];
}

// Bionic object sizes (LP64), so a slot is fully cleared before use.
#define BIONIC_MUTEX_SIZE 40
#define BIONIC_COND_SIZE  48
#define BIONIC_ATTR_SIZE  56
#define BIONIC_FILE_SIZE  152

static int shim_pthread_mutex_init(void *m, const void *attr)
{
    (void)attr;
    memset(m, 0, BIONIC_MUTEX_SIZE);
    real_mutex(m);
    return 0;
}
// Deliberately keeps the underlying mutex alive. Freeing it here would race
// against any thread already inside real_mutex() holding the index: it would
// dereference a table slot that just became NULL. These cores run ~20 threads
// and do destroy their locks, so that race is real. Leaking one small object
// per destroyed mutex is the cheaper side of the trade; a slot that gets
// re-initialised is zeroed by shim_pthread_mutex_init and takes a fresh index.
static int shim_pthread_mutex_destroy(void *m)
{
    (void)m;
    return 0;
}
static int shim_pthread_mutex_lock(void *m)   { return pthread_mutex_lock(real_mutex(m)); }
static int shim_pthread_mutex_unlock(void *m) { return pthread_mutex_unlock(real_mutex(m)); }

static int shim_pthread_cond_init(void *c, const void *attr)
{
    (void)attr;
    memset(c, 0, BIONIC_COND_SIZE);
    real_cond(c);
    return 0;
}
static int shim_pthread_cond_signal(void *c)    { return pthread_cond_signal(real_cond(c)); }
static int shim_pthread_cond_broadcast(void *c) { return pthread_cond_broadcast(real_cond(c)); }
static int shim_pthread_cond_wait(void *c, void *m)
{
    return pthread_cond_wait(real_cond(c), real_mutex(m));
}
static int shim_pthread_cond_timedwait(void *c, void *m, const struct timespec *ts)
{
    return pthread_cond_timedwait(real_cond(c), real_mutex(m), ts);
}

// Only *_init is imported, so attributes are always defaults; zero the
// caller's Bionic-sized buffer and never hand it to glibc.
static int shim_pthread_mutexattr_init(void *a) { memset(a, 0, 4); return 0; }
static int shim_pthread_condattr_init(void *a)  { memset(a, 0, 4); return 0; }
static int shim_pthread_attr_init(void *a)      { memset(a, 0, BIONIC_ATTR_SIZE); return 0; }

static int shim_pthread_create(pthread_t *t, const void *attr,
                               void *(*fn)(void *), void *arg)
{
    (void)attr;   // defaults only; see above
    return pthread_create(t, NULL, fn, arg);
}

// ---------------------------------------------------------------- group 3

static unsigned char bionic_sF[3 * BIONIC_FILE_SIZE];

// Map a FILE* the library derived from &__sF[i] onto the matching glibc stream.
// Anything else is a pointer we handed out from fopen, so it passes through.
static FILE *xlat(void *f)
{
    unsigned char *p = (unsigned char *)f;
    if (p < bionic_sF || p >= bionic_sF + sizeof bionic_sF) return (FILE *)f;
    switch ((size_t)(p - bionic_sF) / BIONIC_FILE_SIZE) {
    case 0:  return stdin;
    case 1:  return stdout;
    default: return stderr;
    }
}

static int shim_fprintf(void *f, const char *fmt, ...)
{
    va_list ap; va_start(ap, fmt);
    int n = vfprintf(xlat(f), fmt, ap);
    va_end(ap);
    return n;
}
static int shim_vfprintf(void *f, const char *fmt, va_list ap) { return vfprintf(xlat(f), fmt, ap); }
static int shim_fputc(int c, void *f)     { return fputc(c, xlat(f)); }
static int shim_fflush(void *f)           { return fflush(f ? xlat(f) : NULL); }
static int shim_fclose(void *f)           { return fclose(xlat(f)); }
static size_t shim_fwrite(const void *b, size_t s, size_t n, void *f) { return fwrite(b, s, n, xlat(f)); }
static size_t shim_fread(void *b, size_t s, size_t n, void *f)        { return fread(b, s, n, xlat(f)); }
static int shim_fseek(void *f, long off, int whence) { return fseek(xlat(f), off, whence); }
static long shim_ftell(void *f)                      { return ftell(xlat(f)); }

// ---------------------------------------------------------------- unwinder
//
// The C++ runtime finds .eh_frame_hdr via dl_iterate_phdr. glibc's loader never
// saw this object, so without this shim any thrown exception aborts.

#define MAX_OBJECTS 8
static struct { void *base; const void *phdr; size_t phnum; const char *name; } objects[MAX_OBJECTS];
static int object_count;

void spa_bionic_register(spa_object *o, const char *name)
{
    if (object_count >= MAX_OBJECTS) return;
    size_t phnum;
    const void *phdr = spa_phdr(o, &phnum);
    objects[object_count].base = spa_base(o);
    objects[object_count].phdr = phdr;
    objects[object_count].phnum = phnum;
    objects[object_count].name = name;
    object_count++;
}

static int shim_dl_iterate_phdr(int (*cb)(struct dl_phdr_info *, size_t, void *), void *data)
{
    for (int i = 0; i < object_count; i++) {
        struct dl_phdr_info info;
        memset(&info, 0, sizeof info);
        info.dlpi_addr  = (ElfW(Addr))objects[i].base;
        info.dlpi_name  = objects[i].name;
        info.dlpi_phdr  = (const ElfW(Phdr) *)objects[i].phdr;
        info.dlpi_phnum = (ElfW(Half))objects[i].phnum;
        int rc = cb(&info, sizeof info, data);
        if (rc) return rc;
    }
    return dl_iterate_phdr(cb, data);
}

// ---------------------------------------------------------------- resolver

static const struct { const char *name; void *fn; } shims[] = {
    { "__errno",                    (void *)shim___errno },
    { "__sF",                       (void *)bionic_sF },
    { "__android_log_print",        (void *)shim___android_log_print },
    { "android_set_abort_message",  (void *)shim_android_set_abort_message },
    { "__strlen_chk",               (void *)shim___strlen_chk },
    { "__strrchr_chk",              (void *)shim___strrchr_chk },
    { "__strncpy_chk2",             (void *)shim___strncpy_chk2 },

    { "pthread_mutex_init",         (void *)shim_pthread_mutex_init },
    { "pthread_mutex_destroy",      (void *)shim_pthread_mutex_destroy },
    { "pthread_mutex_lock",         (void *)shim_pthread_mutex_lock },
    { "pthread_mutex_unlock",       (void *)shim_pthread_mutex_unlock },
    { "pthread_cond_init",          (void *)shim_pthread_cond_init },
    { "pthread_cond_signal",        (void *)shim_pthread_cond_signal },
    { "pthread_cond_broadcast",     (void *)shim_pthread_cond_broadcast },
    { "pthread_cond_wait",          (void *)shim_pthread_cond_wait },
    { "pthread_cond_timedwait",     (void *)shim_pthread_cond_timedwait },
    { "pthread_mutexattr_init",     (void *)shim_pthread_mutexattr_init },
    { "pthread_condattr_init",      (void *)shim_pthread_condattr_init },
    { "pthread_attr_init",          (void *)shim_pthread_attr_init },
    { "pthread_create",             (void *)shim_pthread_create },

    { "fprintf",                    (void *)shim_fprintf },
    { "vfprintf",                   (void *)shim_vfprintf },
    { "fputc",                      (void *)shim_fputc },
    { "fflush",                     (void *)shim_fflush },
    { "fclose",                     (void *)shim_fclose },
    { "fwrite",                     (void *)shim_fwrite },
    { "fread",                      (void *)shim_fread },
    { "fseek",                      (void *)shim_fseek },
    { "ftell",                      (void *)shim_ftell },

    { "dl_iterate_phdr",            (void *)shim_dl_iterate_phdr },
};

void *spa_bionic_resolve(const char *name, void *user)
{
    (void)user;
    for (size_t i = 0; i < sizeof shims / sizeof shims[0]; i++)
        if (strcmp(name, shims[i].name) == 0) return shims[i].fn;

    return dlsym(RTLD_DEFAULT, name);
}
