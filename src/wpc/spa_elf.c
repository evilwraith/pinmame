#define _GNU_SOURCE
#include "spa_elf.h"

#include <elf.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define R_AARCH64_ABS64     257
#define R_AARCH64_GLOB_DAT  1025
#define R_AARCH64_JUMP_SLOT 1026
#define R_AARCH64_RELATIVE  1027

struct spa_object {
    unsigned char *base;
    size_t         span;
    const Elf64_Phdr *phdr;
    size_t            phnum;

    const Elf64_Sym  *symtab;
    const char       *strtab;
    size_t            symcount;

    void  (**init_array)(int, char **, char **);
    size_t   init_count;
};

static int page_round_down(size_t v, size_t ps) { return v & ~(ps - 1); }

static const char *reloc_name(unsigned type)
{
    switch (type) {
    case R_AARCH64_ABS64:     return "ABS64";
    case R_AARCH64_GLOB_DAT:  return "GLOB_DAT";
    case R_AARCH64_JUMP_SLOT: return "JUMP_SLOT";
    case R_AARCH64_RELATIVE:  return "RELATIVE";
    default:                  return "?";
    }
}

// Resolve one symbol index. Symbols defined inside the object bind locally;
// undefined ones go to the host resolver. Unresolved weak symbols bind to 0,
// which is what a real linker does and what the C++ runtime bits expect.
static int resolve_sym(spa_object *o, unsigned idx, spa_resolver resolver,
                       void *user, unsigned long *out)
{
    const Elf64_Sym *sym = &o->symtab[idx];
    const char *name = o->strtab + sym->st_name;

    if (sym->st_shndx != SHN_UNDEF) {
        *out = (unsigned long)(o->base + sym->st_value);
        return 0;
    }

    void *addr = resolver ? resolver(name, user) : NULL;
    if (addr) {
        *out = (unsigned long)addr;
        return 0;
    }
    if (ELF64_ST_BIND(sym->st_info) == STB_WEAK) {
        *out = 0;
        return 0;
    }
    fprintf(stderr, "spa_elf: unresolved symbol '%s'\n", name);
    return -1;
}

static int apply_relocs(spa_object *o, const Elf64_Rela *rela, size_t count,
                        spa_resolver resolver, void *user)
{
    int failures = 0;

    for (size_t i = 0; i < count; i++) {
        unsigned type = ELF64_R_TYPE(rela[i].r_info);
        unsigned idx  = ELF64_R_SYM(rela[i].r_info);
        unsigned long *slot = (unsigned long *)(o->base + rela[i].r_offset);
        unsigned long value;

        switch (type) {
        case R_AARCH64_RELATIVE:
            *slot = (unsigned long)o->base + rela[i].r_addend;
            break;

        case R_AARCH64_ABS64:
        case R_AARCH64_GLOB_DAT:
        case R_AARCH64_JUMP_SLOT:
            if (resolve_sym(o, idx, resolver, user, &value) != 0) {
                failures++;
                break;
            }
            *slot = value + rela[i].r_addend;
            break;

        default:
            fprintf(stderr, "spa_elf: unsupported relocation type %u (%s) at %#lx\n",
                    type, reloc_name(type), (unsigned long)rela[i].r_offset);
            failures++;
            break;
        }
    }
    return failures;
}

spa_object *spa_open_image(const void *image_data, size_t image_size,
                           spa_resolver resolver, void *user)
{
    const unsigned char *file = (const unsigned char *)image_data;

    if (image_size < sizeof(Elf64_Ehdr)) {
        fprintf(stderr, "spa_elf: image too small to be an ELF object\n");
        return NULL;
    }

    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)file;
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0 ||
        eh->e_ident[EI_CLASS] != ELFCLASS64 || eh->e_machine != EM_AARCH64) {
        fprintf(stderr, "spa_elf: not an aarch64 ELF64 object\n");
        return NULL;
    }

    const Elf64_Phdr *ph = (const Elf64_Phdr *)(file + eh->e_phoff);

    // Span of the whole image, so every segment lands at a fixed offset from a
    // single base.
    size_t lo = (size_t)-1, hi = 0;
    for (int i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type != PT_LOAD) continue;
        if (ph[i].p_vaddr < lo) lo = ph[i].p_vaddr;
        if (ph[i].p_vaddr + ph[i].p_memsz > hi) hi = ph[i].p_vaddr + ph[i].p_memsz;
    }
    if (lo == (size_t)-1) {
        fprintf(stderr, "spa_elf: no PT_LOAD segments\n");
        return NULL;
    }

    size_t ps = (size_t)sysconf(_SC_PAGESIZE);
    lo = page_round_down(lo, ps);
    size_t span = ((hi - lo) + ps - 1) & ~(ps - 1);

    // One anonymous RW mapping for the whole image: .bss comes out zeroed for
    // free, and segment contents are copied in. Protections are applied after
    // relocation. (These cores carry a ~130 MB .bss; the mapping is lazy.)
    unsigned char *base = mmap(NULL, span, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) { perror("mmap image"); return NULL; }

    for (int i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type != PT_LOAD) continue;
        memcpy(base + (ph[i].p_vaddr - lo), file + ph[i].p_offset, ph[i].p_filesz);
    }

    spa_object *o = calloc(1, sizeof *o);
    o->base  = base - lo;   // so base[p_vaddr] addresses work directly
    o->span  = span;
    o->phnum = eh->e_phnum;
    o->phdr  = (const Elf64_Phdr *)(o->base + eh->e_phoff);

    // Locate PT_DYNAMIC and read what we need out of it.
    const Elf64_Dyn *dyn = NULL;
    const Elf64_Phdr *relro = NULL;
    for (int i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type == PT_DYNAMIC)  dyn   = (const Elf64_Dyn *)(o->base + ph[i].p_vaddr);
        if (ph[i].p_type == PT_GNU_RELRO) relro = &ph[i];
        if (ph[i].p_type == PT_TLS) {
            // Measured absent; if a future core has one, fail loudly rather
            // than corrupt thread state.
            fprintf(stderr, "spa_elf: object has PT_TLS, which is not supported\n");
            goto fail;
        }
    }
    if (!dyn) { fprintf(stderr, "spa_elf: no PT_DYNAMIC\n"); goto fail; }

    const Elf64_Rela *rela = NULL, *jmprel = NULL;
    size_t relasz = 0, pltrelsz = 0;
    const Elf64_Word *hash = NULL;

    for (const Elf64_Dyn *d = dyn; d->d_tag != DT_NULL; d++) {
        switch (d->d_tag) {
        case DT_SYMTAB:     o->symtab = (const Elf64_Sym *)(o->base + d->d_un.d_ptr); break;
        case DT_STRTAB:     o->strtab = (const char *)(o->base + d->d_un.d_ptr); break;
        case DT_HASH:       hash      = (const Elf64_Word *)(o->base + d->d_un.d_ptr); break;
        case DT_RELA:       rela      = (const Elf64_Rela *)(o->base + d->d_un.d_ptr); break;
        case DT_RELASZ:     relasz    = d->d_un.d_val; break;
        case DT_JMPREL:     jmprel    = (const Elf64_Rela *)(o->base + d->d_un.d_ptr); break;
        case DT_PLTRELSZ:   pltrelsz  = d->d_un.d_val; break;
        case DT_INIT_ARRAY: o->init_array = (void (**)(int, char **, char **))(o->base + d->d_un.d_ptr); break;
        case DT_INIT_ARRAYSZ: o->init_count = d->d_un.d_val / sizeof(void *); break;
        default: break;
        }
    }
    if (!o->symtab || !o->strtab) {
        fprintf(stderr, "spa_elf: missing symbol or string table\n");
        goto fail;
    }

    // DT_HASH's nchain is the authoritative dynamic symbol count.
    o->symcount = hash ? hash[1] : 0;

    int failures = 0;
    if (rela)   failures += apply_relocs(o, rela,   relasz  / sizeof(Elf64_Rela), resolver, user);
    if (jmprel) failures += apply_relocs(o, jmprel, pltrelsz / sizeof(Elf64_Rela), resolver, user);
    if (failures) {
        fprintf(stderr, "spa_elf: %d relocation(s) could not be applied\n", failures);
        goto fail;
    }

    // Apply real segment protections now that every write is done.
    for (int i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type != PT_LOAD) continue;
        int prot = 0;
        if (ph[i].p_flags & PF_R) prot |= PROT_READ;
        if (ph[i].p_flags & PF_W) prot |= PROT_WRITE;
        if (ph[i].p_flags & PF_X) prot |= PROT_EXEC;
        unsigned char *seg = o->base + page_round_down(ph[i].p_vaddr, ps);
        size_t len = (ph[i].p_vaddr - page_round_down(ph[i].p_vaddr, ps)) + ph[i].p_memsz;
        len = (len + ps - 1) & ~(ps - 1);
        if (mprotect(seg, len, prot) != 0) perror("mprotect segment");
    }
    if (relro) {
        unsigned char *seg = o->base + page_round_down(relro->p_vaddr, ps);
        size_t len = (relro->p_vaddr - page_round_down(relro->p_vaddr, ps)) + relro->p_memsz;
        len = (len + ps - 1) & ~(ps - 1);
        if (mprotect(seg, len, PROT_READ) != 0) perror("mprotect relro");
    }



    __builtin___clear_cache((char *)base, (char *)base + span);

    for (size_t i = 0; i < o->init_count; i++)
        if (o->init_array[i]) o->init_array[i](0, NULL, NULL);

    return o;

fail:
    munmap(base, span);

    free(o);
    return NULL;
}

void *spa_sym(spa_object *obj, const char *name)
{
    for (size_t i = 0; i < obj->symcount; i++) {
        const Elf64_Sym *s = &obj->symtab[i];
        if (s->st_shndx == SHN_UNDEF) continue;
        if (strcmp(obj->strtab + s->st_name, name) == 0)
            return obj->base + s->st_value;
    }
    return NULL;
}

void  *spa_base(spa_object *o) { return o->base; }
size_t spa_span(spa_object *o) { return o->span; }

const void *spa_phdr(spa_object *o, size_t *phnum)
{
    if (phnum) *phnum = o->phnum;
    return o->phdr;
}

void spa_close(spa_object *o)
{
    if (!o) return;
    free(o);   // image mapping is intentionally left in place
}

// Convenience wrapper for standalone hosts: read the object off disk and hand
// it to spa_open_image.
spa_object *spa_open(const char *path, spa_resolver resolver, void *user)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror(path); return NULL; }

    struct stat st;
    if (fstat(fd, &st) != 0) { perror("fstat"); close(fd); return NULL; }

    unsigned char *file = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (file == MAP_FAILED) { perror("mmap file"); return NULL; }

    spa_object *o = spa_open_image(file, st.st_size, resolver, user);
    munmap(file, st.st_size);
    return o;
}
