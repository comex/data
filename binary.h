#pragma once

struct dyld_cache_header;
struct shared_file_mapping_np;
struct mach_header;
struct dysymtab_command;
struct binary {
    int actual_cpusubtype;
    void *load_base;

    struct dyld_cache_header *dyld_hdr;
    uint32_t dyld_mapping_count;
    struct shared_file_mapping_np *dyld_mappings;
    struct shared_file_mapping_np *last_sfm;

    struct mach_header *mach_hdr;
    struct segment_command *last_seg;

    struct nlist *symtab;
    uint32_t nsyms;
    
    // for b_sym (external stuff)
    struct nlist *ext_symtab;
    uint32_t ext_nsyms;

    char *strtab;
    uint32_t strsize;
    struct dysymtab_command *dysymtab;
};


//#define I_TRUST_YOU

// check for start + size exceeding the range
__attribute__((const))
prange_t rangeconv_checkof(range_t range);

#ifdef I_TRUST_YOU
#define rangeconv rangeconv_checkof
#else
__attribute__((const)) prange_t rangeconv(range_t range);
#endif
__attribute__((const)) prange_t rangeconv_off(range_t range);

__attribute__((const, always_inline))
static inline void *b_addrconv_unsafe(const struct binary *binary, addr_t addr) {
    return (void *) ((char *)binary->load_base + (addr & 0x0fffffff));
}

void b_init(struct binary *binary);

void b_load_dyldcache(struct binary *binary, const char *path);
void b_load_running_dyldcache(struct binary *binary, void *baseaddr);
range_t b_dyldcache_nth_segment(const struct binary *binary, int n);
void b_dyldcache_load_macho(struct binary *binary, const char *filename);

void b_running_kernel_load_macho(struct binary *binary);
void b_macho_load_symbols(struct binary *binary);
void b_load_macho(struct binary *binary, const char *path);
__attribute__((pure)) range_t b_macho_segrange(const struct binary *binary, const char *segname);
void b_macho_store(struct binary *binary, const char *path);

addr_t b_sym(const struct binary *binary, const char *name, bool to_execute);

#define CMD_ITERATE(hdr, cmd) for(struct load_command *cmd = (void *)((hdr) + 1), *end = (void *)((char *)(hdr) + (hdr)->sizeofcmds); cmd; cmd = cmd->cmdsize < ((char *)end - (char *)cmd) ? (void *)((char *)cmd + cmd->cmdsize) : NULL)

#define r(sz) \
static inline uint##sz##_t read##sz(const struct binary *binary, addr_t addr) { \
    return *(uint##sz##_t *)(rangeconv((range_t) {binary, addr, sz/8}).start); \
}

r(8)
r(16)
r(32)
r(64)

