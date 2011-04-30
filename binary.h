#pragma once

struct dyld_cache_header;
struct shared_file_mapping_np;
struct mach_header;
struct dysymtab_command;
struct binary {
    bool valid;

    int actual_cpusubtype;
    void *load_add;
    prange_t valid_range;

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

    // alternatively
    prange_t export_trie;
    addr_t export_baseaddr;

    char *strtab;
    uint32_t strsize;
    struct dysymtab_command *dysymtab;

    struct binary *reexports;
    unsigned int reexport_count;
};


__attribute__((const)) prange_t rangeconv(range_t range);
__attribute__((const)) prange_t rangeconv_off(range_t range);
__attribute__((const)) range_t range_to_off_range(range_t range);
__attribute__((const)) range_t off_range_to_range(range_t range);

void b_init(struct binary *binary);

void b_load_dyldcache(struct binary *binary, const char *path, bool rw);
void b_prange_load_dyldcache(struct binary *binary, prange_t range, const char *name);
void b_dyldcache_load_macho(const struct binary *binary, const char *filename, struct binary *out);

void b_macho_load_symbols(struct binary *binary);
void b_load_macho(struct binary *binary, const char *path, bool rw);
void b_fd_load_macho(struct binary *binary, int fd, bool rw);
void b_prange_load_macho(struct binary *binary, prange_t range, const char *name);

__attribute__((const)) range_t b_macho_segrange(const struct binary *binary, const char *segname);
void b_macho_store(struct binary *binary, const char *path);

range_t b_nth_segment(const struct binary *binary, unsigned int n);
addr_t b_sym(const struct binary *binary, const char *name, bool to_execute, bool must_find);
addr_t b_private_sym(const struct binary *binary, const char *name, bool to_execute, bool must_find);

uint32_t b_allocate_from_macho_fd(int fd);
void b_inject_into_macho_fd(const struct binary *binary, int fd, addr_t (*find_hack_func)(const struct binary *binary));

#define CMD_ITERATE(hdr, cmd) for(struct load_command *cmd = (void *)((hdr) + 1), *end = (void *)((char *)(hdr + 1) + (hdr)->sizeofcmds); cmd < end; cmd = (void *)((char *)cmd + cmd->cmdsize))

#define r(sz) \
static inline uint##sz##_t b_read##sz(const struct binary *binary, addr_t addr) { \
    return *(uint##sz##_t *)(rangeconv((range_t) {binary, addr, sz/8}).start); \
}

r(8)
r(16)
r(32)
r(64)
