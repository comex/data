#pragma once
#include "../binary.h"

#define CMD_ITERATE(hdr, cmd) for(struct load_command *cmd = (struct load_command *)((hdr) + 1), *end = (struct load_command *)((char *)((hdr) + 1) + (hdr)->sizeofcmds); cmd < end; cmd = (struct load_command *)((char *)cmd + cmd->cmdsize))

struct load_command;

struct mach_binary {
    // this is unnecessary, don't use it
    struct mach_header *hdr;

    // this stuff is _all_ symbols...

    struct nlist *symtab;
    uint32_t nsyms;
    
    // for b_sym (external stuff)
    struct nlist *ext_symtab, *imp_symtab;
    uint32_t ext_nsyms, imp_nsyms;

    // alternatively
    struct dyld_info_command *dyld_info;
    prange_t export_trie;
    addr_t export_baseaddr;

    char *strtab;
    uint32_t strsize;
    const struct dysymtab_command *dysymtab;
};

__BEGIN_DECLS

static inline struct mach_header *b_mach_hdr(const struct binary *binary) {
    return binary->valid_range.start + binary->header_offset;
}

__attribute__((pure)) range_t b_macho_segrange(const struct binary *binary, const char *segname);
__attribute__((pure)) range_t b_macho_sectrange(const struct binary *binary, const char *segname, const char *sectname);

void b_prange_load_macho(struct binary *binary, prange_t range, size_t offset, const char *name);
void b_prange_load_macho_nosyms(struct binary *binary, prange_t range, size_t offset, const char *name);

void b_load_macho(struct binary *binary, const char *filename);

struct nlist *b_macho_nth_symbol(const struct binary *binary, uint32_t n);

addr_t b_macho_reloc_base(const struct binary *binary);

#define b_pointer_size(binary) (sizeof(addr_t) == 4 ? (uint8_t) 4 : (binary)->pointer_size)

const char *convert_lc_str(const struct load_command *cmd, uint32_t offset);

__END_DECLS

