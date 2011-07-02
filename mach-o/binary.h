#pragma once
#include "../binary.h"

#define CMD_ITERATE(hdr, cmd) for(struct load_command *cmd = (struct load_command *)((hdr) + 1), *end = (struct load_command *)((char *)(hdr + 1) + (hdr)->sizeofcmds); cmd < end; cmd = (struct load_command *)((char *)cmd + cmd->cmdsize))

struct mach_binary {
    struct mach_header *hdr;

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

};

__BEGIN_DECLS

__attribute__((const)) range_t b_macho_segrange(const struct binary *binary, const char *segname);
__attribute__((const)) range_t b_macho_sectrange(const struct binary *binary, const char *segname, const char *sectname);
void b_macho_store(struct binary *binary, const char *path);

void b_prange_load_macho(struct binary *binary, prange_t range, size_t offset, const char *name);

uint32_t b_allocate_from_macho_fd(int fd);
void b_inject_into_macho_fd(const struct binary *binary, int fd, addr_t (*find_hack_func)(const struct binary *binary));

void b_load_macho(struct binary *binary, const char *filename);

struct nlist *b_macho_nth_symbol(const struct binary *binary, uint32_t n);

__END_DECLS
