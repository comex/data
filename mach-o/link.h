#pragma once
#include "binary.h"

typedef addr_t (*lookupsym_t)(const struct binary *binary, const char *sym);

enum reloc_mode {
    RELOC_DEFAULT,
    RELOC_LOCAL_ONLY,
    RELOC_EXTERN_ONLY,
    RELOC_USERLAND
};

__BEGIN_DECLS

void b_relocate(struct binary *load, const struct binary *target, enum reloc_mode mode, lookupsym_t lookup_sym, addr_t slide);

__END_DECLS
