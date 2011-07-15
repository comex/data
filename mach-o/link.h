#pragma once
#include "binary.h"

typedef uint32_t (*lookupsym_t)(const struct binary *binary, const char *sym);

enum reloc_mode {
    RELOC_DEFAULT,
    RELOC_LOCAL_ONLY,
    RELOC_EXTERN_ONLY
};

__BEGIN_DECLS

void b_relocate(struct binary *load, const struct binary *target, enum reloc_mode mode, lookupsym_t lookup_sym, uint32_t slide);

__END_DECLS
