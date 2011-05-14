#pragma once
#include "common.h"
#include "binary.h"

typedef uint32_t (*lookupsym_t)(const struct binary *binary, const char *sym);

__BEGIN_DECLS

void b_relocate(struct binary *load, const struct binary *target, lookupsym_t lookup_sym, uint32_t slide);

__END_DECLS
