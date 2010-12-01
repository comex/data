#pragma once
#include "common.h"
#include "binary.h"
uint32_t b_lookup_sym(const struct binary *binary, char *sym);
void b_relocate(struct binary *binary, uint32_t slide);
uint32_t b_find_sysent(const struct binary *kern);
