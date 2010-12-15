#pragma once
#include "common.h"
#include "binary.h"

uint32_t b_allocate_from_running_kernel(const struct binary *to_load);
void b_inject_into_running_kernel(const struct binary *to_load, uint32_t sysent);
void unload_from_running_kernel(uint32_t addr);
void b_running_kernel_load_macho(struct binary *binary);
