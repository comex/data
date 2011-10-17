#pragma once
#include "binary.h"

uint32_t b_allocate_from_macho_fd(int fd);
void b_inject_into_macho_fd(const struct binary *binary, int fd, addr_t (*find_hack_func)(const struct binary *binary), bool userland);

