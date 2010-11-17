#include "../config/config_asm.h"

static void check_no_placeholders(prange_t pr) {
    for(uintptr_t addr = (uintptr_t)pr.start; addr + sizeof(uint32_t) <= (uintptr_t)pr.start + pr.size; addr++) {
        uint32_t val = *(uint32_t *)addr;
        if(val > CONFIG_MIN && val < CONFIG_MAX) {
            die("got %08x", val);
        }
    }
}

