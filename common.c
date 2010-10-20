#include "common.h"

prange_t pdup(prange_t range) {
    void *buf = malloc(range.size);
    memcpy(buf, range.start, range.size);
    return (prange_t) {buf, range.size};
}

void write_range(prange_t range, const char *fn, mode_t mode) {
    int fd = open(fn, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if(fd == -1) {
        edie("write_range: could not open %s", fn);
    }
    if(write(fd, range.start, range.size) != range.size) {
        edie("write_range: could not write data to %s", fn);
    }
    close(fd);
}

void check_range_has_addr(range_t range, addr_t addr) {
    if(addr < range.start || addr >= (range.start | range.size)) {
        die("bad address 0x%08x (not in range %08x-%08x)", addr, range.start, range.start + (uint32_t) range.size);
    }
}

