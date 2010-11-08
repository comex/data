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

static inline bool parse_hex_digit(char digit, uint8_t *result) {
    if(digit >= '0' && digit <= '9') {
        *result = digit - '0';
        return true;
    } else if(digit >= 'a' && digit <= 'f') {
        *result = 10 + (digit - 'a');
        return true;
    }
    return false;
}

prange_t parse_hex_string(char *string) {
    size_t len = strlen(string);
    if(len % 2) goto bad;
    len /= 2;
    uint8_t *buf = malloc(len);
    prange_t result = (prange_t) {buf, len};
    while(len--) {
        char first = *string++;
        char second = *string++;
        uint8_t a, b;
        if(!parse_hex_digit(first, &a)) goto bad;
        if(!parse_hex_digit(second, &b)) goto bad;
        *buf++ = (a * 0x10) + b;
    }
    return result;
    bad:
    die("bad hex string %s", string);
}

uint32_t parse_hex_uint32(char *string) {
    prange_t pr = parse_hex_string(string);
    if(pr.size > sizeof(uint32_t)) { 
        die("too long hex string %s", string);
    }
    uint32_t u;
    memcpy(&u, pr.start, pr.size);
    free(pr.start);
    return u;
}
