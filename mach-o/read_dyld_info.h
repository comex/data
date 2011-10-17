#pragma once
#include <stdint.h>
// ld64
static uint32_t read_uleb128(void **ptr, void *end) {
    uint32_t result = 0;
    uint8_t *p = *ptr;
    uint8_t bit;
    int shift = 0;
    do {
        if(p >= (uint8_t *) end) die("uleb128 overrun");
        bit = *p++;
        uint32_t k = bit & 0x7f;
        if(((k << shift) >> shift) != k) die("uleb128 too big");
        result |= k << shift;
        shift += 7;
    } while(bit & 0x80);
    *ptr = p;
    return result;
}

static inline void *read_bytes(void **ptr, void *end, size_t size) {
    char *p = *ptr;
    if((size_t) ((char *) end - p) < size) die("too big");
    *ptr = p + size;
    return p;
}

#define read_int(ptr, end, typ) *((typ *) read_bytes(ptr, end, sizeof(typ)))
