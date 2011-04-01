#include "find.h"
#include "binary.h"

static addr_t find_data_raw(range_t range, int16_t *buf, ssize_t pattern_size, size_t offset, int align, bool must_find, const char *name) {
    // the problem with this is that it would probably be faster to search for everything at once
    int8_t table[256];
    for(int c = 0; c < 256; c++) {
        table[c] = pattern_size + 1;
    }
    for(int pos = 0; pos < pattern_size; pos++) {
        if(buf[pos] == -1) {
            // Unfortunately, we can't put any character past being in this position...
            for(int i = 0; i < 256; i++) {
                table[i] = pattern_size - pos;// - 1;
            }
        } else {
            table[buf[pos]] = pattern_size - pos;// - 1;
        }
    }
    // now, for each c, let x be the last position in the string, other than the final position, where c might appear, or -1 if it doesn't appear anywhere; table[i] is size - x - 1.
    // so if we got c but no match, we can skip ahead by table[i]
    // i.e. lame Boyer–Moore
    // I implemented the other half, but it actually made things /slower/
    buf += pattern_size;
    addr_t foundit = 0;
    prange_t pr = rangeconv(range);
    uint8_t *start = pr.start + pattern_size, *cursor = start;
    uint8_t *end = pr.start + pr.size;
    while(cursor <= end) {
        for(int i = -1; i >= -pattern_size; i--) {
            if(buf[i] != -1 && cursor[i] != buf[i]) {
                // Not a match
                goto keep_going;
            }
        }
        // Whoa, we found it
        addr_t new = cursor - start + range.start;
        if(align && (new & (align - 1))) {
            // Just kidding.
            goto keep_going;
        }
        if(foundit) {
            die("found [%s] multiple times in range: first at %08x then at %08x", name, foundit, new);
        }
        foundit = new;
        if(align) {
            break;
        }
        // otherwise, keep searching to make sure we won't find it again
        keep_going:;
        int jump = table[*cursor];
        cursor += jump;
    }
    if(foundit) {
        return foundit + offset;
    } else if(must_find) {
        die("didn't find [%s] in range (%x, %zx)", name, range.start, range.size);
    } else {
        return 0;
    }
}

addr_t find_data(range_t range, char *to_find, int align, bool must_find) {
#ifdef PROFILING
    clock_t a = clock();
#endif
    int16_t buf[128];
    ssize_t pattern_size = 0;
    ssize_t offset = -1;
    autofree char *to_find_ = strdup(to_find);
    while(to_find_) {
        char *bit = strsep(&to_find_, " ");
        if(!strcmp(bit, "-")) {
            offset = pattern_size; 
            continue;
        } else if(!strcmp(bit, "+")) {
            offset = pattern_size + 1;
            continue;
        } else if(!strcmp(bit, "..")) {
            buf[pattern_size] = -1;
        } else {
            char *endptr;
            buf[pattern_size] = (int16_t) (strtol(bit, &endptr, 16) & 0xff);
            if(*endptr) {
                die("invalid bit %s in [%s]", bit, to_find);
            }
        }
        if(++pattern_size >= 128) {
            die("pattern [%s] too big", to_find);
        }
    }
    if(offset == -1) {
        die("pattern [%s] doesn't have an offset", to_find);
    }
    addr_t result = find_data_raw(range, buf, pattern_size, offset, align, must_find, to_find);
#ifdef PROFILING
    clock_t b = clock();
    printf("find_data [%s] took %d/%d\n", to_find, (int)(b - a), (int)CLOCKS_PER_SEC);
#endif
    return result;
}

addr_t find_string(range_t range, const char *string, int align, bool must_find) {
    size_t len = strlen(string);
    autofree int16_t *buf = malloc(sizeof(int16_t) * (len + 2));
    buf[0] = buf[len + 1] = 0;
    for(unsigned int i = 0; i < len; i++) {
        buf[i+1] = (uint8_t) string[i];
    }
    addr_t result = find_data_raw(range, buf, len + 2, 1, align, must_find, string);
    return result;
}

addr_t find_bytes(range_t range, const char *bytes, size_t len, int align, bool must_find) {
    autofree int16_t *buf = malloc(sizeof(int16_t) * (len + 2));
    for(unsigned int i = 0; i < len; i++) {
        buf[i] = (uint8_t) bytes[i];
    }
    addr_t result = find_data_raw(range, buf, len, 0, align, must_find, "bytes");
    return result;
}
addr_t find_int32(range_t range, uint32_t number, bool must_find) {
    prange_t pr = rangeconv(range);
    char *start = pr.start;
    char *end = pr.start + pr.size;
    for(char *p = start; p + 4 <= end; p++) {
        if(*((uint32_t *)p) == number) {
            return p - start + range.start;
        }
    }
    if(must_find) {
        die("didn't find %08x in range", number);
    } else {
        return 0;
    }
}

addr_t find_bof(range_t range, addr_t eof, bool is_thumb) {
    // push {..., lr}; add r7, sp, ...
    addr_t addr = (eof - 1) & ~1;
    check_range_has_addr(range, addr);
    prange_t pr = rangeconv(range);
    if(is_thumb) {
        addr &= ~1;
        uint8_t *p = pr.start + (addr - range.start);
        // xx b5 xx af
        while(!(p[1] == 0xb5 && \
                p[3] == 0xaf)) {
            p -= 2;
            addr -= 2;
            if((void *)p < (void *)pr.start) goto fail;
        }
    } else {
        addr &= ~3;
        uint16_t *p = pr.start + (addr - range.start);
        // xx xx 2d e9 xx xx 8d e2
        while(!(p[1] == 0xe92d && \
                p[3] == 0xe28d)) {
            p -= 2;
            addr -= 4;
            if((void *)p < (void *)pr.start) goto fail;
        }
    }
    return addr;
    fail:
    die("couldn't find the beginning of %08x", eof);
}

uint32_t resolve_ldr(struct binary *binary, addr_t addr) {
    uint32_t val = b_read32(binary, addr & ~1); 
    addr_t target;
    if(addr & 1) {
        addr_t base = ((addr + 3) & ~3);
        if((val & 0xf800) == 0x4800) { // thumb
            target = base + ((val & 0xff) * 4);
        } else if((val & 0xffff) == 0xf8df) { // thumb-2
            target = base + ((val & 0x0fff0000) >> 16);
        } else {
            die("weird thumb instruction %08x at %08x", val, addr);
        }
    } else {
        addr_t base = addr + 8;
        if((val & 0x0fff0000) == 0x59f0000) { // arm
            target = base + (val & 0xfff);
        } else {
            die("weird ARM instruction %08x at %08x", val, addr);
        }
    }
    return b_read32(binary, target);
}

addr_t find_bl(range_t *range) {
    bool thumb = range->start & 1;
    range->start &= ~1;
    prange_t pr = rangeconv(*range);    
    uint32_t diff;
    void *base;
    if(thumb) {
        uint16_t *p = pr.start;
        while((uintptr_t)(p + 2) <= (uintptr_t)pr.start + pr.size) {
            base = p;
            uint16_t val = *p++;
            if((val & 0xf800) == 0xf000) {
                uint32_t imm10 = val & 0x3ff;
                uint32_t S = ((val & 0x400) >> 10);
                uint16_t val2 = *p++;

                uint32_t J1 = ((val2 & 0x2000) >> 13);
                uint32_t J2 = ((val2 & 0x800) >> 11);
                uint32_t I1 = ~(J1 ^ S) & 1, I2 = ~(J2 ^ S) & 1;
                uint32_t imm11 = val2 & 0x7ff;
                diff = (S << 24) | (I1 << 23) | (I2 << 22) | (imm10 << 12) | (imm11 << 1);

                if((val2 & 0xd000) == 0xd000) {
                    // BL
                    diff |= 1;
                    goto ok;
                } else if((val2 & 0xd000) == 0xc000) {
                    // BLX
                    goto ok;
                }
            }
        }
    } else {
        uint32_t *p = pr.start;
        while((uintptr_t)(p + 1) <= (uintptr_t)pr.start + pr.size) {
            base = p;
            uint32_t val = *p++;
            if((val & 0xfe000000) == 0xfa000000) {
                // BL
                diff = ((val & 0xffffff) << 2);
                goto ok;
            } else if((val & 0x0f000000) == 0x0b000000) {
                // BLX
                diff = ((val & 0x1000000) >> 23) | ((val & 0xffffff) << 2) | 1;
                goto ok;
            }
        }
    }
    return 0;
    ok:;
    addr_t baseaddr = ((char *) base) - ((char *) pr.start) + range->start + 4;
    printf("%08x\n", baseaddr);
    range->start = baseaddr + thumb;
    if(diff & 0x800000) diff |= 0xff000000;
    return baseaddr + diff;
}

addr_t b_find_anywhere(struct binary *binary, char *to_find, int align, bool must_find) {
    range_t range;
    for(int i = 0; (range = b_nth_segment(binary, i)).binary; i++) {
        addr_t result = find_data(range, to_find, align, false);
        if(result) return result;
    }
    if(must_find) {
        die("didn't find [%s] anywhere", to_find);
    } else {
        return 0;
    }
}
