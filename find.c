#include "find.h"
#include "binary.h"

static addr_t find_data_int(range_t range, int16_t *buf, ssize_t pattern_size, size_t offset, int align, bool must_find, const char *name) {
    int8_t table[256];
    for(int c = 0; c < 256; c++) {
        table[c] = pattern_size;
    }
    for(int pos = 0; pos < pattern_size - 1; pos++) {
        if(buf[pos] == -1) {
            // Unfortunately, we can't put any character past being in this position...
            for(int i = 0; i < 256; i++) {
                table[i] = pattern_size - pos - 1;
            }
        } else {
            table[buf[pos]] = pattern_size - pos - 1;
        }
    }
    // now, for each c, let x be the last position in the string, other than the final position, where c might appear, or -1 if it doesn't appear anywhere; table[i] is size - x - 1.
    // so if we got c but no match, we can skip ahead by table[i]
    // i.e. lame Boyer–Moore
    // I implemented the other half, but it actually made things /slower/
    buf += pattern_size - 1;
    addr_t foundit = 0;
    prange_t pr = rangeconv(range);
    uint8_t *start = pr.start + pattern_size - 1, *cursor = start;
    uint8_t *end = pr.start + pr.size;
    while(cursor < end) {
        for(int i = 0; i >= (-pattern_size + 1); i--) {
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
            die("Found [%s] multiple times in range: first at %08x then at %08x", name, foundit, new);
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
        die("Didn't find [%s] in range (%x, %zx)", name, range.start, range.size);
    } else {
        return 0;
    }
}

addr_t find_data(range_t range, char *to_find, int align, bool must_find) {
#ifdef PROFILING
    clock_t a = clock();
#endif
    int16_t buf[128];
    size_t pattern_size = 0;
    size_t offset = -1;
    char *to_find_ = strdup(to_find);
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
    free(to_find_);
    if(offset == -1) {
        die("pattern [%s] doesn't have an offset", to_find);
    }
    addr_t result = find_data_int(range, buf, pattern_size, offset, align, must_find, to_find);
#ifdef PROFILING
    clock_t b = clock();
    printf("find_data [%s] took %d/%d\n", to_find, (int)(b - a), (int)CLOCKS_PER_SEC);
#endif
    return result;
}

addr_t find_string(range_t range, const char *string, int align, bool must_find) {
    size_t len = strlen(string);
    int16_t *buf = malloc(sizeof(int16_t) * (len + 2));
    buf[0] = buf[len + 1] = 0;
    for(int i = 0; i < len; i++) {
        buf[i+1] = (uint8_t) string[i];
    }
    addr_t result = find_data_int(range, buf, len, 1, align, must_find, string);
    free(buf);
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
        die("Didn't find %08x in range", number);
    } else {
        return 0;
    }
}

uintptr_t preplace32_a(prange_t range, uint32_t a) {
    for(uintptr_t addr = (uintptr_t)range.start; addr + sizeof(uint32_t) <= (uintptr_t)range.start + range.size; addr++) {
        if(*(uint32_t *)addr == a) {
            return addr;
        }
    }
    fprintf(stderr, "preplace32: warning: didn't find %08x anywhere\n", a);
    return 0;
}

void preplace32_b(prange_t range, uintptr_t start, uint32_t a, uint32_t b) {
    for(uintptr_t addr = start; addr + sizeof(uint32_t) <= (uintptr_t)range.start + range.size; addr++) {
        if(*(uint32_t *)addr == a) {
            *(uint32_t *)addr = b;
        }
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
    uint32_t val = read32(binary, addr & ~1); 
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
    return read32(binary, target);
}

addr_t b_dyldcache_find_anywhere(struct binary *binary, char *to_find, int align) {
    range_t range;
    for(int i = 0; (range = b_dyldcache_nth_segment(binary, i)).start; i++) {
        addr_t result = find_data(range, to_find, align, false);
        if(result) return result;
    }
    die("Didn't find [%s] /anywhere/", to_find);
}

