#include "common.h"
#include "find.h"
#include "binary.h"
#include "cc.h"
#include "../config/config_asm.h"

__attribute__((const))
static bool b_is_armv7(struct binary *binary) {
    bool result;
    switch(binary->actual_cpusubtype) {
    case 6:
        result = false;
        break;
    case 9:
        result = true;
        break;
    default:
        die("unknown cpusubtype %d", binary->actual_cpusubtype);
    }
    return result;
}

// case-specific stuff

// count the number of set bits
static int count_ones(uint32_t number) {
    int result = 0;
    for(; number; number >>= 1) {
        result += (number & 1);
    }
    return result;
}

// ldmib<cond> r11/r11!, {.., .., .., sp, pc}
addr_t find_kinit(struct binary *binary, uint32_t cond) {
    range_t range;
    for(int i = 0; (range = b_dyldcache_nth_segment(binary, i)).start; i++) {
        uint32_t *p = rangeconv(range).start;
        for(addr_t addr = range.start; addr + 4 <= (range.start + range.size); addr += 4) {
            // <3 http://a.qoid.us/01x.py
            // fun fact: on armv6 this is actually UNPREDICTABLE
            uint32_t val = *p++;
            if((val & 0xf9fe000) != 0x99ba000) continue;
            uint32_t actual_cond = ((val & 0xf0000000) >> 28);
            if(actual_cond != cond) continue;
            uint32_t reglist = val & 0x1fff;
            // The famous interview question: calculate the number of 1 bits
            if(count_ones(reglist) != 3) continue;
            return addr; 
        }
    }
    die("didn't find kinit /anywhere/"); 
}

uint32_t find_dvp_struct_offset(struct binary *binary) {
    range_t range = b_macho_segrange(binary, "__PRELINK_TEXT");
    addr_t derive_vnode_path = find_bof(range, find_int32(range, find_string(range, "path", 0, true), true), b_is_armv7(binary));
    uint8_t byte = read8(binary, find_data((range_t){binary, derive_vnode_path, 1024}, !b_is_armv7(binary) ? "00 00 50 e3 02 30 a0 11 - .. 00 94 e5" : "- .. 69 6a 46", 0, true));
    if(b_is_armv7(binary)) {
        return (4 | (byte >> 6)) << 2;
    } else {
        return byte;
    }
}

void check_no_placeholders(prange_t pr) {
#ifndef __arm__
    for(uintptr_t addr = (uintptr_t)pr.start; addr + sizeof(uint32_t) <= (uintptr_t)pr.start + pr.size; addr++) {
        uint32_t val = *(uint32_t *)addr;
        if(val > CONFIG_MIN && val < CONFIG_MAX) {
            die("got %08x", val);
        }
    }
#endif
}

void do_dyldcache(prange_t pr, struct binary *binary) {
    bool is_armv7 = b_is_armv7(binary);
    preplace32(pr, CONFIG_IS_ARMV7, (uint32_t) is_armv7);
    // hexydec
    int align = is_armv7 ? 2 : 4;
    preplace32(pr, CONFIG_K4, b_dyldcache_find_anywhere(binary, is_armv7 ? "+ 00 68 b0 bd" : "- 00 00 90 e5 b0 80 bd e8", align));
    preplace32(pr, CONFIG_K5, b_dyldcache_find_anywhere(binary, is_armv7 ? "+ 20 60 90 bd" : "- 00 00 84 e5 90 80 bd e8", align));
    preplace32(pr, CONFIG_K6, b_dyldcache_find_anywhere(binary, is_armv7 ? "+ 20 44 90 bd" : "- 00 00 84 e0 90 80 bd e8", align));
    preplace32(pr, CONFIG_K7, b_dyldcache_find_anywhere(binary, is_armv7 ? "+ 0f bd" : "- 0f 80 bd e8", align));
    preplace32(pr, CONFIG_K9, b_dyldcache_find_anywhere(binary, "+ 0e bd", 2));
    preplace32(pr, CONFIG_K10, b_dyldcache_find_anywhere(binary, is_armv7 ? "+ a7 f1 00 0d 80 bd" : "- 00 d0 47 e2 80 80 bd e8", align));
    preplace32(pr, CONFIG_K11, b_dyldcache_find_anywhere(binary, "+ f0 bd", 2));
    preplace32(pr, CONFIG_K12, b_dyldcache_find_anywhere(binary, is_armv7 ? "+ a0 47 b0 bd" : "- 34 ff 2f e1 b0 80 bd e8", align));
    preplace32(pr, CONFIG_K14, b_dyldcache_find_anywhere(binary, "+ 20 58 90 bd", 2));
    preplace32(pr, CONFIG_K15, b_dyldcache_find_anywhere(binary, is_armv7 ? "+ 40 f8 04 4b 90 bd" : "- 00 40 80 e5 90 80 bd e8", align));
    preplace32(pr, CONFIG_K16, b_dyldcache_find_anywhere(binary, is_armv7 ? "+ 20 68 90 bd" : "- 00 00 94 e5 90 80 bd e8", align));
    preplace32(pr, CONFIG_K17, b_dyldcache_find_anywhere(binary, is_armv7 ? "+ 25 60 b0 bd" : "- 00 50 84 e5 b0 80 bd e8", align));
    preplace32(pr, CONFIG_K18, b_dyldcache_find_anywhere(binary, "+ 10 bd", 2));
    preplace32(pr, CONFIG_K19, b_dyldcache_find_anywhere(binary, "+ 80 bd", 2));
    preplace32(pr, CONFIG_KINIT, find_kinit(binary, is_armv7 ? 4 /* MI */ : 5 /* PL */));
    //b_dyldcache_load_macho(binary, "/usr/lib/libSystem.B.dylib");
    //preplace32(pr, 0xfeed1001, b_sym(binary, "_sysctlbyname", true));
    //preplace32(pr, 0xfeed1002, b_sym(binary, "_execve", true));
}

void do_kernel(prange_t pr, struct binary *binary) {
    bool is_armv7 = b_is_armv7(binary);
    preplace32(pr, CONFIG_IS_ARMV7, (uint32_t) is_armv7);
    
    preplace32(pr, CONFIG_VN_GETPATH, b_sym(binary, "_vn_getpath", true));
    preplace32(pr, CONFIG_MEMCMP, b_sym(binary, "_memcmp", true));
    preplace32(pr, CONFIG_KALLOC, b_sym(binary, "_kalloc", true));
    preplace32(pr, CONFIG_FLUSH_DCACHE, b_sym(binary, "_flush_dcache", true));
    preplace32(pr, CONFIG_INVALIDATE_ICACHE, b_sym(binary, "_invalidate_icache", true));
    preplace32(pr, CONFIG_IOLOG, b_sym(binary, "_IOLog", true));
    preplace32(pr, CONFIG_COPYIN, b_sym(binary, "_copyin", true));

    // sandbox
    range_t range = b_macho_segrange(binary, "__PRELINK_TEXT");
    addr_t sb_evaluate = find_bof(range, find_int32(range, find_string(range, "bad opcode", false, true), true), is_armv7);
    preplace32(pr, CONFIG_SB_EVALUATE, sb_evaluate);
    preplace32(pr, CONFIG_SB_EVALUATE_ORIG1, read32(binary, sb_evaluate));
    preplace32(pr, CONFIG_SB_EVALUATE_ORIG2, read32(binary, sb_evaluate + 4));
    preplace32(pr, CONFIG_SB_EVALUATE_JUMPTO, sb_evaluate + (is_armv7 ? 9 : 8));
    preplace32(pr, CONFIG_DVP_STRUCT_OFFSET, find_dvp_struct_offset(binary));
    
    // patches
    preplace32(pr, CONFIG_PATCH_KERNEL_PMAP_NX_ENABLED, read32(binary, b_sym(binary, "_kernel_pmap", false)) + 0x420);
    addr_t sysent = find_data(b_macho_segrange(binary, "__DATA"), "21 00 00 00 00 10 86 00 -", 0, true);

    // vm_map_enter (patch1) - allow RWX pages
    preplace32(pr, CONFIG_PATCH1, find_data(b_macho_segrange(binary, "__TEXT"), is_armv7 ? "- 02 0f .. .. 63 08 03 f0 01 05 e3 0a 13 f0 01 03" : "- .. .. .. .. 6b 08 1e 1c eb 0a 01 22 1c 1c 16 40 14 40", 0, true));
    preplace32(pr, CONFIG_PATCH1_TO, is_armv7 ? 0x46c00f02 : 0x46c046c0);

    // AMFI (patch3) - disable the predefined list of executable stuff
    preplace32(pr, CONFIG_PATCH3, find_data(b_macho_segrange(binary, "__PRELINK_TEXT"), is_armv7 ? "23 78 9c 45 05 d1 .. .. .. .. .. .. .. 4b 98 47 00 .. -" : "13 20 a0 e3 .. .. .. .. 33 ff 2f e1 00 00 50 e3 00 00 00 0a .. 40 a0 e3 - 04 00 a0 e1 90 80 bd e8", 0, true));
    preplace32(pr, CONFIG_PATCH3_TO, is_armv7 ? 0x1c201c20 : 0xe3a00001);
    // PE_i_can_has_debugger (patch4) - so AMFI allows non-ldid'd binaries (and some other stuff is allowed)
    preplace32(pr, CONFIG_PATCH4, b_sym(binary, "_PE_i_can_has_debugger", false));

    // task_for_pid 0
    preplace32(pr, CONFIG_PATCH_TFP0, find_data(b_macho_segrange(binary, "__TEXT"), is_armv7 ? "85 68 00 23 .. 93 .. 93 - 5c b9 .. .. 29 46 04 22" : "85 68 .. 93 .. 93 - 00 2c 0b d1", 0, true));
    // this is necessary so a reboot isn't required after using the screwed up version
    preplace32(pr, CONFIG_PATCH_TFP0_TO, is_armv7 ? 0x46c0e00b : 0xe00b2c00);
        
    // cs_enforcement_disable
    preplace32(pr, CONFIG_PATCH_CS_ENFORCEMENT_DISABLE, resolve_ldr(binary, find_data(b_macho_segrange(binary, "__TEXT"), is_armv7 ? "1d ee 90 3f d3 f8 4c 33 d3 f8 9c 20 + .. .. .. .. 19 68 00 29" : "9c 22 03 59 99 58 + .. .. 1a 68 00 2a", 0, true)));
    
    // pf
    preplace32(pr, CONFIG_SYSENT_PATCH, sysent + 4);
    addr_t sysent_patch_orig = read32(binary, sysent + 4);
    preplace32(pr, CONFIG_SYSENT_PATCH_ORIG, sysent_patch_orig);
    preplace32(pr, CONFIG_TARGET_ADDR, (sysent_patch_orig & 0x00ffffff) | 0x2f000000);

}

void do_dyld(prange_t pr, struct binary *binary) {
    (void) pr; (void) binary;
}

int main(int argc, char **argv) {
    struct binary kernel, dyld, cache;
    b_init(&kernel);
    b_init(&dyld);
    b_init(&cache);
    char **p = &argv[1];
    if(!p[0]) goto usage;
    while(p[0]) {
        if(p[0][0] == '-') switch(p[0][1]) {
        case 'C':
            b_load_running_dyldcache(&cache, (void *) 0x30000000);
            p++;
            break;
        case 'c':
            if(!p[1]) goto usage;
            b_load_dyldcache(&cache, p[1]);
            p += 2;
            break;
        case 'k': {
            if(!p[1]) goto usage;
            b_load_macho(&kernel, p[1], false);
            p += 2;
            break;
        }
        case 'K': {
            b_running_kernel_load_macho(&kernel);  
            p++;
            break;
        }
#ifdef IMG3_SUPPORT
        case 'i': {
            if(!p[1] || !p[2] || !p[3]) goto usage;
            uint32_t key_bits;
            prange_t key = parse_hex_string(p[2]);
            prange_t iv = parse_hex_string(p[3]);
            prange_t data = parse_img3_file(p[1], &key_bits);
            prange_t kern = decrypt_and_decompress(key_bits, key, iv, data);
            b_prange_load_macho(&kernel, kern, false);
            p += 4;
            break;
        }
#endif
        default:
            goto usage;
        }
        else { // not a -
            if(!p[1]) goto usage;
            mode_t mode;
            prange_t pr = load_file(p[0], true, &mode);
            if(cache.valid) do_dyldcache(pr, &cache);
            if(kernel.valid) do_kernel(pr, &kernel);
            if(dyld.valid) do_dyld(pr, &dyld);
            check_no_placeholders(pr);
            write_file(pr, p[1], mode);
            punmap(pr);
            p += 2;
        }
    }
    return 0;

    usage:
    fprintf(stderr, "Usage: data [-c cache | -C] [k kernel | -K"
#ifdef IMG3_SUPPORT
    " | -i kernel_img3 key iv"
#endif
    "] infile outfile [infile outfile...]\n");
    return 1;
}
