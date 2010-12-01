#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include "common.h"
#include "binary.h"
#include "find.h"
#include "cc.h"
#include "running_kernel.h"
#include "loader.h"
#include "link.h"

static struct binary kern;

int main(int argc, char **argv) {
    b_init(&kern);
    argv++;
    while(1) {
        char *arg = *argv++;
        if(!arg) goto usage;
        if(arg[0] != '-' || arg[1] == '\0' || arg[2] != '\0') goto usage;
        switch(arg[1]) {
        case 'k': {
            char *kern_fn;
            if(!(kern_fn = *argv++)) goto usage;
            b_load_macho(&kern, kern_fn, true);
            break;
        }
#ifdef IMG3_SUPPORT
        case 'i': {
            uint32_t key_bits;
            prange_t data = parse_img3_file(*argv++, &key_bits);
            prange_t key = parse_hex_string(*argv++);
            prange_t iv = parse_hex_string(*argv++);
            prange_t decompressed = decrypt_and_decompress(key_bits, key, iv, data);
            b_prange_load_macho(&kern, decompressed, false);
            break;
        }
#endif
#ifdef __APPLE__
        case 'l': {
            if(!kern.valid) goto usage;
            if(!*argv) goto usage;
            char *to_load_fn;
            while(to_load_fn = *argv++) {
                struct binary to_load;
                b_init(&to_load);
                b_load_macho(&to_load, to_load_fn, true);
                uint32_t slide = b_allocate_from_running_kernel(&to_load);
                if(!(to_load.mach_hdr->flags & MH_PREBOUND)) {
                    b_relocate(&to_load, slide);
                }
                b_inject_into_running_kernel(&to_load, b_find_sysent(&kern));
            }
            return 0;
        }
#endif
        case 'p': {
            if(!kern.valid) goto usage;
            if(!*argv) goto usage;
            char *to_load_fn, *output_fn;
            uint32_t slide = 0xf0000000;
            while(to_load_fn = *argv++) {
                if(!(output_fn = *argv++)) goto usage;
                struct binary to_load;
                b_init(&to_load);
                b_load_macho(&to_load, to_load_fn, true);
                if(!(to_load.mach_hdr->flags & MH_PREBOUND)) {
                    b_relocate(&to_load, slide);
                    slide += 0x10000;
                }
                to_load.mach_hdr->flags |= MH_PREBOUND;
                b_macho_store(&to_load, output_fn);
            }
            return 0;
        }
        case 'q': {
            return 0;
        }
        case 'u': {
            char *baseaddr_hex;
            if(!(baseaddr_hex = *argv++)) goto usage;
            unload_from_running_kernel(parse_hex_uint32(baseaddr_hex));
            return 0;
        }
        }
    }

    usage:
    printf("Usage: loader -k kern "
#ifdef __APPLE__
                                 "-l kcode.dylib                load\n"
#endif
           "                      -p kcode.dylib out.dylib      prelink\n"
           "                      -q kcode.dylib out_kern       insert into kc\n"
           "              -u f0000000                           unload\n"
           );
}

