#ifdef IMG3_SUPPORT
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/mman.h>
#include <unistd.h>
#include <CommonCrypto/CommonCryptor.h>
#include <mach-o/fat.h>
#include "common.h"
#include "lzss.h"

// this is sort of irrelevant, but I'd like to use it for OS X kernelcaches which are sometimes compressed within fat

#ifndef __arm__ // copy and paste from libstuff
static const struct arch_flag {
    const char *name;
    cpu_type_t type;
    cpu_subtype_t subtype;
} arch_flags[] = {
    { "any",	CPU_TYPE_ANY,	  CPU_SUBTYPE_MULTIPLE },
    { "little",	CPU_TYPE_ANY,	  CPU_SUBTYPE_LITTLE_ENDIAN },
    { "big",	CPU_TYPE_ANY,	  CPU_SUBTYPE_BIG_ENDIAN },

/* 64-bit Mach-O architectures */

    /* architecture families */
    { "ppc64",     CPU_TYPE_POWERPC64, CPU_SUBTYPE_POWERPC_ALL },
    { "x86_64",    CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL },
    /* specific architecture implementations */
    { "ppc970-64", CPU_TYPE_POWERPC64, CPU_SUBTYPE_POWERPC_970 },

/* 32-bit Mach-O architectures */

    /* architecture families */
    { "ppc",    CPU_TYPE_POWERPC, CPU_SUBTYPE_POWERPC_ALL },
    { "i386",   CPU_TYPE_I386,    CPU_SUBTYPE_I386_ALL },
    { "m68k",   CPU_TYPE_MC680x0, CPU_SUBTYPE_MC680x0_ALL },
    { "hppa",   CPU_TYPE_HPPA,    CPU_SUBTYPE_HPPA_ALL },
    { "sparc",	CPU_TYPE_SPARC,   CPU_SUBTYPE_SPARC_ALL },
    { "m88k",   CPU_TYPE_MC88000, CPU_SUBTYPE_MC88000_ALL },
    { "i860",   CPU_TYPE_I860,    CPU_SUBTYPE_I860_ALL },
    { "arm",    CPU_TYPE_ARM,     CPU_SUBTYPE_ARM_ALL },
    /* specific architecture implementations */
    { "ppc601", CPU_TYPE_POWERPC, CPU_SUBTYPE_POWERPC_601 },
    { "ppc603", CPU_TYPE_POWERPC, CPU_SUBTYPE_POWERPC_603 },
    { "ppc603e",CPU_TYPE_POWERPC, CPU_SUBTYPE_POWERPC_603e },
    { "ppc603ev",CPU_TYPE_POWERPC,CPU_SUBTYPE_POWERPC_603ev },
    { "ppc604", CPU_TYPE_POWERPC, CPU_SUBTYPE_POWERPC_604 },
    { "ppc604e",CPU_TYPE_POWERPC, CPU_SUBTYPE_POWERPC_604e },
    { "ppc750", CPU_TYPE_POWERPC, CPU_SUBTYPE_POWERPC_750 },
    { "ppc7400",CPU_TYPE_POWERPC, CPU_SUBTYPE_POWERPC_7400 },
    { "ppc7450",CPU_TYPE_POWERPC, CPU_SUBTYPE_POWERPC_7450 },
    { "ppc970", CPU_TYPE_POWERPC, CPU_SUBTYPE_POWERPC_970 },
    { "i486",   CPU_TYPE_I386,    CPU_SUBTYPE_486 },
    { "i486SX", CPU_TYPE_I386,    CPU_SUBTYPE_486SX },
    { "pentium",CPU_TYPE_I386,    CPU_SUBTYPE_PENT }, /* same as i586 */
    { "i586",   CPU_TYPE_I386,    CPU_SUBTYPE_586 },
    { "pentpro", CPU_TYPE_I386, CPU_SUBTYPE_PENTPRO }, /* same as i686 */
    { "i686",   CPU_TYPE_I386, CPU_SUBTYPE_PENTPRO },
    { "pentIIm3",CPU_TYPE_I386, CPU_SUBTYPE_PENTII_M3 },
    { "pentIIm5",CPU_TYPE_I386, CPU_SUBTYPE_PENTII_M5 },
    { "pentium4",CPU_TYPE_I386, CPU_SUBTYPE_PENTIUM_4 },
    { "m68030", CPU_TYPE_MC680x0, CPU_SUBTYPE_MC68030_ONLY },
    { "m68040", CPU_TYPE_MC680x0, CPU_SUBTYPE_MC68040 },
    { "hppa7100LC", CPU_TYPE_HPPA,  CPU_SUBTYPE_HPPA_7100LC },
    { "armv4t", CPU_TYPE_ARM,     CPU_SUBTYPE_ARM_V4T},
    { "armv5",  CPU_TYPE_ARM,     CPU_SUBTYPE_ARM_V5TEJ},
    { "xscale", CPU_TYPE_ARM,     CPU_SUBTYPE_ARM_XSCALE},
    { "armv6",  CPU_TYPE_ARM,     CPU_SUBTYPE_ARM_V6 },
    { "armv7",  CPU_TYPE_ARM,     CPU_SUBTYPE_ARM_V7 },
    { NULL,	0,		  0 }
};
#endif

static prange_t parse_fat(prange_t input, const char *arch) {
#ifdef __arm__
    return input;
#else
    if(input.size < sizeof(struct fat_header)) return input;
    struct fat_header *fh = input.start;
    if(SWAP32(fh->magic) != FAT_MAGIC) return input;
    if(!arch) die("arch not specified for fat file");

    cpu_type_t type;
    cpu_subtype_t subtype;
    for(const struct arch_flag *p = arch_flags; p < (struct arch_flag *) (&arch_flags + 1); p++) {
        if(!strcmp(arch, p->name)) {
            type = p->type;
            subtype = p->subtype;
            goto ok;
        }
    }
    die("unknown arch %s", arch);

    ok:;
    struct fat_arch *fa = (void *) (fh + 1);
    uint32_t nfat_arch = SWAP32(fh->nfat_arch);
    if((input.size - sizeof(struct fat_header)) / sizeof(struct fat_arch) < nfat_arch) die("nfat_arch overflow");
    for(uint32_t i = 0; i < nfat_arch; i++) {
        cpu_type_t mytype = SWAP32(fa[i].cputype);
        cpu_subtype_t mysubtype = SWAP32(fa[i].cpusubtype);
        uint32_t offset = SWAP32(fa[i].offset);
        uint32_t size = SWAP32(fa[i].size);
        if(type == mytype && subtype == mysubtype) {
            if(offset > input.size || size > input.size - offset) die("fat overflow");
            return (prange_t) {input.start + offset, size};
        }
    }
    die("arch %s not present in fat file", arch);
#endif
}

static prange_t decrypt(uint32_t key_bits, prange_t key, prange_t iv, prange_t buffer) {
    size_t size;
    switch(key_bits) {
        case 128: size = kCCKeySizeAES128; break;
        case 192: size = kCCKeySizeAES192; break;
        case 256: size = kCCKeySizeAES256; break;
        default: abort();
    }
    if(key.size != size) {
        die("bad key_len %zu", key.size);
    }
    if(iv.size != 16) {
        die("bad iv_len %zu", iv.size);
    }
    size_t outbuf_len = buffer.size + 32;
    autofree void *outbuf = malloc(outbuf_len);
    assert(outbuf);
    CCCryptorStatus result = CCCrypt(kCCDecrypt,
                                     kCCAlgorithmAES128,
                                     0,
                                     key.start,
                                     size,
                                     iv.start, 
                                     buffer.start,
                                     buffer.size & ~0xf,
                                     outbuf,
                                     outbuf_len,
                                     &outbuf_len);
    
    if(result != kCCSuccess) {
        die("decryption failed: %d", (unsigned int) result);
    }
    return (prange_t) {outbuf, outbuf_len};
}

struct comp_header {
    uint32_t signature;
    uint32_t compression_type;
    uint32_t checksum;
    uint32_t length_uncompressed;
    uint32_t length_compressed;
    uint8_t  padding[0x16C];
} __attribute__((packed));

static prange_t decompress(prange_t buffer) {
    // is it really compressed?
    if(buffer.size < sizeof(struct comp_header)) return buffer;
    struct comp_header *ch = buffer.start;
    if(!(ch->signature == 0x706d6f63 && ch->compression_type == 0x73737a6c)) {
        return buffer;
    }

    uint32_t length_compressed = swap32(ch->length_compressed);
    uint32_t length_uncompressed = swap32(ch->length_uncompressed);
    uint32_t checksum = swap32(ch->checksum);
    if((buffer.size - sizeof(struct comp_header)) < length_compressed) {
        die("too large length_compressed %x > %lx", length_compressed, buffer.size - sizeof(struct comp_header));
    }
    // not a fan of buffer overflows
    size_t decbuf_len = (length_uncompressed + 0x1fff) & ~0xfff;
    void *decbuf = mmap(NULL, decbuf_len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
    assert(decbuf != MAP_FAILED);
    assert(!mprotect((char *)decbuf + decbuf_len - 0x1000, PROT_NONE, 0x1000));

    int actual_length_uncompressed = decompress_lzss(decbuf, (void *) (ch + 1), length_compressed);
    if(actual_length_uncompressed < 0 || (unsigned int) actual_length_uncompressed != length_uncompressed) {
        die("invalid complzss thing");
    }

#ifndef __arm__
    uint32_t actual_checksum = lzadler32(decbuf, actual_length_uncompressed);
    if(actual_checksum != checksum) {
        die("bad checksum (%x, %x)", actual_checksum, checksum);
    }
#else
    (void) checksum;
#endif
    return (prange_t) {decbuf, actual_length_uncompressed};
}

struct img3_header {
    uint32_t magic;
    uint32_t size;
    uint32_t data_size;
    uint32_t shsh_offset;
    uint32_t name;
} __attribute__((packed));

struct img3_tag {
    uint32_t magic;
    uint32_t size;
    uint32_t data_size;
    char data[0];
    union {
        struct {
            uint32_t key_modifier;
            uint32_t key_bits;
        } __attribute__((packed)) kbag;
    };
} __attribute__((packed));

static prange_t parse_img3(prange_t img3, const char *key, const char *iv) {
    if(img3.size < sizeof(struct img3_header)) return img3;
    struct img3_header *hdr = img3.start;
    if(hdr->magic != (uint32_t) 'Img3') return img3;

    assert(hdr->size <= img3.size);
    void *end = (char *)(img3.start) + hdr->size;
    //assert(hdr->name == (uint32_t) 'krnl');
    struct img3_tag *tag = (void *) (hdr + 1);
    struct img3_tag *tag2;
    prange_t result;
    memset(&result, 0, sizeof(result)); // not actually necessary, >:( gcc
    bool have_data = false, have_kbag = false;
    uint32_t key_bits;
    while(!(have_data && have_kbag)) {
        if((void *)tag->data >= end) {
            // out of tags
            break;
        }
        //printf("%.4s %p %x\n", (char *) &tag->magic, &tag->data[0], tag->data_size);
        tag2 = (void *) ((char *)tag + tag->size);
        if((void *)tag2 > end || tag2 <= tag) {
            die("tag cut off");
        }
        if(tag->magic == (uint32_t) 'DATA') {
            result = (prange_t) {tag->data, tag->size - 3 * sizeof(uint32_t)};
            have_data = true;
        } else if(tag->magic == (uint32_t) 'KBAG') {
            assert(tag->size >= 5 * sizeof(uint32_t));
            if(tag->kbag.key_modifier) {
                key_bits = tag->kbag.key_bits;
                have_kbag = true;
            }
        }
        tag = tag2;
    }

    if(!have_data) {
        die("didn't find DATA");
    }

    if(have_kbag) {
        if(!key || !iv) die("key/iv not specified for encrypted img3");
        return decrypt(key_bits, parse_hex_string(key), parse_hex_string(iv), result);
    } else {
        // unencrypted like iOS 4.3.1
        return result;
    }
}

prange_t unpack(prange_t input, const char *key, const char *iv) {
    input = parse_img3(input, key, iv); 
    input = parse_fat(input, key);
    input = decompress(input);
    return input;
}
#endif
