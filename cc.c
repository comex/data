#ifndef IMG3_SUPPORT
#error cc.c and lzss.c are for IMG3_SUPPORT builds
#endif
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/mman.h>
#include <unistd.h>
#include <CommonCrypto/CommonCryptor.h>
#include "common.h"
#include "lzss.h"

struct comp_header {
    uint32_t signature;
    uint32_t compression_type;
    uint32_t checksum;
    uint32_t length_uncompressed;
    uint32_t length_compressed;
    uint8_t  padding[0x16C];
} __attribute__((packed));

prange_t decrypt_and_decompress(uint32_t key_bits, prange_t key, prange_t iv, prange_t buffer) {
#ifdef PROFILING
    clock_t tv1 = clock();
#endif

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
    void *outbuf = malloc(outbuf_len);
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
    
#ifdef PROFILING
    clock_t tv2 = clock();
#endif
    if(result != kCCSuccess) {
        die("decryption failed: %d", (unsigned int) result);
    }
    if(outbuf_len < sizeof(struct comp_header)) {
        die("too small decrypted result");
    }
    struct comp_header *ch = outbuf;
    if(!(ch->signature == 0x706d6f63 && ch->compression_type == 0x73737a6c)) {
        die("nonsense decrypted result is not complzss (%x %x)", ch->signature, ch->compression_type);
    }
    uint32_t length_compressed = ntohl(ch->length_compressed);
    uint32_t length_uncompressed = ntohl(ch->length_uncompressed);
    uint32_t checksum = ntohl(ch->checksum);
    if((outbuf_len - sizeof(struct comp_header)) < length_compressed) {
        die("too big length_compressed %x > %lx", length_compressed, outbuf_len - sizeof(struct comp_header));
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

#if 0
    uint32_t actual_checksum = lzadler32(decbuf, actual_length_uncompressed);
    if(actual_checksum != checksum) {
        die("bad checksum (%x, %x)", actual_checksum, checksum);
    }
#endif

    free(outbuf);
#ifdef PROFILING
    clock_t tv3 = clock();
    printf("decrypt:%u decompress:%u\n", (unsigned int) (tv2 - tv1), (unsigned int) (tv3 - tv2));
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

prange_t parse_img3(prange_t img3, uint32_t *key_bits) {
    assert(img3.size >= sizeof(struct img3_header));
    struct img3_header *hdr = img3.start;
    assert(hdr->magic == (uint32_t) 'Img3');
    assert(hdr->size <= img3.size);
    void *end = (char *)(img3.start) + hdr->size;
    assert(hdr->name == (uint32_t) 'krnl');
    struct img3_tag *tag = (void *) (hdr + 1);
    struct img3_tag *tag2;
    prange_t result;
    memset(&result, 0, sizeof(result)); // not actually necessary, >:( gcc
    bool have_data = false, have_kbag = false;
    while(!(have_data && have_kbag)) {
        if((void *)tag->data >= end) {
            // out of tags
            die("didn't find DATA and KBAG");
        }
        printf("%.4s %p %x\n", (char *) &tag->magic, &tag->data[0], tag->data_size);
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
                *key_bits = tag->kbag.key_bits;
                have_kbag = true;
            }
        }
        tag = tag2;
    }
    return result;
}

prange_t parse_img3_file(char *filename, uint32_t *key_bits) {
    return parse_img3(load_file(filename, false, NULL), key_bits);
}
