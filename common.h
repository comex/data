#pragma once
#define _XOPEN_SOURCE 500
#define _BSD_SOURCE
#define _DARWIN_C_SOURCE

//#define PROFILING

#define swap32 __builtin_bswap32
#define SWAP32(x) ((typeof(x)) swap32((uint32_t) (x)))

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/cdefs.h>
#ifdef PROFILING
#include <time.h>
#endif

static inline void _free_cleanup(void *pp) {
    void *p = *((void **) pp);
    if(p) free(p);
}
#define autofree __attribute__((cleanup(_free_cleanup)))

__unused static const char *const _arg = (char *) MAP_FAILED;

#define die(fmt, args...) ((_arg == MAP_FAILED) ? \
    _die("%s: " fmt "\n", __func__, ##args) : \
    _die("%s: %s: " fmt "\n", __func__, _arg, ##args))

#define edie(fmt, args...) die(fmt ": %s", ##args, strerror(errno))

struct binary;
typedef uint32_t addr_t;
typedef struct { const struct binary *binary; addr_t start; size_t size; } range_t;
typedef struct { void *start; size_t size; } prange_t;

__BEGIN_DECLS

void check_range_has_addr(range_t range, addr_t addr);

prange_t pdup(prange_t range);
void pfree(prange_t range);
void punmap(prange_t range);

bool is_valid_range(prange_t range);

prange_t parse_hex_string(const char *string);

prange_t load_file(const char *filename, bool rw, mode_t *mode);
prange_t load_fd(int fd, bool rw);

void store_file(prange_t range, const char *filename, mode_t mode);

uint32_t parse_hex_uint32(const char *string);

__attribute__((noreturn)) void _die(const char *fmt, ...);

#if !defined(__APPLE__) || __DARWIN_C_LEVEL < 200809L
static inline size_t strnlen(const char *s, size_t n) {
  const char *p = (const char *) memchr(s, 0, n);
  return p ? (size_t) (p-s) : n;
}
#endif

__END_DECLS
