#pragma once

//#define PROFILING

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <unistd.h>
#ifdef PROFILING
#include <time.h>
#endif

static const char *_arg = NULL;
#define die(fmt, args...) do { \
    fprintf(stderr, "%s: ", __func__); \
    if(_arg) fprintf(stderr, "%s: ", _arg); \
    fprintf(stderr, fmt "\n", ##args); \
    exit(1); \
} while(0)
#define edie(fmt, args...) die(fmt ": %s", ##args, strerror(errno))

struct binary;
typedef uint32_t addr_t;
typedef struct { const struct binary *binary; addr_t start; size_t size; } range_t;
typedef struct { void *start; size_t size; } prange_t;

void check_range_has_addr(range_t range, addr_t addr);

prange_t pdup(prange_t range);
void pfree(prange_t range);
void punmap(prange_t range);

static inline bool is_valid_range(prange_t range) {
    char c;
    return !mincore(range.start, range.size, &c);
}

prange_t parse_hex_string(const char *string);

prange_t load_file(const char *filename, bool rw, mode_t *mode);
void write_file(prange_t range, const char *filename, mode_t mode);

uint32_t parse_hex_uint32(char *string);
