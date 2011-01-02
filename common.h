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

typedef void (* __attribute__((noreturn)) death_func_t )(const char *message);
void set_death_func(death_func_t new_func);
__attribute__((noreturn)) void xdie(const char *fmt, ...);

__attribute__((unused)) static const char *_arg = MAP_FAILED;
#define die(fmt, args...) ((_arg) == MAP_FAILED ? xdie("%s: " fmt "\n", __func__, ##args) : xdie("%s: %s: " fmt "\n", __func__, _arg, ##args))
#define edie(fmt, args...) die(fmt ": %s", ##args, strerror(errno))

struct binary;
typedef uint32_t addr_t;
typedef struct { const struct binary *binary; addr_t start; size_t size; } range_t;
typedef struct { void *start; size_t size; } prange_t;

void check_range_has_addr(range_t range, addr_t addr);

prange_t pdup(prange_t range);
void pfree(prange_t range);
void punmap(prange_t range);

bool is_valid_range(prange_t range);

prange_t parse_hex_string(const char *string);

prange_t load_file(const char *filename, bool rw, mode_t *mode);
prange_t load_fd(int fd, bool rw);

void store_file(prange_t range, const char *filename, mode_t mode);

uint32_t parse_hex_uint32(char *string);
