#include "common.h"
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <stdarg.h>
#include <setjmp.h>

prange_t pdup(prange_t range) {
    void *buf = malloc(range.size);
    memcpy(buf, range.start, range.size);
    return (prange_t) {buf, range.size};
}

void pfree(prange_t range) {
    free(range.start);
}

void punmap(prange_t range) {
    munmap(range.start, range.size);
}

void check_range_has_addr(range_t range, addr_t addr) {
    if(addr < range.start || addr >= (range.start + range.size)) {
        die("bad address 0x%08x (not in range %08x-%08x)", addr, range.start, range.start + (uint32_t) range.size);
    }
}
    
bool is_valid_range(prange_t range) {
    char c;
    return !mincore(range.start, range.size, (void *) &c);
}

static inline bool parse_hex_digit(char digit, uint8_t *result) {
    if(digit >= '0' && digit <= '9') {
        *result = digit - '0';
        return true;
    } else if(digit >= 'a' && digit <= 'f') {
        *result = 10 + (digit - 'a');
        return true;
    }
    return false;
}

prange_t parse_hex_string(const char *string) {
    size_t len = strlen(string);
    if(len % 2) goto bad;
    len /= 2;
    uint8_t *buf = malloc(len);
    prange_t result = (prange_t) {buf, len};
    while(len--) {
        char first = *string++;
        char second = *string++;
        uint8_t a, b;
        if(!parse_hex_digit(first, &a)) goto bad;
        if(!parse_hex_digit(second, &b)) goto bad;
        *buf++ = (a * 0x10) + b;
    }
    return result;
    bad:
    die("bad hex string %s", string);
}

prange_t load_file(const char *filename, bool rw, mode_t *mode) {
#define _arg filename
    if(mode) {
        struct stat st;
        if(lstat(filename, &st)) {
            edie("could not lstat");
        }
        *mode = st.st_mode;
    }
    int fd = open(filename, O_RDONLY);
    if(fd == -1) {
        edie("could not open");
    }
    return load_fd(fd, rw);
#undef _arg
}

prange_t load_fd(int fd, bool rw) {
    off_t end = lseek(fd, 0, SEEK_END);
    if(end == 0) {
        fprintf(stderr, "load_fd: warning: mapping an empty file\n");
    }
    if(sizeof(off_t) > sizeof(size_t) && end > (off_t) SIZE_MAX) {
        die("too big: %lld", (long long) end);
    }
    void *buf = mmap(NULL, (size_t) end, PROT_READ | (rw ? PROT_WRITE : 0), MAP_PRIVATE, fd, 0);
    if(buf == MAP_FAILED) {
        edie("could not mmap buf (end=%zd)", (size_t) end);
    }
    return (prange_t) {buf, (size_t) end};
}

void store_file(prange_t range, const char *filename, mode_t mode) {
#define _arg filename
    int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if(fd == -1) {
        edie("could not open");
    }
    if(write(fd, range.start, range.size) != (ssize_t) range.size) {
        edie("could not write data");
    }
    close(fd);
#undef _arg
}

uint32_t parse_hex_uint32(char *string) {
    prange_t pr = parse_hex_string(string);
    if(pr.size > 4) {
        die("too long hex string %s", string);
    }
    uint32_t u = 0;
    memcpy(&u, pr.start, pr.size);
    free(pr.start);
    return swap32(u);
}

static jmp_buf die_handler;
static bool die_handler_valid;
static char die_message[256];

void _die(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);

    if(die_handler_valid) {
        die_handler_valid = false;
        vsnprintf(die_message, sizeof(die_message), fmt, ap);
        longjmp(die_handler, -1);
    } else {
        vfprintf(stderr, fmt, ap);
        abort();
    }

    va_end(ap);
}

const char *data_try(void (*func)()) {
    if(setjmp(die_handler)) {
        return die_message;
    } else {
        die_handler_valid = true;
        func();
        die_handler_valid = false;
        return NULL;
    }
}
