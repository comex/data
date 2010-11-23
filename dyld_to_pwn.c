#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "loader.h"

struct arm_unixthread_command {
    uint32_t    cmd;        /* LC_UNIXTHREAD */
    uint32_t    cmdsize;    /* sizeof(struct arm_unixthread_command) */
    uint32_t    flavor;     /* 1 */
    uint32_t    count;      /* 17 */
    uint32_t    r[13];
    uint32_t    sp;
    uint32_t    lr;
    uint32_t    pc;
    uint32_t    cpsr;
};

int main(int argc, char **argv) {
    int dyld_fd = open(argv[1], O_RDONLY);
    assert(dyld_fd > 0);
    off_t dyld_size = lseek(dyld_fd, 0, SEEK_END);
    size_t rounded_dyld_size = (((size_t) dyld_size) + 0xfff) & ~0xfff;
    struct mach_header *dyld_hdr = mmap(NULL, dyld_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, dyld_fd, 0);

    int extra_fd = open(argv[2], O_RDONLY);
    assert(extra_fd > 0);
    off_t extra_size = lseek(extra_fd, 0, SEEK_END);
    void *extra_buf = malloc((size_t) extra_size);
    assert(pread(extra_fd, extra_buf, (size_t) extra_size - 4, 4) == (ssize_t) extra_size - 4);

    dyld_hdr->filetype = MH_EXECUTE;

    struct segment_command *seg1 = (void *) (((char *) (dyld_hdr + 1)) + dyld_hdr->sizeofcmds);
    struct segment_command *seg2 = (void *) (seg1 + 1);
    struct arm_unixthread_command *unixthread = (void *) (seg2 + 1);
    dyld_hdr->ncmds += 3;
    dyld_hdr->sizeofcmds += 2*sizeof(struct segment_command) + sizeof(struct arm_unixthread_command);
    
    seg1->cmd = LC_SEGMENT;
    seg1->cmdsize = sizeof(*seg1);
    const char seg1name[16] = "__STACK";
    memcpy(seg1->segname, seg1name, 16);
    seg1->vmaddr = 0x10000000;
    seg1->vmsize = 0x01000000;
    seg1->fileoff = 0;
    seg1->filesize = 0;
    seg1->maxprot = seg1->initprot = PROT_READ | PROT_WRITE;
    seg1->nsects = 0;
    seg1->flags = 0;

    seg2->cmd = LC_SEGMENT;
    seg2->cmdsize = sizeof(*seg2);
    const char seg2name[16] = "__CAKE";
    memcpy(seg2->segname, seg2name, 16);
    seg2->vmaddr = 0x11000000;
    seg2->vmsize = (uint32_t) (extra_size - 4);
    seg2->fileoff = (uint32_t) rounded_dyld_size;
    seg2->filesize = (uint32_t) (extra_size - 4);
    seg2->maxprot = seg2->initprot = PROT_READ | PROT_WRITE;
    seg2->nsects = 0;
    seg2->flags = 0;
    
    memset(unixthread, 0, sizeof(*unixthread));
    unixthread->cmd = LC_UNIXTHREAD;
    unixthread->cmdsize = sizeof(*unixthread);
    unixthread->flavor = 1;
    unixthread->count = 17;
    unixthread->sp = 0x11000000;
    assert(pread(extra_fd, &unixthread->pc, 4, 0) == 4);

    int output_fd = open(argv[3], O_WRONLY | O_TRUNC | O_CREAT, 0755);
    assert(output_fd > 0);
    assert(write(output_fd, dyld_hdr, (size_t) dyld_size) == (ssize_t) dyld_size);
    size_t diff = rounded_dyld_size - (size_t) dyld_size;
    char *zeroes = calloc(1, rounded_dyld_size - (size_t) dyld_size);
    assert(write(output_fd, zeroes, diff) == (ssize_t) diff);
    assert(write(output_fd, extra_buf, (size_t) extra_size - 4) == (ssize_t) extra_size - 4);
    close(output_fd);
}
