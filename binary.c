#define BINARY_C
#include "common.h"
#include "binary.h"
#include "loader.h"
#include "nlist.h"
#include "fat.h"
#include "dyld_cache_format.h"
#ifdef __APPLE__
#include <mach/mach.h>
#endif

const int desired_cputype = 12; // ARM
const int desired_cpusubtype = 0; // v7=9, v6=6

void b_init(struct binary *binary) {
    memset(binary, 0, sizeof(*binary));
}

static void b_reserve_memory(struct binary *binary, uint32_t minaddr, uint32_t maxaddr) {
    if(minaddr > maxaddr) {
        die("weird minaddr/maxaddr %08x, %08x", minaddr, maxaddr);
    }
    void *result = mmap(NULL, (size_t) (maxaddr - minaddr), PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if(result == MAP_FAILED) {
        edie("could not do so");
    }
    binary->load_base = (char *)result - minaddr;
}

void b_macho_load_symbols(struct binary *binary) {
    CMD_ITERATE(binary->mach_hdr, cmd) {
        if(cmd->cmd == LC_SYMTAB) {
            struct symtab_command *scmd = (void *) cmd;
            if(scmd->nsyms >= 0x1000000) {
                die("ridiculous number of symbols (%u)", scmd->nsyms);
            }
            binary->nsyms = scmd->nsyms;
            binary->strsize = scmd->strsize;
            binary->symtab = rangeconv_off((range_t) {binary, scmd->symoff, scmd->nsyms * sizeof(struct nlist)}).start;
            binary->strtab = rangeconv_off((range_t) {binary, scmd->stroff, scmd->strsize}).start;
        } else if(cmd->cmd == LC_DYSYMTAB) {
            binary->dysymtab = (void *) cmd;
        } else if(cmd->cmd == LC_DYLD_INFO_ONLY) {
            fprintf(stderr, "b_load_symbols: warning: file is fancy, symbols might be missing\n");
        }
    }
    if(binary->symtab && binary->dysymtab) {
        uint32_t iextdefsym = binary->dysymtab->iextdefsym;
        uint32_t nextdefsym = binary->dysymtab->nextdefsym;
        if(iextdefsym >= binary->nsyms) {
            die("bad iextdefsym (%u)", iextdefsym);
        }
        if(nextdefsym > binary->nsyms - iextdefsym) {
            die("bad nextdefsym (%u)", nextdefsym);
        }
        binary->ext_symtab = binary->symtab + iextdefsym;
        binary->ext_nsyms = nextdefsym;
    } else {
        binary->ext_symtab = binary->symtab;
        binary->ext_nsyms = binary->nsyms;
    }
}

static void do_dyld_hdr(struct binary *binary) {
    if(memcmp(binary->dyld_hdr->magic, "dyld_", 5)) {
        die("not a dyld cache");
    }
    char *thing = binary->dyld_hdr->magic + sizeof(binary->dyld_hdr->magic) - 7;
    if(!memcmp(thing, " armv7", 7)) {
        binary->actual_cpusubtype = 9;
    } else if(!memcmp(thing, " armv6", 7)) {
        binary->actual_cpusubtype = 6;
    } else {
        die("unknown processor in magic: %.6s", thing);
    }

    if(binary->dyld_hdr->mappingCount > 1000) {
        die("insane mapping count: %u", binary->dyld_hdr->mappingCount);
    }
    binary->dyld_mapping_count = binary->dyld_hdr->mappingCount;
}

void b_load_dyldcache(struct binary *binary, const char *path) {
#define _arg path
    int fd = open(path, O_RDONLY);
    if(fd == -1) { 
        edie("could not open");
    }
    binary->dyld_hdr = malloc(sizeof(*binary->dyld_hdr));
    if(read(fd, binary->dyld_hdr, sizeof(*binary->dyld_hdr)) != sizeof(*binary->dyld_hdr)) {
        die("truncated");
    }
    do_dyld_hdr(binary);

    size_t sz = binary->dyld_mapping_count * sizeof(struct shared_file_mapping_np);
    binary->dyld_mappings = malloc(sz);
    if(pread(fd, binary->dyld_mappings, sz, binary->dyld_hdr->mappingOffset) != sz) {
        edie("could not read mappings");
    }

    uint32_t minaddr = (uint32_t) -1, maxaddr = 0;
    for(int i = 0; i < binary->dyld_mapping_count; i++) {
        struct shared_file_mapping_np *mapping = &binary->dyld_mappings[i];
        addr_t address = (addr_t) mapping->sfm_address;
        size_t size = (size_t) mapping->sfm_size;
        if(address < minaddr) minaddr = address;
        if((address + size) > maxaddr) maxaddr = address + size;
    }
    b_reserve_memory(binary, minaddr, maxaddr);


    for(int i = 0; i < binary->dyld_mapping_count; i++) {
        struct shared_file_mapping_np *mapping = &binary->dyld_mappings[i];
        if(mmap(b_addrconv_unsafe(binary, (addr_t) mapping->sfm_address), (size_t) mapping->sfm_size, PROT_READ, MAP_SHARED | MAP_FIXED, fd, (off_t) mapping->sfm_file_offset) == MAP_FAILED) {
            edie("could not map segment %d of this crappy binary format", i);
        }
    }
#undef _arg
}

void b_load_running_dyldcache(struct binary *binary, void *baseaddr) {
    binary->dyld_hdr = baseaddr;
    binary->load_base = NULL;
    do_dyld_hdr(binary);
    binary->dyld_mappings = (void *) ((char *)binary->dyld_hdr + binary->dyld_hdr->mappingOffset);
}

range_t b_dyldcache_nth_segment(const struct binary *binary, int n) {
    if(n < binary->dyld_mapping_count) {
        ((struct binary *) binary)->last_sfm = &binary->dyld_mappings[n];
        return (range_t) {binary, (addr_t) binary->dyld_mappings[n].sfm_address, (size_t) binary->dyld_mappings[n].sfm_size};
    } else {
        return (range_t) {binary, 0, 0};
    }
}

void b_dyldcache_load_macho(struct binary *binary, const char *filename) {
    if(binary->dyld_hdr->imagesCount > 1000) {
        die("insane images count");
    }
    for(int i = 0; i < binary->dyld_hdr->imagesCount; i++) {
        struct dyld_cache_image_info *info = rangeconv_off((range_t) {binary, binary->dyld_hdr->imagesOffset + i * sizeof(*info), sizeof(*info)}).start;
        char *name = rangeconv_off((range_t) {binary, info->pathFileOffset, 128}).start;
        if(strncmp(name, filename, 128)) {
            continue;
        }
        // we found it
        binary->mach_hdr = rangeconv((range_t) {binary, (addr_t) info->address, 0x1000}).start;
        break;
    }
    b_macho_load_symbols(binary);
}

#define DEFINE_RANGECONV(name, dfield, mfield, intro, dreturn, mreturn) \
prange_t name(range_t range) { \
    if(range.binary->dyld_hdr) { \
        struct shared_file_mapping_np *sfm = range.binary->last_sfm; \
        if(sfm && sfm->dfield <= range.start && range.start <= range.start + range.size && range.start + range.size <= sfm->dfield + sfm->sfm_size) { \
            goto dok; \
        } \
        sfm = range.binary->dyld_mappings; \
        for(uint32_t i = 0; i < range.binary->dyld_mapping_count; i++) { \
            if(sfm->dfield <= range.start && range.start <= range.start + range.size && range.start + range.size <= sfm->dfield + sfm->sfm_size) { \
                /* ditto */ \
                ((struct binary *) (range.binary))->last_sfm = sfm; \
                goto dok; \
            } \
            sfm++; \
        } \
        goto err; \
        dok: \
        return (prange_t) {dreturn, range.size}; \
    } else if(range.binary->mach_hdr) { \
        struct segment_command *seg = range.binary->last_seg; \
        if(seg && seg->mfield <= range.start && range.start <= range.start + range.size && range.start + range.size <= seg->mfield + seg->filesize) { \
            goto mok; \
        } \
        CMD_ITERATE(range.binary->mach_hdr, cmd) { \
            if(cmd->cmd == LC_SEGMENT) { \
                seg = (void *) cmd; \
                if(seg->mfield <= range.start && range.start <= range.start + range.size && range.start + range.size <= seg->mfield + seg->filesize) { \
                    ((struct binary *) (range.binary))->last_seg = seg; \
                    goto mok; \
                } \
            } \
        } \
        goto err; \
        mok: \
        return (prange_t) {mreturn, range.size}; \
    } else { \
        die("neither dyld_hdr nor mach_hdr present"); \
    } \
    err: \
    die(intro " (%08x, %zx) not valid", range.start, range.size); \
}

DEFINE_RANGECONV(rangeconv, sfm_address, vmaddr, "range", \
    b_addrconv_unsafe(range.binary, range.start), \
    b_addrconv_unsafe(range.binary, range.start))
DEFINE_RANGECONV(rangeconv_off, sfm_file_offset, fileoff, "offset range", \
    (char *)b_addrconv_unsafe(range.binary, sfm->sfm_address) + range.start - sfm->sfm_file_offset, \
    (char *)b_addrconv_unsafe(range.binary, seg->vmaddr) + range.start - seg->fileoff)

typedef void *(*almost_mmap_func)(void *, size_t, int, int, uintptr_t, off_t);
typedef int (*munmap_func)(void *, size_t);

static void b_load_macho_m(struct binary *binary, const char *path, uintptr_t fd, bool rw, almost_mmap_func mm, munmap_func mum) {
#define _arg path
    struct mach_header *mach_hdr;
    void *fhdr = (*mm)(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if(fhdr == MAP_FAILED) {
        edie("could not map file header");
    }
    uint32_t magic = *(uint32_t *)fhdr;
    uint32_t fat_offset;
    if(magic == MH_MAGIC) {
        // thin file
        mach_hdr = fhdr;
        if(mach_hdr->cputype != desired_cputype || (mach_hdr->cpusubtype != 0 && desired_cpusubtype != 0 && mach_hdr->cpusubtype != desired_cpusubtype)) {
            die("thin file doesn't have the right architecture");
        }
        fat_offset = 0;
    } else if(magic == FAT_MAGIC) {
        if(desired_cpusubtype == 0) {
            die("fat, but we don't even know what we want (desired_cpusubtype == 0)");
        }
        struct fat_header *fathdr = fhdr;
        struct fat_arch *arch = (void *)(fathdr + 1);
        uint32_t nfat_arch = fathdr->nfat_arch;
        if(sizeof(struct fat_header) + nfat_arch * sizeof(struct fat_arch) >= 0x1000) {
            die("fat header is too big");
        }
        while(nfat_arch--) {
            if(arch->cputype == desired_cputype && (arch->cpusubtype == 0 || arch->cpusubtype == desired_cpusubtype)) {
                (*mum)(fhdr, 0x1000);
                fat_offset = arch->offset;
                mach_hdr = (*mm)(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, fat_offset);
                if(mach_hdr == MAP_FAILED) {
                    edie("could not map mach-o header from fat file", path);
                }
                break;
            }
            arch++;
        }
    } else {
        die("(%08x) what is this I don't even", magic);
    }

    binary->actual_cpusubtype = mach_hdr->cpusubtype;

    if(mach_hdr->sizeofcmds > 0x1000 - sizeof(*mach_hdr)) {
        die("sizeofcmds is too big");
    }

    binary->symtab = NULL;

    uint32_t minaddr = (uint32_t) -1, maxaddr = 0;
    CMD_ITERATE(mach_hdr, cmd) {
        if(cmd->cmd == LC_SEGMENT) {
            const struct segment_command *scmd = (void *) cmd;
            if(scmd->vmaddr < minaddr) minaddr = scmd->vmaddr;
            if((scmd->vmaddr + scmd->filesize) > maxaddr) maxaddr = scmd->vmaddr + scmd->filesize;
        }
    }
    b_reserve_memory(binary, minaddr, maxaddr);

    CMD_ITERATE(mach_hdr, cmd) {
        if(cmd->cmd == LC_SEGMENT) {
            struct segment_command *scmd = (void *) cmd;
            if(scmd->vmsize == 0) scmd->filesize = 0; // __CTF
            if(scmd->filesize != 0) {
                if((*mm)(b_addrconv_unsafe(binary, scmd->vmaddr), scmd->filesize, rw ? (PROT_READ | PROT_WRITE) : PROT_READ, MAP_PRIVATE | MAP_FIXED, fd, fat_offset + scmd->fileoff) == MAP_FAILED) {
                    edie("could not map segment %.16s at %u+%u,%u", scmd->segname, scmd->fileoff, fat_offset, scmd->filesize);
                }
            }
            if(scmd->fileoff == 0) {
                binary->mach_hdr = b_addrconv_unsafe(binary, scmd->vmaddr);
            }
        }
    }

    (*mum)(mach_hdr, 0x1000);
    
    b_macho_load_symbols(binary);
#undef _arg
}

static void *almost_mmap(void *addr, size_t len, int prot, int flags, uintptr_t fd, off_t offset) {
    return mmap(addr, len, prot, flags, (int) fd, offset);
}

void b_load_macho(struct binary *binary, const char *path, bool rw) {
    int fd = open(path, O_RDONLY);
    if(fd == -1) { 
        edie("could not open");
    }
    b_load_macho_m(binary, path, fd, rw, &almost_mmap, &munmap);
}

#ifdef IMG3_SUPPORT
#include <mach/mach.h>
static void *fake_mmap(void *addr, size_t len, int prot, int flags, uintptr_t fd, off_t offset) {
    vm_address_t address = (vm_address_t) addr;
    vm_prot_t c, m;
    prange_t *pr = (void *) fd;

    if(flags & MAP_FIXED) {
        munmap((void *)addr, len);
    }

    kern_return_t kr = vm_remap(mach_task_self(), &address, (vm_size_t) ((len + 0xfff) & ~0xfff), 0xfff, !(flags & MAP_FIXED), mach_task_self(), (vm_address_t)pr->start + offset, true, &c, &m, VM_INHERIT_NONE);
    if(kr) {
        switch(kr) {
        case KERN_INVALID_ADDRESS: errno = EINVAL; break;
        case KERN_NO_SPACE: errno = ENOMEM; break;
        case KERN_PROTECTION_FAILURE: errno = EACCES; break;
        }
        return MAP_FAILED;
    } else if(!(c & VM_PROT_READ)) {
        errno = EACCES;
        return MAP_FAILED;
    } else {
        return (void *) address;
    }
}

static int fake_munmap(void *addr, size_t len) {
    kern_return_t kr = vm_deallocate(mach_task_self(), (mach_vm_address_t) addr, (mach_vm_size_t) len);
    if(!kr) {
        return 0;
    } else {
        errno = EINVAL;
        return -1;
    }
}

void b_prange_load_macho(struct binary *binary, prange_t range, bool rw) {
    b_load_macho_m(binary, "(buffer)", (uintptr_t) &range, rw, &fake_mmap, &fake_munmap);
}
#endif

void b_running_kernel_load_macho(struct binary *binary) {
#ifdef __APPLE__
    kern_return_t kr;

    mach_port_name_t kernel_task;
    kr = task_for_pid(mach_task_self(), 0, &kernel_task);
    if(kr) {
        die("task_for_pid failed.  u probably need kernel patches. kr=%d", kr);
    }

    kr = vm_allocate(mach_task_self(), (vm_address_t *) &binary->mach_hdr, 0x1000, true);
    if(kr) {
        die("vm_allocate mach_hdr failed");
    }
    addr_t mh_addr;
    vm_size_t size;
    for(addr_t hugebase = 0x80000000; hugebase; hugebase += 0x40000000) {
        for(addr_t pagebase = 0x1000; pagebase < 0x10000; pagebase += 0x1000) {
            // vm read, compare to MH_MAGIC, hurf durf
            mh_addr = (vm_address_t) (hugebase + pagebase);
            size = 0x1000;
            // This will return either KERN_PROTECTION_FAILURE if it's a good address, and KERN_INVALID_ADDRESS otherwise.
            // But if we use a shorter size, it will read if it's a good address, and /crash/ otherwise.
            // So we do two.
            kr = vm_read_overwrite(kernel_task, (vm_address_t) mh_addr, size, (vm_address_t) binary->mach_hdr, &size);
            if(kr == KERN_INVALID_ADDRESS) {
                continue;
            } else if(kr && kr != KERN_PROTECTION_FAILURE) {
                die("unexpected error from vm_read_overwrite: %d", kr);
            }
            // ok, it's valid, but is it the actual header?
            size = 0xfff;
            kr = vm_read_overwrite(kernel_task, (vm_address_t) mh_addr, size, (vm_address_t) binary->mach_hdr, &size);
            if(kr) {
                die("second vm_read_overwrite failed: %d", kr);
            }
            if(binary->mach_hdr->magic == MH_MAGIC) {
                printf("found running kernel at 0x%08x\n", mh_addr);
                goto ok;
            }
        }
    }
    die("didn't find the kernel anywhere");

    ok:;

    binary->actual_cpusubtype = binary->mach_hdr->cpusubtype;

    if(binary->mach_hdr->sizeofcmds > size - sizeof(*binary->mach_hdr)) {
        die("sizeofcmds is too big");
    }
    addr_t maxaddr = mh_addr;
    CMD_ITERATE(binary->mach_hdr, cmd) {
        if(cmd->cmd == LC_SEGMENT) {
            struct segment_command *scmd = (void *) cmd;
            addr_t newmax = scmd->vmaddr + scmd->filesize;
            if(newmax > maxaddr) maxaddr = newmax;
        }
    }

    // Well, uh, this sucks.  But there's some block on reading.  In fact, it's probably a bug that this works.
    size_t read_size = maxaddr - mh_addr;
    char *p = malloc(read_size);
    binary->load_base = p - 0x1000;
#ifdef PROFILING
    clock_t a = clock();
#endif
    while(read_size > 0) {
        vm_size_t this_size = (vm_size_t) read_size;
        if(this_size > 0xfff) this_size = 0xfff;
        kr = vm_read_overwrite(kernel_task, (vm_address_t) mh_addr, this_size, (vm_address_t) p, &this_size);
        if(kr) {
            die("vm_read_overwrite failed: %d", kr);
        }
        mh_addr += this_size;
        p += this_size;
        read_size -= this_size;
    }
#ifdef PROFILING
    clock_t b = clock();
    printf("it took %d clocks to read the kernel\n", (int)(b - a));
#endif
    b_macho_load_symbols(binary);
/*
    vm_address_t mine = 0x10000000;
    vm_prot_t curprot, maxprot;

    printf("%x %x %x\n", maxaddr, mh_addr, maxaddr - mh_addr);

    for(addr_t i = 0xc0000000; i < 0xc0100000; i += 0x1000) {
        vm_size_t outsize;
        vm_address_t data;
        kr = vm_read(kernel_task, (vm_address_t) i, 0xfff, &data, &outsize);
        printf("%08x -> %d\n", i, kr);
    }
    die("...\n");

    kr = vm_remap(mach_task_self(), &mine, 0x1000, 0, true, kernel_task, (mach_vm_address_t) mh_addr, false, &curprot, &maxprot, VM_INHERIT_NONE);
    if(kr) {
        die("load_running_kernel: vm_remap returned %d\n", mine, kr);
    }
    printf("curprot=%d maxprot=%d mine=%x\n", curprot, maxprot, mine);

    load_base = (void *) (mine - 0x1000);
*/
    mach_port_deallocate(mach_task_self(), kernel_task);
#else
    die("load_running_kernel: not on Apple");
#endif
}
 

range_t b_macho_segrange(const struct binary *binary, const char *segname) {
    CMD_ITERATE(binary->mach_hdr, cmd) {
        if(cmd->cmd == LC_SEGMENT) {
            struct segment_command *seg = (void *) cmd;
            if(!strncmp(seg->segname, segname, 16)) {
                // still semantically const
                ((struct binary *) binary)->last_seg = seg;
                return (range_t) {binary, seg->vmaddr, seg->filesize};
            }
        }
    }
    die("no such segment %s", segname);
}

#define DEFINE_MACHO_RANGECONV(name, field, intro) \
prange_t name(range_t range) { \
    struct segment_command *seg = range.binary->last_seg; \
    if(seg && seg->field <= range.start && seg->filesize - (seg->field - range.start) >= range.size) { \
        goto ok; \
    } \
    CMD_ITERATE(range.binary->mach_hdr, cmd) { \
        if(cmd->cmd == LC_SEGMENT) { \
            seg = (void *) cmd; \
            if(seg->field <= range.start && seg->filesize - (seg->field - range.start) >= range.size) { \
                /* ditto */ \
                ((struct binary *) (range.binary))->last_seg = seg; \
                goto ok; \
            } \
        } \
    } \
    die(intro " (%08x, %zx) not valid", range.start, range.size); \
    ok: \
    return (prange_t) {b_addrconv_unsafe(range.binary, range.start), range.size}; \
}

prange_t rangeconv_checkof(range_t range) {
    if((range.size & ~0x0fffffff) || (((range.start & 0x0fffffff) + range.size) & ~0x0fffffff)) {
        die("range (%08x, %zx) overflowing", range.start, range.size);
    }
    return (prange_t) {b_addrconv_unsafe(range.binary, range.start), range.size};
}

// return value is |1 if to_execute is set and it is a thumb symbol
addr_t b_sym(const struct binary *binary, const char *name, bool to_execute) {
    if(!binary->ext_symtab) {
        die("we wanted %s but there is no symbol table", name);
    }
    // I stole dyld's codez
    const struct nlist *base = binary->ext_symtab;
    for(uint32_t n = binary->ext_nsyms; n > 0; n /= 2) {
        const struct nlist *pivot = base + n/2;
        uint32_t strx = pivot->n_un.n_strx;
        if(strx >= binary->strsize) {
            die("insane strx: %u", strx);
        }
        const char *pivot_str = binary->strtab + strx;
        int cmp = strncmp(name, pivot_str, binary->strsize - strx);
        if(cmp == 0) {
            // we found it
            addr_t result = pivot->n_value;
            if(to_execute && (pivot->n_desc & N_ARM_THUMB_DEF)) {
                result |= 1;
            }
            return result;
        } else if(cmp > 0) {
            base = pivot + 1; 
            n--;
        }
    }
    die("symbol %s not found", name);
}

void b_macho_store(struct binary *binary, const char *path) {
#define _arg path
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if(fd <= 0) {
        edie("unable to open");
    }
    CMD_ITERATE(binary->mach_hdr, cmd) {
        if(cmd->cmd == LC_SEGMENT) {
            struct segment_command *scmd = (void *) cmd;
            lseek(fd, scmd->fileoff, SEEK_SET);
            if(write(fd, b_addrconv_unsafe(binary, scmd->vmaddr), scmd->filesize) != scmd->filesize) {
                edie("couldn't write segment data");
            }
        }
    }
#undef _arg
}
