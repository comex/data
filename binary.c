#include "common.h"
#include "binary.h"
#include "loader.h"
#include "nlist.h"
#include "fat.h"
#include "dyld_cache_format.h"
#include "find.h"

const int desired_cputype = 12; // ARM
const int desired_cpusubtype = 0; // v7=9, v6=6

void b_init(struct binary *binary) {
    memset(binary, 0, sizeof(*binary));
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

void b_load_dyldcache(struct binary *binary, const char *path, bool rw) {
    b_prange_load_dyldcache(binary, load_file(path, rw, NULL), path);
}

void b_prange_load_dyldcache(struct binary *binary, prange_t pr, const char *name) {
#define _arg name
    binary->valid = true;
    binary->is_address_indexed = false;

    if(pr.size < sizeof(*binary->dyld_hdr)) {
        die("truncated");
    }
    binary->dyld_hdr = pr.start;
    do_dyld_hdr(binary);

    if(binary->dyld_hdr->mappingOffset >= pr.size || binary->dyld_hdr->mappingOffset + (binary->dyld_mapping_count * sizeof(struct shared_file_mapping_np)) > pr.size) {
        die("truncated");
    }
    
    for(unsigned int i = 0; i < binary->dyld_mapping_count; i++) {
        struct shared_file_mapping_np *mapping = &binary->dyld_mappings[i];
        if(mapping->sfm_file_offset >= pr.size || mapping->sfm_file_offset + mapping->sfm_size > pr.size) {
            die("truncated");
        }
    }
#undef _arg
}

void b_load_running_dyldcache(struct binary *binary, void *baseaddr) {
    binary->valid = true;
    binary->is_address_indexed = true;
    binary->dyld_hdr = baseaddr;
    binary->load_base = NULL;
    binary->limit = NULL;
    do_dyld_hdr(binary);
    binary->dyld_mappings = (void *) ((char *)binary->dyld_hdr + binary->dyld_hdr->mappingOffset);
}

range_t b_dyldcache_nth_segment(const struct binary *binary, unsigned int n) {
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
    for(unsigned int i = 0; i < binary->dyld_hdr->imagesCount; i++) {
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

#define DEFINE_RANGECONV(rettype, name, intro, dfield, mfield, retfunc) \
rettype name(range_t range) { \
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
        return retfunc(range.binary, sfm->sfm_address, sfm->sfm_file_offset, range.start - sfm->dfield, range.size); \
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
        return retfunc(range.binary, seg->vmaddr, seg->fileoff, range.start - seg->mfield, range.size); \
    } else { \
        die("neither dyld_hdr nor mach_hdr present"); \
    } \
    err: \
    die(intro " (%08x, %zx) not valid", range.start, range.size); \
}

__attribute__((const))
inline prange_t x_prange(const struct binary *binary, addr_t addrbase, addr_t offbase, addr_t diff, size_t size) {
    return (prange_t) {(char *)binary->load_base + (binary->is_address_indexed ? addrbase : offbase) + diff, size};
}

__attribute__((const))
static inline range_t x_range(const struct binary *binary, addr_t addrbase, addr_t offbase, addr_t diff, size_t size) {
    (void) offbase;
    return (range_t) {binary, addrbase + diff, size};
}


__attribute__((const))
static inline range_t x_off_range(const struct binary *binary, addr_t addrbase, addr_t offbase, addr_t diff, size_t size) {
    (void) addrbase;
    return (range_t) {binary, offbase + diff, size};
}

DEFINE_RANGECONV(prange_t, rangeconv, "range", sfm_address, vmaddr, x_prange)
DEFINE_RANGECONV(prange_t, rangeconv_off, "offset range", sfm_file_offset, fileoff, x_prange)
DEFINE_RANGECONV(range_t, range_to_off_range, "range", sfm_address, vmaddr, x_off_range)
DEFINE_RANGECONV(range_t, off_range_to_range, "offset range", sfm_file_offset, fileoff, x_range)


void b_prange_load_macho(struct binary *binary, prange_t pr, const char *name) {
#define _arg name
    binary->valid = true;
    binary->is_address_indexed = false;

    if(pr.size < 0x1000) {
        die("truncated");
    }
    
    struct mach_header *mach_hdr;

    uint32_t magic = *(uint32_t *)pr.start;
    uint32_t fat_offset;
    if(magic == MH_MAGIC) {
        // thin file
        mach_hdr = pr.start;
        if(mach_hdr->cputype != desired_cputype || (mach_hdr->cpusubtype != 0 && desired_cpusubtype != 0 && mach_hdr->cpusubtype != desired_cpusubtype)) {
            die("thin file doesn't have the right architecture");
        }
        fat_offset = 0;
    } else if(magic == FAT_MAGIC) {
        if(desired_cpusubtype == 0) {
            die("fat, but we don't even know what we want (desired_cpusubtype == 0)");
        }
        struct fat_header *fathdr = pr.start;
        struct fat_arch *arch = (void *)(fathdr + 1);
        uint32_t nfat_arch = fathdr->nfat_arch;
        if(sizeof(struct fat_header) + nfat_arch * sizeof(struct fat_arch) >= 0x1000) {
            die("fat header is too big");
        }
        while(nfat_arch--) {
            if(arch->cputype == desired_cputype && (arch->cpusubtype == 0 || arch->cpusubtype == desired_cpusubtype)) {
                fat_offset = arch->offset;
                if(fat_offset + 0x1000 >= pr.size) {
                    die("truncated (couldn't seek to fat offset %u)", fat_offset);
                }
                mach_hdr = (void *) ((char *)pr.start + fat_offset);
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

    CMD_ITERATE(mach_hdr, cmd) {
        if(cmd->cmd == LC_SEGMENT) {
            const struct segment_command *scmd = (void *) cmd;
            if(scmd->fileoff >= pr.size || scmd->fileoff + scmd->filesize > pr.size) {
                die("truncated"); 
            }
        }
    }

    binary->load_base = pr.start;
    binary->limit = (char *)pr.start + pr.size;
    binary->mach_hdr = mach_hdr;

    b_macho_load_symbols(binary);
#undef _arg
}

void b_load_macho(struct binary *binary, const char *path, bool rw) {
    b_prange_load_macho(binary, load_file(path, rw, NULL), path);
}

void b_fd_load_macho(struct binary *binary, int fd, bool rw) {
    b_prange_load_macho(binary, load_fd(fd, rw), "(fd)");
}

range_t b_macho_segrange(const struct binary *binary, const char *segname) {
    if(binary->last_seg && !strncmp(binary->last_seg->segname, segname, 16)) {
        return (range_t) {binary, binary->last_seg->vmaddr, binary->last_seg->filesize};
    }

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
    if(binary->is_address_indexed) {
        CMD_ITERATE(binary->mach_hdr, cmd) {
            if(cmd->cmd == LC_SEGMENT) {
                struct segment_command *scmd = (void *) cmd;
                lseek(fd, scmd->fileoff, SEEK_SET);
                ssize_t result = write(fd, ((char *) binary->load_base) + scmd->vmaddr, scmd->filesize);
                if(result < 0 || result != (ssize_t)scmd->filesize) {
                    edie("couldn't write segment data");
                }
            }
        }
    } else {
        size_t tow = ((char *)binary->limit) - ((char *)binary->load_base);
        printf("%zx %p %p\n", tow, binary->limit, binary->load_base);
        ssize_t result = write(fd, binary->load_base, tow);
        if(result < 0 || result != (ssize_t)tow) {
            edie("couldn't write whole file");
        }
    }
    close(fd);
#undef _arg
}

bool b_is_armv7(struct binary *binary) {
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

uint32_t b_allocate_from_macho_fd(int fd) {
    struct mach_header *hdr = mmap(NULL, 0x1000, PROT_READ, MAP_SHARED, fd, 0);
    if(hdr == MAP_FAILED) edie("could not mmap hdr");
    if(hdr->sizeofcmds > 0x1000 || hdr->sizeofcmds + sizeof(struct mach_header) > 0x1000) {
        die("too many commands");
    }

    uint32_t max = 0;
    CMD_ITERATE(hdr, cmd) {
        if(cmd->cmd == LC_SEGMENT) {
            struct segment_command *seg = (void *) cmd;
            if(seg->vmaddr >= 0xf0000000 || seg->vmaddr + seg->vmsize < seg->vmaddr) {
                die("overflow");
            }
            uint32_t newmax = seg->vmaddr + seg->vmsize;
            if(newmax > max) max = newmax;
        }
    }

    if(max == 0) {
        die("no segments");
    }

    munmap(hdr, 0x1000);

    return (max + 0xfff) & ~0xfff;
}


static addr_t find_vm_pageout(const struct binary *binary);

void b_inject_into_macho_fd(const struct binary *binary, int fd) {

    off_t seg_off = lseek(fd, 0, SEEK_END);
    struct mach_header *hdr = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if(hdr == MAP_FAILED) edie("could not mmap hdr in read/write mode");
    if(hdr->sizeofcmds > 0x1000 || hdr->sizeofcmds + sizeof(struct mach_header) > 0x1000) {
        die("too many commands");
    }

    struct segment_command *newseg = (void *) ((char *) (hdr + 1) + hdr->sizeofcmds);
    off_t header_off = sizeof(struct mach_header) + hdr->sizeofcmds;

    uint32_t init_ptrs[100];
    int num_init_ptrs = 0;

    CMD_ITERATE(binary->mach_hdr, cmd) {
        if(cmd->cmd == LC_SEGMENT) {
            struct segment_command *seg = (void *) cmd;
            if(seg->nsects > 1000) {
                die("too many sections");
            }
            size_t size = sizeof(struct segment_command) + seg->nsects * sizeof(struct section);
            if(size != seg->cmdsize) {
                die("inconsistent cmdsize");
            }

            if(header_off + size > 0x1000) {
                die("not enough space");
            }

            hdr->ncmds++;
            hdr->sizeofcmds += size;

            memcpy(newseg, seg, size);

            seg_off = (seg_off + 0xfff) & ~0xfff;

            newseg->fileoff = (uint32_t) seg_off;
            prange_t pr = rangeconv((range_t) {binary, seg->vmaddr, seg->filesize});
            if((size_t) pwrite(fd, pr.start, pr.size, seg_off) != pr.size) {
                die("couldn't write additional segment");
            }

            seg_off += pr.size;

            newseg = (void *) ((char *)newseg + size);
            header_off += size;
            
            struct section *sections = (void *) (seg + 1);
            for(unsigned int i = 0; i < seg->nsects; i++) {
                struct section *sect = &sections[i];
                if((sect->flags & SECTION_TYPE) == S_MOD_INIT_FUNC_POINTERS) {
                    uint32_t *p = rangeconv((range_t) {binary, sect->addr, sect->size}).start;
                    size_t num = sect->size / 4;
                    while(num--) {
                        if(num_init_ptrs < 100) init_ptrs[num_init_ptrs++] = *p++;
                    }
                }
                // ZEROFILL is okay because iBoot always zeroes vmsize - filesize
            }
        }
    }


    // now deal with the init pointers
    if(num_init_ptrs > 0) {
        if(num_init_ptrs == 1) {
            fprintf(stderr, "note: 1 constructor function is present; hacking vm_pageout\n");
        } else {
            fprintf(stderr, "note: %d constructor functions are present; hacking vm_pageout\n", num_init_ptrs);
        }
        
        // ldr r3, [pc]; bx r3
        uint16_t part0[] = {0x4b00, 0x4718};

        // push {lr}; ldr r3, [pc, #4]; blx r3; b next
        // (the address of the init func)
        // 
        uint16_t part1[] = {0xb500, 0x4b01, 0x4798, 0xe001};
        // (bytes_to_move bytes of stuff)
        // pop {r3}; mov lr, r3
        static const uint16_t part2[] = {0xbc08, 0x469e};
        // ldr r3, foo; bx r3
        static const uint16_t part3[] = {0x4b00, 0x4718};


        uint32_t bytes_to_move = 12; // don't cut the MRC in two!

        struct binary kern;
        b_init(&kern);
        b_fd_load_macho(&kern, fd, false);
        addr_t vm_pageout = find_vm_pageout(&kern);
        fprintf(stderr, "vm_pageout = %08x\n", vm_pageout);
        prange_t vm_pageout_pr = rangeconv((range_t) {&kern, vm_pageout & ~1, bytes_to_move});
        range_t vm_pageout_off_range = range_to_off_range((range_t) {&kern, vm_pageout & ~1, sizeof(part0) + sizeof(uint32_t)});

        // allocate a new segment for the stub

        uint32_t stub_size = (sizeof(part1) + 4) * num_init_ptrs + sizeof(part2) + bytes_to_move + sizeof(part3) + 4;

        if(!(vm_pageout & 1)) {
            die("vm_pageout is not thumb");
        }


        size_t size = sizeof(struct segment_command);
        if(header_off + size > 0x1000) {
            die("not enough space");
        }

        seg_off = (seg_off + 0xfff) & ~0xfff;

        hdr->ncmds++;
        hdr->sizeofcmds += sizeof(struct segment_command);
        
        newseg->cmd = LC_SEGMENT;
        newseg->cmdsize = sizeof(struct segment_command);
        memset(newseg->segname, 0, 16);
        strcpy(newseg->segname, "__CRAP");
        newseg->vmaddr = b_allocate_from_macho_fd(fd);
        newseg->vmsize = stub_size;
        newseg->fileoff = (uint32_t) seg_off;
        newseg->filesize = stub_size;
        newseg->maxprot = newseg->initprot = PROT_READ | PROT_EXEC;
        newseg->nsects = 0;
        newseg->flags = 0;

        lseek(fd, seg_off, SEEK_SET);

        seg_off += 4 * num_init_ptrs;

        for(int i = 0; i < num_init_ptrs; i++) {
            if(write(fd, part1, sizeof(part1)) != sizeof(part1) ||
               write(fd, &init_ptrs[i], 4) != 4) {
                edie("couldn't write part1");
            }
            part1[0] = 0x46c0;
        }
        
        if(write(fd, part2, sizeof(part2)) != sizeof(part2)) {
            edie("couldn't write part2");
        }

        if((size_t) write(fd, vm_pageout_pr.start, bytes_to_move) != bytes_to_move) {
            edie("couldn't write moved bytes");
        }

        if(write(fd, part3, sizeof(part3)) != sizeof(part3)) {
            edie("couldn't write part3");
        }

        uint32_t new_addr = vm_pageout + bytes_to_move;

        if(write(fd, &new_addr, sizeof(new_addr)) != sizeof(new_addr)) {
            edie("couldn't write new_addr");
        }
        
        lseek(fd, vm_pageout_off_range.start, SEEK_SET);

        if(write(fd, part0, sizeof(part0)) != sizeof(part0)) {
            edie("couldn't write part0");
        }

        new_addr = newseg->vmaddr | 1;

        if(write(fd, &new_addr, sizeof(new_addr)) != sizeof(new_addr)) {
            edie("couldn't write new_addr 2");
        }
    }

    munmap(hdr, 0x1000);
}

static addr_t find_vm_pageout(const struct binary *binary) {
    static const struct binary *last_binary;
    static addr_t last_vm_pageout;
    
    if(last_binary != binary) {
        last_binary = binary;

        range_t text = b_macho_segrange(binary, "__TEXT");
        const char *string = "\"vm_pageout_iothread_external";
        addr_t eof = find_int32(text, find_bytes(text, string, strlen(string), 1, true), true);
        printf("eof=%08x\n", eof);
        last_vm_pageout = find_bof(text, eof, true) | 1;
    }

    return last_vm_pageout;
}
