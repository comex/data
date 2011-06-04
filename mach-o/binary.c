#include "binary.h"
#include "headers/loader.h"
#include "headers/nlist.h"
#include "headers/fat.h"

const int desired_cputype = 12; // ARM
const int desired_cpusubtype = 0; // v7=9, v6=6

static addr_t sym(const struct binary *binary, const char *name, int options);
static void copy_syms(const struct binary *binary, struct data_sym **syms, uint32_t *nsyms, int options);

static void do_load_commands(struct binary *binary) {
    struct mach_header *hdr = binary->mach->hdr;
    if(!prange_check(binary, (prange_t) {hdr, hdr->sizeofcmds})) {
        die("not enough room for commands");
    }
    uint32_t nsegs = 0;
    CMD_ITERATE(hdr, cmd) {
        if(cmd + 1 > end || cmd > end - 1) {
            die("sizeofcmds is not even");
        }
        if(cmd->cmdsize > (size_t) ((char *) end - (char *) cmd)) {
            die("cmdsize overflows (%u)", cmd->cmdsize);
        }
        uint32_t required = 0;
        switch(cmd->cmd) {
        case LC_SEGMENT:
            required = sizeof(struct segment_command);
            nsegs++;
            break;
        case LC_REEXPORT_DYLIB:
            required = sizeof(struct dylib_command);
            break;
        case LC_SYMTAB:
            required = sizeof(struct symtab_command);
            break;
        case LC_DYSYMTAB:
            required = sizeof(struct dysymtab_command);
            break;
        case LC_DYLD_INFO:
        case LC_DYLD_INFO_ONLY:
            required = sizeof(struct dyld_info_command);
            break;
        case LC_ID_DYLIB:
            required = sizeof(struct dylib_command);
            break;
        }

        if(cmd->cmdsize < required) {
            die("cmdsize (%u) too small for cmd (0x%x)", cmd->cmdsize, cmd->cmd);
        }
    }
    binary->nsegments = nsegs;
    struct data_segment *seg = binary->segments = malloc(sizeof(*binary->segments) * binary->nsegments);
    CMD_ITERATE(hdr, cmd) {
        if(cmd->cmd == LC_SEGMENT) {
            struct segment_command *scmd = (void *) cmd;
            seg->file_range = (range_t) {binary, scmd->fileoff, scmd->filesize};
            seg->vm_range = (range_t) {binary, scmd->vmaddr, scmd->vmsize};
            seg->native_segment = cmd;
            seg++;
        }
    }
}

static void do_symbols(struct binary *binary) {
    CMD_ITERATE(binary->mach->hdr, cmd) {
        if(cmd->cmd == LC_SEGMENT) {
            struct segment_command *seg = (void *) cmd;
            if(seg->fileoff == 0) {
                binary->mach->export_baseaddr = seg->vmaddr;
            }
        } else if(cmd->cmd == LC_SYMTAB) {
            struct symtab_command *scmd = (void *) cmd;
            if(scmd->nsyms >= 0x1000000) {
                die("ridiculous number of symbols (%u)", scmd->nsyms);
            }
            binary->mach->nsyms = scmd->nsyms;
            binary->mach->strsize = scmd->strsize;
            binary->mach->symtab = rangeconv_off((range_t) {binary, scmd->symoff, scmd->nsyms * sizeof(struct nlist)}, MUST_FIND).start;
            binary->mach->strtab = rangeconv_off((range_t) {binary, scmd->stroff, scmd->strsize}, MUST_FIND).start;
            if(binary->mach->strtab[binary->mach->strsize - 1]) {
                die("string table does not end with \\0");
            }
        } else if(cmd->cmd == LC_DYSYMTAB) {
            binary->mach->dysymtab = (void *) cmd;
        } else if(cmd->cmd == LC_DYLD_INFO_ONLY || cmd->cmd == LC_DYLD_INFO) {
            struct dyld_info_command *dcmd = (void *) cmd;
            binary->mach->export_trie = rangeconv_off((range_t) {binary, dcmd->export_off, dcmd->export_size}, MUST_FIND);
        }
    }
    if(binary->mach->symtab && binary->mach->dysymtab) {
        uint32_t iextdefsym = binary->mach->dysymtab->iextdefsym;
        uint32_t nextdefsym = binary->mach->dysymtab->nextdefsym;
        if(iextdefsym >= binary->mach->nsyms) {
            die("bad iextdefsym (%u)", iextdefsym);
        }
        if(nextdefsym > binary->mach->nsyms - iextdefsym) {
            die("bad nextdefsym (%u)", nextdefsym);
        }
        binary->mach->ext_symtab = binary->mach->symtab + iextdefsym;
        binary->mach->ext_nsyms = nextdefsym;
    } else {
        binary->mach->ext_symtab = binary->mach->symtab;
        binary->mach->ext_nsyms = binary->mach->nsyms;
    }
}

void b_prange_load_macho(struct binary *binary, prange_t pr, size_t offset, const char *name) {
#define _arg name
    binary->valid = true;
    binary->mach = calloc(sizeof(*binary->mach), 1);
    binary->_sym = sym;
    binary->_copy_syms = copy_syms;

    binary->load_add = pr.start;
    binary->valid_range = pr;
    binary->header_offset = offset;

    if(offset - pr.size < sizeof(struct mach_header)) {
        die("not enough room");
    }

    struct mach_header *hdr = pr.start + offset;
    if(hdr->magic == MH_MAGIC) {
        // thin file
        binary->mach->hdr = pr.start;
        if(binary->mach->hdr->cputype != desired_cputype || (binary->mach->hdr->cpusubtype != 0 && desired_cpusubtype != 0 && binary->mach->hdr->cpusubtype != desired_cpusubtype)) {
            die("thin file doesn't have the right architecture");
        }
    } else if(hdr->magic == FAT_CIGAM) {
        if(offset) die("fat, offset != 0");

        struct fat_header *fathdr = (void *) hdr;
        struct fat_arch *arch = (void *)(fathdr + 1);
        uint32_t nfat_arch = SWAP32(fathdr->nfat_arch);
        if(nfat_arch > 1000 || pr.size < sizeof(struct fat_header) + nfat_arch * sizeof(struct fat_arch)) {
            die("fat header is too small");
        }
        binary->mach->hdr = NULL;
        while(nfat_arch--) {
            if(SWAP32(arch->cputype) == desired_cputype && (arch->cpusubtype == 0 || desired_cpusubtype == 0 || SWAP32(arch->cpusubtype) == desired_cpusubtype)) {
                uint32_t fat_offset = SWAP32(arch->offset);
                if(pr.size - fat_offset > sizeof(struct mach_header)) {
                    die("fat_offset too big");
                }
                binary->mach->hdr = pr.start + fat_offset;
                break;
            }
            arch++;
        }

        if(!binary->mach->hdr) {
            die("no compatible architectures in fat file");
        } else if(desired_cpusubtype == 0) {
            fprintf(stderr, "b_prange_load_macho: warning: fat, but out of apathy we just picked the first architecture with cputype %d, whose subtype was %d\n", desired_cputype, binary->mach->hdr->cpusubtype);
        }
    } else if(hdr->magic == MH_CIGAM || hdr->magic == FAT_MAGIC) {
        die("wrong endian");
    } else {
        die("(%08x) what is this I don't even", hdr->magic);
    }

    binary->actual_cpusubtype = binary->mach->hdr->cpusubtype;

    do_load_commands(binary);
    do_symbols(binary);
#undef _arg
}


static inline struct data_sym convert_nlist(const struct binary *binary, const struct nlist *nl, int options) {
    struct data_sym result;
    uint32_t strx = (uint32_t) nl->n_un.n_strx;
    if(strx >= binary->mach->strsize) {
        die("insane strx: %u", strx);
    }
    result.name = binary->mach->strtab + strx;
    result.address = nl->n_value;
    if((options & TO_EXECUTE) && (nl->n_desc & N_ARM_THUMB_DEF)) {
        result.address |= 1;
    }
    return result;
}

struct nlist *b_macho_nth_symbol(const struct binary *binary, uint32_t n) {
    if(!binary->mach->symtab) {
        die("no symbol table");
    }
    if(n >= binary->mach->nsyms) {
        die("sym too high: %u", sym);
    }
    struct nlist *nl = binary->mach->symtab + n;
    if((uint32_t) nl->n_un.n_strx >= binary->mach->strsize) {
        die("insane strx: %d", (int) nl->n_un.n_strx);
    }
    return nl;
}


static addr_t sym_nlist(const struct binary *binary, const char *name, int options) {
    // I stole dyld's codez
    const struct nlist *base = binary->mach->ext_symtab;
    for(uint32_t n = binary->mach->ext_nsyms; n > 0; n /= 2) {
        const struct nlist *pivot = base + n/2;
        struct data_sym ds = convert_nlist(binary, pivot, options);
        int cmp = strcmp(name, ds.name);
        if(cmp == 0) {
            return ds.address;
        } else if(cmp > 0) {
            base = pivot + 1; 
            n--;
        }
    }

    for(unsigned int i = 0; i < binary->nreexports; i++) {
        addr_t result;
        if(result = b_sym(&binary->reexports[i], name, options)) {
            return result;
        }
    }

    return 0;
}

// ld64
static uint32_t read_uleb128(void **ptr, void *end) {
    uint32_t result = 0;
    uint8_t *p = *ptr;
    uint8_t bit;
    int shift = 0;
    do {
        if(p >= (uint8_t *) end) die("uleb128 overrun");
        bit = *p++;
        uint32_t k = bit & 0x7f;
        if(((k << shift) >> shift) != k) die("uleb128 too big");
        result |= k << shift;
        shift += 7;
    } while(bit & 0x80);
    *ptr = p;
    return result;
}

static inline void *read_bytes(void **ptr, void *end, size_t size) {
    char *p = *ptr;
    if(p == end || (size_t) ((char *) end - p) < size) die("too big");
    *ptr = p + size;
    return p;
}

#define read_int(ptr, end, typ) *((typ *) read_bytes(ptr, end, sizeof(typ)))

static addr_t trie_recurse(const struct binary *binary, void *ptr, char *start, char *end, const char *name0, const char *name, int options) {
    uint8_t terminal_size = read_int(&ptr, end, uint8_t);
    if(terminal_size) {
        uint32_t flags = read_uleb128(&ptr, end);
        uint32_t address = read_uleb128(&ptr, end);
        uint32_t resolver = 0;
        if(flags & 0x10) {
            resolver = read_uleb128(&ptr, end);
        }
        if(!name[0]) {
            if(resolver) {
                fprintf(stderr, "trie_recurse: %s has a resolver; returning failure\n", name0);
                return 0;
            }
            if(flags & 8) {
                // indirect definition
                address--;
                if(address >= binary->nreexports) {
                    die("invalid sub-library %d", address);
                }
                return b_sym(&binary->reexports[address], name0, options);
            }
            if(!(options & TO_EXECUTE)) {
                address &= ~1u;
            }
            return ((addr_t) address) + binary->mach->export_baseaddr;
        }
    }

    uint8_t child_count = read_int(&ptr, end, uint8_t);
    while(child_count--) {
        const char *name2 = name;
        char c;
        while(1) {
            c = read_int(&ptr, end, char);
            if(!c) {
                uint64_t offset = read_uleb128(&ptr, end);
                if(offset >= (size_t) (end - start)) die("invalid child offset");
                return trie_recurse(binary, start + offset, start, end, name0, name2, options);
            }
            if(c != *name2++) {
                break;
            }
        }
        // skip the rest
        do {
            c = read_int(&ptr, end, char);
        } while(c);
        read_uleb128(&ptr, end);
    }
    return 0;
}

static addr_t sym_trie(const struct binary *binary, const char *name, int options) {
    return trie_recurse(binary,
                        binary->mach->export_trie.start,
                        binary->mach->export_trie.start,
                        (char *)binary->mach->export_trie.start + binary->mach->export_trie.size,
                        name,
                        name,
                        options);
}

static addr_t sym_private(const struct binary *binary, const char *name, int options) {
    if(!binary->mach->symtab) {
        die("we wanted %s but there is no symbol table", name);
    }
    const struct nlist *base = binary->mach->symtab;
    for(uint32_t i = 0; i < binary->mach->nsyms; i++) {
        struct data_sym ds = convert_nlist(binary, base + i, options);
        if(!strcmp(ds.name, name)) return ds.address;
    }
    return 0;
}

static addr_t sym_imported(const struct binary *binary, const char *name, __unused int options) {
    // most of this function is copied and pasted from link.c :$
    CMD_ITERATE(binary->mach->hdr, cmd) {
        if(cmd->cmd == LC_SEGMENT) {
            struct segment_command *seg = (void *) cmd;
            struct section *sections = (void *) (seg + 1);
            for(uint32_t i = 0; i < seg->nsects; i++) {
                struct section *sect = &sections[i];
                uint8_t type = sect->flags & SECTION_TYPE;
                if(type != S_NON_LAZY_SYMBOL_POINTERS && type != S_LAZY_SYMBOL_POINTERS) continue;

                uint32_t indirect_table_offset = sect->reserved1;
                uint32_t *indirect = rangeconv_off((range_t) {binary, (addr_t) (binary->mach->dysymtab->indirectsymoff + indirect_table_offset*sizeof(uint32_t)), (sect->size / 4) * sizeof(uint32_t)}, MUST_FIND).start;
                
                for(uint32_t i = 0; i < sect->size / 4; i++) {
                    uint32_t sym = indirect[i];
                    if(sym == INDIRECT_SYMBOL_LOCAL || sym == INDIRECT_SYMBOL_ABS) continue;
                    struct nlist *nl = b_macho_nth_symbol(binary, sym);
                    if(!strcmp(binary->mach->strtab + nl->n_un.n_strx, name)) {
                        return sect->addr + 4*i;
                    }
                }
            }
        }
    }
    return 0;
}

static addr_t sym(const struct binary *binary, const char *name, int options) {
    addr_t (*func)(const struct binary *binary, const char *name, int options);
    if(options & PRIVATE_SYM)
        func = sym_private;
    else if(options & IMPORTED_SYM)
        func = sym_imported;
    else if(binary->mach->export_trie.start)
        func = sym_trie;
    else
        func = sym_nlist;
    return func(binary, name, options & ~MUST_FIND);
}

static void copy_syms(const struct binary *binary, struct data_sym **syms, uint32_t *nsyms, int options) {
    uint32_t n = *nsyms = binary->mach->nsyms;
    struct data_sym *s = *syms = malloc(sizeof(struct data_sym) * n);
    const struct nlist *nl = (options & PRIVATE_SYM) ? binary->mach->symtab : binary->mach->ext_symtab;
    for(uint32_t i = 0; i < ((options & PRIVATE_SYM) ? binary->mach->ext_nsyms : binary->mach->nsyms); i++) {
        *s++ = convert_nlist(binary, nl++, options);
    }
}

void b_macho_store(struct binary *binary, const char *path) {
#define _arg path
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if(fd <= 0) {
        edie("unable to open");
    }
    ssize_t result = write(fd, binary->valid_range.start, binary->valid_range.size);
    if(result < 0 || result != (ssize_t)binary->valid_range.size) {
        edie("couldn't write whole file");
    }
    close(fd);
#undef _arg
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

    return (max + 0xfff) & ~0xfffu;
}


void b_inject_into_macho_fd(const struct binary *binary, int fd, addr_t (*find_hack_func)(const struct binary *binary)) {
    off_t seg_off = lseek(fd, 0, SEEK_END);
    struct mach_header *hdr = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if(hdr == MAP_FAILED) edie("could not mmap hdr in read/write mode");
    if(hdr->sizeofcmds > 0x1000 || hdr->sizeofcmds + sizeof(struct mach_header) > 0x1000) {
        die("too many commands");
    }

    struct segment_command *newseg = (void *) ((char *) (hdr + 1) + hdr->sizeofcmds);
    off_t header_off = (off_t) (sizeof(struct mach_header) + hdr->sizeofcmds);

    uint32_t init_ptrs[100];
    int num_init_ptrs = 0;

    CMD_ITERATE(binary->mach->hdr, cmd) {
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
            hdr->sizeofcmds += (uint32_t) size;

            memcpy(newseg, seg, size);

            seg_off = (seg_off + 0xfff) & ~0xfff;

            newseg->fileoff = (uint32_t) seg_off;
            prange_t pr = rangeconv((range_t) {binary, seg->vmaddr, seg->filesize}, MUST_FIND);
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
                    uint32_t *p = rangeconv((range_t) {binary, sect->addr, sect->size}, MUST_FIND).start;
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
            fprintf(stderr, "note: 1 constructor function is present; using the hack_func\n");
        } else {
            fprintf(stderr, "note: %d constructor functions are present; using the hack_func\n", num_init_ptrs);
        }

        if(!find_hack_func) {
            die("...but there was no find_hack_func");
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
        b_prange_load_macho(&kern, load_fd(fd, false), 0, "kern");
        addr_t hack_func = find_hack_func(&kern);
        fprintf(stderr, "hack_func = %08x\n", hack_func);
        prange_t hack_func_pr = rangeconv((range_t) {&kern, hack_func & ~1, bytes_to_move}, MUST_FIND);
        range_t hack_func_off_range = range_to_off_range((range_t) {&kern, hack_func & ~1, sizeof(part0) + sizeof(uint32_t)}, MUST_FIND);

        // allocate a new segment for the stub

        uint32_t stub_size = (uint32_t) ((sizeof(part1) + 4) * num_init_ptrs + sizeof(part2) + bytes_to_move + sizeof(part3) + 4);

        if(!(hack_func & 1)) {
            die("hack func 0x%x is not thumb", hack_func);
        }


        size_t size = sizeof(struct segment_command);
        if(header_off + size > 0x1000) {
            die("not enough space");
        }

        seg_off = (seg_off + 0xfff) & ~0xfff;
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

        if((size_t) write(fd, hack_func_pr.start, bytes_to_move) != bytes_to_move) {
            edie("couldn't write moved bytes");
        }

        if(write(fd, part3, sizeof(part3)) != sizeof(part3)) {
            edie("couldn't write part3");
        }

        uint32_t new_addr = hack_func + bytes_to_move;

        if(write(fd, &new_addr, sizeof(new_addr)) != sizeof(new_addr)) {
            edie("couldn't write new_addr");
        }
        
        lseek(fd, hack_func_off_range.start, SEEK_SET);

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

range_t b_macho_segrange(const struct binary *binary, const char *segname) {
    CMD_ITERATE(binary->mach->hdr, cmd) {
        if(cmd->cmd == LC_SEGMENT) {
            struct segment_command *seg = (void *) cmd;
            if(!strncmp(seg->segname, segname, 16)) {
                return (range_t) {binary, seg->vmaddr, seg->filesize};
            }
        }
    }
    die("no such segment %s", segname);
}

