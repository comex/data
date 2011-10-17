#include "binary.h"
#include "headers/loader.h"
#include "headers/nlist.h"
#include "headers/fat.h"
#include "read_dyld_info.h"

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
    if(nsegs > MAX_ARRAY(struct data_segment)) {
        die("segment overflow");
    }
    binary->nsegments = nsegs;
    struct data_segment *seg = binary->segments = malloc(sizeof(*binary->segments) * binary->nsegments);
    CMD_ITERATE(hdr, cmd) {
        if(cmd->cmd == LC_SEGMENT) {
            struct segment_command *scmd = (void *) cmd;
            if(scmd->nsects > MAX_ARRAY(struct section) || scmd->cmdsize < sizeof(*scmd) + scmd->nsects * sizeof(struct section)) {
                die("section overflow");
            }
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
            if(scmd->nsyms > MAX_ARRAY(struct data_sym) || scmd->nsyms > MAX_ARRAY(struct nlist)) {
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
    struct dysymtab_command *dc;
    if(binary->mach->symtab && (dc = binary->mach->dysymtab)) {
#define do_it(isym, nsym, x_symtab, x_nsyms) \
        if(dc->isym <= binary->mach->nsyms && dc->nsym <= binary->mach->nsyms - dc->isym && dc->nsym <= MAX_ARRAY(struct nlist) && dc->nsym <= MAX_ARRAY(struct data_sym)) { \
            binary->mach->x_symtab = binary->mach->symtab + dc->isym; \
            binary->mach->x_nsyms = dc->nsym; \
        } else { \
            fprintf(stderr, "warning: bad %s/%s (%u, %u)\n", #isym, #nsym, dc->isym, dc->nsym); \
        }
        do_it(iextdefsym, nextdefsym, ext_symtab, ext_nsyms)
        do_it(iundefsym, nundefsym, imp_symtab, imp_nsyms)
#undef do_it
    } else {
        binary->mach->ext_symtab = binary->mach->symtab;
        binary->mach->ext_nsyms = binary->mach->nsyms;
    }
}

void b_prange_load_macho(struct binary *binary, prange_t pr, size_t offset, const char *name) {
    b_prange_load_macho_nosyms(binary, pr, offset, name);
    do_symbols(binary);
    binary->_sym = sym;
    binary->_copy_syms = copy_syms;
}

void b_prange_load_macho_nosyms(struct binary *binary, prange_t pr, size_t offset, const char *name) {
#define _arg name
    binary->valid = true;
    binary->mach = calloc(sizeof(*binary->mach), 1);

    binary->valid_range = pr;
    binary->header_offset = offset;

    if(offset >= pr.size || offset - pr.size < sizeof(struct mach_header)) {
        die("not enough room");
    }

    struct mach_header *hdr = pr.start + offset;
    if(hdr->magic == MH_MAGIC) {
        // thin file
        binary->mach->hdr = hdr;
        /*if(hdr->cputype != desired_cputype || (hdr->cpusubtype != 0 && desired_cpusubtype != 0 && hdr->cpusubtype != desired_cpusubtype)) {
            die("thin file doesn't have the right architecture");
        }*/
    } else if(hdr->magic == FAT_CIGAM) {
        if(offset) die("fat, offset != 0");

        struct fat_header *fathdr = (void *) hdr;
        struct fat_arch *arch = (void *)(fathdr + 1);
        uint32_t nfat_arch = SWAP32(fathdr->nfat_arch);
        if((pr.size - sizeof(struct fat_header)) / sizeof(struct fat_arch) < nfat_arch) {
            die("fat header is too small");
        }
        binary->mach->hdr = NULL;
        while(nfat_arch--) {
            if(SWAP32(arch->cputype) == desired_cputype && (arch->cpusubtype == 0 || desired_cpusubtype == 0 || SWAP32(arch->cpusubtype) == desired_cpusubtype)) {
                uint32_t fat_offset = SWAP32(arch->offset);
                if(fat_offset >= pr.size || pr.size - fat_offset < sizeof(struct mach_header)) {
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

static addr_t trie_recurse(const struct binary *binary, void *ptr, char *start, char *end, const char *name0, const char *name, int options) {
    if(start == end) return 0;
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
    uint32_t n;
    const struct nlist *nl;
    bool can_be_zero = false;
    if(options & PRIVATE_SYM) {
        nl = binary->mach->symtab;
        n = binary->mach->nsyms;
    } else if(options & IMPORTED_SYM) {
        nl = binary->mach->imp_symtab;
        n = binary->mach->imp_nsyms;
        can_be_zero = true;
    } else {
        nl = binary->mach->ext_symtab;
        n = binary->mach->ext_nsyms;
    }
    struct data_sym *s = *syms = malloc(sizeof(struct data_sym) * n);
    for(uint32_t i = 0; i < n; i++) {
        *s = convert_nlist(binary, nl++, options);
        if(can_be_zero || s->address) s++;
    }
    *nsyms = s - *syms;
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

range_t b_macho_sectrange(const struct binary *binary, const char *segname, const char *sectname) {
    CMD_ITERATE(binary->mach->hdr, cmd) {
        if(cmd->cmd == LC_SEGMENT) {
            struct segment_command *seg = (void *) cmd;
            if(!strncmp(seg->segname, segname, 16)) {
                struct section *sect = (void *) (seg + 1);
                for(uint32_t i = 0; i < seg->nsects; i++) {
                    if(!strncmp(sect[i].sectname, sectname, 16)) {
                        return (range_t) {binary, sect->addr, sect->size};
                    }
                }
            }
        }
    }
    die("no such segment %s", segname);
}

void b_load_macho(struct binary *binary, const char *filename) {
    return b_prange_load_macho(binary, load_file(filename, true, NULL), 0, filename);
}

addr_t b_macho_reloc_base(const struct binary *binary) {
    // copying dyld's behavior
    CMD_ITERATE(binary->mach->hdr, cmd) {
        if(cmd->cmd == LC_SEGMENT) {
            struct segment_command *seg = (void *) cmd;
            if(binary->mach->hdr->cputype != 0x01000007 /* CPU_TYPE_X86_64 */ || (seg->initprot & PROT_WRITE)) {
                return seg->vmaddr;
            }
        }
    }
    die("no segments");
}
