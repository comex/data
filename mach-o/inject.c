#include "binary.h"

struct linkedit_info {
    arange_t linkedit_range;
    void *linkedit_ptr;

    // things we need to move:
    // 0. string table
    // 1-3. {local, extdef, undef}sym
    // 4-5. {locrel, extrel}
    // 6. indirect syms
    // [hey, I will just assume that nobody has any section relocations because it makes things simpler!]
    // things we need to update:
    // - symbols reference string table
    // - relocations reference symbols
    // - indirect syms reference symbols
    // - (section data references indirect syms)
#define NMOVEME 7
    struct moveme {
        uint32_t *off, *size;
        uint32_t size_divider;
    } moveme[NMOVEME];

    struct symtab_command *symtab;
    struct dysymtab_command *dysymtab;
};

static const struct moveref {
    int target_start, target_end;
    ptrdiff_t offset;
} moveref[NMOVEME] = {
    /* 0 */   {-1, -1, 0},
    /* 1-3 */ {0, 0, offsetof(struct nlist, n_un.n_strx)},
              {0, 0, offsetof(struct nlist, n_un.n_strx)},
              {0, 0, offsetof(struct nlist, n_un.n_strx)},
              // hooray for little endian
    /* 4-5 */ {1, 3, offsetof(struct relocation_info, r_symbolnum},
              {1, 3, offsetof(struct relocation_info, r_symbolnum},
              // the whole thing is a symbol number
    /* 6 */   {1, 3, 0}
};


static bool catch_linkedit(struct mach_header *hdr, struct linkedit_info *li) {
    memset(li, 0, sizeof(*li));
    bool ret = false;
    CMD_ITERATE(hdr, cmd) {
        switch(cmd->cmd) {
        case LC_SEGMENT: {
            struct segment_command *seg = (void *) cmd;
            if(!strcmp(seg->segname, "__LINKEDIT")) {
                li->linkedit_range.start = seg->fileoff;
                li->linkedit_range.size = seg->filesize;
                ret = true;
                cmd->cmd = 0x1000;
                break;
            }

            break;
        }
        case LC_SYMTAB: {
            struct symtab_command *symtab = (void *) cmd;
            li->symtab = symtab;

            li->moveme[0].off = &symtab->stroff;
            li->moveme[0].size = &symtab->strsize;
            li->moveme[0].size_divider = 1;

            break;
        case LC_DYSYMTAB: {
            struct dysymtab_command *dys = (void *) cmd;
            li->dysymtab = dys;

            li->moveme[1].off = &dys->ilocalsym;
            li->moveme[1].size = &dys->nlocalsym;
            li->moveme[1].size_divider = sizeof(struct nlist);

            li->moveme[2].off = &dys->iextdefsym;
            li->moveme[2].size = &dys->nextdefsym;
            li->moveme[2].size_divider = sizeof(struct nlist);

            li->moveme[3].off = &dys->iundefsym;
            li->moveme[3].size = &dys->nundefsym;
            li->moveme[3].size_divider = sizeof(struct nlist);

            li->moveme[4].off = &dys->locreloff;
            li->moveme[4].size = &dys->nlocrel;
            li->moveme[4].size_divider = sizeof(struct relocation_info);

            li->moveme[5].off = &dys->extreloff;
            li->moveme[5].size = &dys->nextrel;
            li->moveme[5].size_divider = sizeof(struct relocation_info);

            li->moveme[6].off = &dys->indirectsymoff;
            li->moveme[6].size = &dys->nindirectsyms;
            li->moveme[6].size_divider = 4;

            break;
        }
        case LC_DYLD_INFO_ONLY:
        case LC_DYLD_INFO:
        case LC_CODE_SIGNATURE:
        case LC_SEGMENT_SPLIT_INFO:
        case LC_FUNCTION_STARTS:
            // hope you didn't need that stuff <3
            cmd->cmd = 0x1000;
            break;
        }
    }
    // we want both binaries to have a symtab and dysymtab, makes things easier
    if(!li->symtab || !li->dysymab) die("symtab/dysymtab missing");
    return ret;
}

void b_inject_into_macho_fd(const struct binary *binary, int fd, addr_t (*find_hack_func)(const struct binary *binary), bool userland) {

#define ADD_COMMAND(size) ({ \
        uint32_t header_off = sizeof(struct mach_header) + hdr->sizeofcmds; \
        if(header_off + (size) > 0x1000) { \
            die("not enough space"); \
        } \
        hdr->ncmds++; \
        void *ret = (char *) hdr + header_off; \
        hdr->sizeofcmds += (uint32_t) (size); \
        ret; \
    })

#define ADD_SEGMENT(size) ({ \
        uint32_t ret = (seg_off + 0xfff) & ~0xfff; \
        seg_off = ret + (size); \
        lseek(fd, seg_off, SEEK_SET); \
        ret; \
    })

#define ADD_SEGMENT_ADDR(size) ({ \
        uint32_t ret = (seg_addr + 0xfff) & ~0xfff; \
        seg_addr = ret + (size); \
        ret; \
    })
        
    off_t seg_off = lseek(fd, 0, SEEK_END);
    addr_t seg_addr = 0;

    struct mach_header *hdr = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if(hdr == MAP_FAILED) edie("could not mmap hdr in read/write mode");
    if(hdr->sizeofcmds > 0x1000 || hdr->sizeofcmds + sizeof(struct mach_header) > 0x1000) {
        die("too many commands");
    }
    
    // in userland mode, we cut off the LINKEDIT segment  (for target, only if it's at the end of the binary)
    struct linkedit_info li[2];
    if(userland) {
        if(catch_linkedit(binary->mach->hdr, &li[0])) {
            load_li.linkedit_ptr = rangeconv_off((range_t) {binary, li[0].linkedit_range.start, li[0].linkedit_range.size});
        }
        if(catch_linkedit(hdr, &li[1])) {
            li[1].linkedit_base = mmap(NULL, li[1].linkedit_range.size, PROT_READ, MAP_PRIVATE, fd, li[1].linkedit_range.start);
            if(li[1].linkedit_base == MAP_FAILED) edie("could not map target __LINKEDIT");
            if(li[1].linkedit_range.start + li[1].linkedit_range.size == seg_off) {
                seg_off = li[1].linkedit_range.start;
                ftruncate(fd, seg_off);
            }
        }
    }

    off_t header_off = (off_t) (sizeof(struct mach_header) + hdr->sizeofcmds);

    uint32_t init_ptrs[100];
    int num_init_ptrs = 0;
    uint32_t *reserved1s[100];
    int num_reserved1s = 0;

    if(userland) {
        CMD_ITERATE(hdr, cmd) {
            if(cmd->cmd == LC_SEGMENT) {
                struct segment_command *seg = (void *) cmd;
                struct section *sections = (void *) (seg + 1);
                for(uint32_t i = 0; i < seg->nsects; i++) {
                    struct section *sect = &sections[i];
                    switch(sect->flags & SECTION_TYPE) {
                    case S_NON_LAZY_SYMBOL_POINTERS:
                    case S_LAZY_SYMBOL_POINTERS:
                        if(num_reserved1s < 100) reserved1s[num_reserved1s++] = &sect->reserved1;
                        break;
                    }
                }
            }
        }
    }

    CMD_ITERATE(binary->mach->hdr, cmd) {
        if(cmd->cmd == LC_SEGMENT) {
            struct segment_command *seg = (void *) cmd;
            size_t size = sizeof(struct segment_command) + seg->nsects * sizeof(struct section);
            if(size != seg->cmdsize) {
                die("inconsistent cmdsize");
            }

            // make seg_addr useful
            addr_t new_addr = seg->vmaddr + seg->vmsize;
            if(new_addr > seg_addr) seg_addr = new_addr;

            struct segment_command *newseg = ADD_COMMAND(size);
            memcpy(newseg, seg, size);
            prange_t pr = rangeconv_off((range_t) {binary, seg->fileoff, seg->filesize}, MUST_FIND);

            newseg->fileoff = (uint32_t) ADD_SEGMENT(pr.size);
            printf("setting fileoff to %u\n", newseg->fileoff);
            if((size_t) pwrite(fd, pr.start, pr.size, newseg->fileoff) != pr.size) {
                die("couldn't write additional segment");
            }

            header_off += size;
            
            if(!userland) {
                struct section *sections = (void *) (seg + 1);
                for(uint32_t i = 0; i < seg->nsects; i++) {
                    struct section *sect = &sections[i];
                    // ZEROFILL is okay because iBoot always zeroes vmsize - filesize
                    if((sect->flags & SECTION_TYPE) == S_MOD_INIT_FUNC_POINTERS) {
                        uint32_t *p = rangeconv_off((range_t) {binary, sect->offset, sect->size}, MUST_FIND).start;
                        size_t num = sect->size / 4;
                        while(num--) {
                            if(num_init_ptrs < 100) init_ptrs[num_init_ptrs++] = *p++;
                        }
                    }
                }
            }
        }
    }


    // now deal with the init pointers (if not userland)
    // this code is really gross
    if(num_init_ptrs > 0) {
        if(num_init_ptrs == 1) { // hey, correct plurals are nice
            fprintf(stderr, "note: 1 constructor function is present; using the hack_func\n");
        } else {
            fprintf(stderr, "note: %d constructor functions are present; using the hack_func\n", num_init_ptrs);
        }

        if(!find_hack_func) {
            die("...but there was no find_hack_func");
        }
        
        // ldr pc, [pc]
        uint16_t part0[] = {0xf8df, 0xf000};

        // push {r0-r3, lr}; adr lr, f+1; ldr pc, a; f: b next; a: .long 0; next:
        // (the address of the init func)
        // 
        uint16_t part1[] = {0xb50f, 0xf20f, 0x0e07, 0xf8df, 0xf004, 0xe001};
        // (bytes_to_move bytes of stuff)
        // pop {r0-r3, lr}
        static const uint16_t part2[] = {0xe8bd, 0x400f};
        // ldr pc, [pc]
        static const uint16_t part3[] = {0xf8df, 0xf000};

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

        struct segment_command *newseg = ADD_COMMAND(sizeof(struct segment_command));
        
        newseg->cmd = LC_SEGMENT;
        newseg->cmdsize = sizeof(struct segment_command);
        memset(newseg->segname, 0, 16);
        strcpy(newseg->segname, "__CRAP");
        newseg->vmaddr = ADD_SEGMENT_ADDR(stub_size);
        newseg->vmsize = stub_size;
        newseg->fileoff = ADD_SEGMENT(stub_size);
        newseg->filesize = stub_size;
        newseg->maxprot = newseg->initprot = PROT_READ | PROT_EXEC;
        newseg->nsects = 0;
        newseg->flags = 0;

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

    if(userland) {
        // build the new LINKEDIT
        uint32_t newsize = 0;
        for(int i = 0; i < NMOVEME; i++) {
            for(int l = 0; l < 2; l++) {
                newsize += *li[l].moveme[i].size;
            }
        }

        if(newsize != 0) {
            uint32_t linkedit_off = ADD_SEGMENT(newsize);
            autofree char *linkedit = malloc(newsize);
            uint32_t off = 0;
            for(int i = 0; i < NMOVEME; i++) {
                uint32_t s = 0;
                for(int l = 0; l < 2; l++) {
                    struct moveme *m = &li[l].moveme[i];
                    uint32_t to_copy = *m->size * m->size_divder;
                    memcpy(linkedit + off + s, li[l].linkedit_ptr + (*m->off - li[l].linkedit_range.start), to_copy);
                    if(l == 1 && i > 0) {
                        // update references in this struct
                        for(char *ptr = linkedit + off + s; ptr < linkedit + off + s + to_copy; ptr += m->size_divider) {
                            uint32_t diff = 0;
                            for(uint32_t j = moveref[i].target_start; j <= moveref[i].target_end; j++) {
                                diff += li[0].moveme[j].size;
                            }
                            *((uint32_t *) (ptr + moveref[i].offset)) += diff;
                        }
                    }
                    s += to_copy;
                }
                // update the one to load
                struct moveme *m = &li[1].moveme[i];
                *m->off = linkedit_off + off;
                *m->size = s / *m->size_divider;

                off += s;
            }

            // that's nice, but now we need to fix the symtab commands...
            uint32_t symoff = li[1].dysymtab->ilocalsym;
            li[1].symtab->symoff = symoff;
            li[1].symtab->nsyms = (li[1].dysymtab->locreloff - symoff) / sizeof(struct nlist);
            li[1].dysymtab->ilocalsym -= symoff;
            li[1].dysymtab->iextdefsym -= symoff;
            li[1].dysymtab->iundefsym -= symoff;

            // ... and update section references
            for(int i = 0; i < num_reserved1s; i++) {
                *reserved1s[i] += li[0].moveme[6].size;
            }

            struct segment_command *newseg = ADD_COMMAND(sizeof(struct segment_command));
            newseg->cmd = LC_SEGMENT;
            newseg->cmdsize = sizeof(struct seegment_command);
            memset(newseg->segname, 0, 16);
            strcpy(newsg->segname, "__LINKEDIT");
            newseg->vmaddr = ADD_SEGMENT_ADDR(newsize);
            newseg->vmsize = newsize;
            newseg->fileoff = linkedit_off;
            newseg->filesize = newsize;
            newseg->maxprot = newseg->initprot = PROT_READ | PROT_WRITE;
            newseg->nsects = 0;
            newseg->flags = 0;
        }
        
        if(target_linkedit_base) munmap(target_linkedit_base);
    }

    munmap(hdr, 0x1000);
}

