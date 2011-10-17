#include "inject.h"
#include "read_dyld_info.h"
#include "headers/loader.h"
#include "headers/nlist.h"
#include "headers/reloc.h"
#include <stddef.h>

struct linkedit_info {
    arange_t linkedit_range;
    void *linkedit_ptr;

    // things we need to move:
    // 0. string table
    // 1-3. {local, extdef, undef}sym
    // 4-5. {locrel, extrel}
    // 6. indirect syms
    // 7-9. dyld info {, weak_, lazy_}bind
    // [hey, I will just assume that nobody has any section relocations because it makes things simpler!]
    // things we need to update:
    // - symbols reference string table
    // - relocations reference symbols
    // - indirect syms reference symbols
    // - (section data references indirect syms)
#define NMOVEME 10
    struct moveme {
        uint32_t *off, *size;
        uint32_t off_base;
        uint32_t size_divider;
        //uint32_t orig_size;
    } moveme[NMOVEME];

    struct symtab_command *symtab;
    struct dysymtab_command *dysymtab;
    struct dyld_info_command *dyld_info;
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
    /* 4-5 */ {1, 3, 4},
              {1, 3, 4},
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
        }
        case LC_DYSYMTAB: {
            struct dysymtab_command *dys = (void *) cmd;
            li->dysymtab = dys;

            li->moveme[1].off = &dys->ilocalsym;
            li->moveme[1].size = &dys->nlocalsym;
            li->moveme[1].off_base = li->symtab->symoff;
            li->moveme[1].size_divider = sizeof(struct nlist);

            li->moveme[2].off = &dys->iextdefsym;
            li->moveme[2].size = &dys->nextdefsym;
            li->moveme[2].off_base = li->symtab->symoff;
            li->moveme[2].size_divider = sizeof(struct nlist);

            li->moveme[3].off = &dys->iundefsym;
            li->moveme[3].size = &dys->nundefsym;
            li->moveme[3].off_base = li->symtab->symoff;
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
        case LC_DYLD_INFO: {
            struct dyld_info_command *di = (void *) cmd;
            li->dyld_info = di;

            di->rebase_off = 0;
            di->rebase_size = 0;

            li->moveme[7].off = &di->bind_off;
            li->moveme[7].size = &di->bind_size;
            li->moveme[7].size_divider = 1;

            li->moveme[8].off = &di->weak_bind_off;
            li->moveme[8].size = &di->weak_bind_size;
            li->moveme[8].size_divider = 1;

            li->moveme[9].off = &di->lazy_bind_off;
            li->moveme[9].size = &di->lazy_bind_size;
            li->moveme[9].size_divider = 1;
            break;
        }
        case LC_CODE_SIGNATURE:
        case LC_SEGMENT_SPLIT_INFO:
        case 38 /*LC_FUNCTION_STARTS*/:
            // hope you didn't need that stuff <3
            cmd->cmd = 0x1000;
            break;
        }
        // xxx - this should be immutable but we are overwriting it
    }
    // we want both binaries to have a symtab and dysymtab, makes things easier
    if(!li->symtab || !li->dysymtab) die("symtab/dysymtab missing");
    return ret;
}

static void handle_retarded_dyld_info(void *ptr, uint32_t size, int num_segments, bool kill_dones) {
    // seriously, take a look at dyldinfo.cpp from ld64, especially, in this case, the separate handing of different LC_DYLD_INFO sections and the different meaning of BIND_OPCODE_DONE in lazy bind vs the other binds
    // not to mention the impossibility of reading this data without knowing every single opcode
    // and the lack of nop
    void *end = ptr + size;
    while(ptr != end) { 
        uint8_t byte = read_int(&ptr, end, uint8_t);
        uint8_t immediate = byte & BIND_IMMEDIATE_MASK;
        uint8_t opcode = byte & BIND_OPCODE_MASK;
        char c;
        switch(opcode){
        // things we actually care about:
        case BIND_OPCODE_DONE:
            if(kill_dones) {
                *((uint8_t *) ptr - 1) = BIND_OPCODE_SET_TYPE_IMM | BIND_TYPE_POINTER;
            }
            break;
        case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: {
            // update the segment number
            uint8_t *p = ptr - 1;
            printf("incr'ing %u by %u\n", (unsigned int) immediate, (unsigned int) num_segments);
            *p = (*p & BIND_OPCODE_MASK) | (immediate + num_segments);
            read_uleb128(&ptr, end);
            break;
        }
        // things we have to get through
        case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
            do {
                c = read_int(&ptr, end, char);
            } while(c);
            break;
        case BIND_OPCODE_SET_ADDEND_SLEB: // actually sleb (and I like how read_uleb128 and read_sleb128 in dyldinfo.cpp are completely separate functions), but read_uleb128 should work
        case BIND_OPCODE_ADD_ADDR_ULEB:
        case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
            read_uleb128(&ptr, end);
            break;

        case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
            read_uleb128(&ptr, end);
            read_uleb128(&ptr, end);
            break;
        }
    }
}

// this is only meaningful on i386
static void fixup_stub_helpers(void *base, size_t size, uint32_t incr) {
    while(size >= 0xa + 0xa) {
        *((uint32_t *) (base + 1)) += incr; 
        base += 0xa;
        size -= 0xa;
    }
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
            li[0].linkedit_ptr = rangeconv_off((range_t) {binary, li[0].linkedit_range.start, li[0].linkedit_range.size}, MUST_FIND).start;
        }
        if(catch_linkedit(hdr, &li[1])) {
            li[1].linkedit_ptr = mmap(NULL, li[1].linkedit_range.size, PROT_READ, MAP_PRIVATE, fd, li[1].linkedit_range.start);
            if(li[1].linkedit_ptr == MAP_FAILED) edie("could not map target __LINKEDIT");
            if((off_t) (li[1].linkedit_range.start + li[1].linkedit_range.size) == seg_off) {
                seg_off = li[1].linkedit_range.start;
                ftruncate(fd, seg_off);
            }
        }
        if((li[0].dyld_info != 0) != (li[1].dyld_info != 0)) {
            die("LC_DYLD_INFO(_ONLY) should be in both or neither");
        }
    }

    off_t header_off = (off_t) (sizeof(struct mach_header) + hdr->sizeofcmds);

    uint32_t init_ptrs[100];
    int num_init_ptrs = 0;
    uint32_t *reserved1s[100];
    int num_reserved1s = 0;

    int num_segments;
    if(userland) {
        num_segments = 0;
        CMD_ITERATE(hdr, cmd) {
            if(cmd->cmd == LC_SEGMENT) {
                num_segments++;
                struct segment_command *seg = (void *) cmd;
                struct section *sections = (void *) (seg + 1);
                for(uint32_t i = 0; i < seg->nsects; i++) {
                    struct section *sect = &sections[i];
                    switch(sect->flags & SECTION_TYPE) {
                    case S_NON_LAZY_SYMBOL_POINTERS:
                    case S_LAZY_SYMBOL_POINTERS:
                    case S_SYMBOL_STUBS:
                        if(num_reserved1s < 100) reserved1s[num_reserved1s++] = &sect->reserved1;
                        break;
                    }

                    // xxx - what happens if there is no dyld_info?
                    if(li[0].dyld_info && !strcmp(sect->sectname, "__stub_helper")) {
                        void *segdata = mmap(NULL, seg->filesize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, seg->fileoff);
                        if(segdata == MAP_FAILED) edie("could not map stub_helper");
                        fixup_stub_helpers(segdata + sect->offset - seg->fileoff, sect->size, *li[0].moveme[9].size);
                        munmap(segdata, seg->filesize);
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
            
            struct section *sections = (void *) (newseg + 1);
            for(uint32_t i = 0; i < seg->nsects; i++) {
                struct section *sect = &sections[i];
                sect->offset = newseg->fileoff + sect->addr - newseg->vmaddr;
                // ZEROFILL is okay because iBoot always zeroes vmsize - filesize
                if(!userland && (sect->flags & SECTION_TYPE) == S_MOD_INIT_FUNC_POINTERS) {
                    uint32_t *p = rangeconv_off((range_t) {binary, sect->offset, sect->size}, MUST_FIND).start;
                    size_t num = sect->size / 4;
                    while(num--) {
                        if(num_init_ptrs < 100) init_ptrs[num_init_ptrs++] = *p++;
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
                newsize += *li[l].moveme[i].size * li[l].moveme[i].size_divider;
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
                    //m->orig_size = *m->size;
                    uint32_t to_copy = *m->size * m->size_divider;
                    memcpy(linkedit + off + s, li[l].linkedit_ptr - li[l].linkedit_range.start + *m->off * (m->off_base ? m->size_divider : 1) + m->off_base, to_copy);
                    if(l == 1 && (i >= 1 && i <= 6)) {
                        // update references in this struct
                        for(char *ptr = linkedit + off + s; ptr < linkedit + off + s + to_copy; ptr += m->size_divider) {
                            uint32_t diff = 0;
                            for(int j = moveref[i].target_start; j <= moveref[i].target_end; j++) {
                                diff += *li[0].moveme[j].size;
                            }
                            *((uint32_t *) (ptr + moveref[i].offset)) += diff;
                        }
                    }
                    s += to_copy;
                }
                printf("i=%d s=%u off=%u\n", i, s, off);
                // update the one to load
                struct moveme *m = &li[1].moveme[i];
                *m->off = linkedit_off + off; // hack hack
                *m->size = s / m->size_divider;

                off += s;
            }

            // that's nice, but now we need to fix the symtab commands...
            uint32_t symoff = li[1].dysymtab->ilocalsym;
            li[1].symtab->symoff = symoff;
            li[1].symtab->nsyms = (li[1].dysymtab->locreloff - symoff) / sizeof(struct nlist);
            // hack
            li[1].dysymtab->ilocalsym = (li[1].dysymtab->ilocalsym - symoff) / sizeof(struct nlist);
            li[1].dysymtab->iextdefsym = (li[1].dysymtab->iextdefsym - symoff) / sizeof(struct nlist);
            li[1].dysymtab->iundefsym = (li[1].dysymtab->iundefsym - symoff) / sizeof(struct nlist);

            // ... and update section references
            for(int i = 0; i < num_reserved1s; i++) {
                *reserved1s[i] += *li[0].moveme[6].size;
            }

            // ... and dyld info
            if(li->dyld_info) {
                for(int i = 7; i <= 9; i++) {
                    printf("%d\n", i);
                    if(*li[1].moveme[i].off) {
                        handle_retarded_dyld_info(linkedit - linkedit_off + *li[1].moveme[i].off, *li[0].moveme[i].size, num_segments, i != 9);
                    }
                }
            }

            struct segment_command *newseg = ADD_COMMAND(sizeof(struct segment_command));
            newseg->cmd = LC_SEGMENT;
            newseg->cmdsize = sizeof(struct segment_command);
            memset(newseg->segname, 0, 16);
            strcpy(newseg->segname, "__LINKEDIT");
            newseg->vmaddr = ADD_SEGMENT_ADDR(newsize);
            newseg->vmsize = newsize;
            newseg->fileoff = linkedit_off;
            newseg->filesize = newsize;
            newseg->maxprot = newseg->initprot = PROT_READ | PROT_WRITE;
            newseg->nsects = 0;
            newseg->flags = 0;

            printf("off=%d newsize=%d\n", linkedit_off, newsize);
            pwrite(fd, linkedit, newsize, linkedit_off);
        }
        
        if(li[1].linkedit_ptr) munmap(li[1].linkedit_ptr, li[1].linkedit_range.size);
    }

    munmap(hdr, 0x1000);
}

