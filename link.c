#include "link.h"
#include "find.h"
#include "loader.h"
#include "nlist.h"
#include "reloc.h"
#include <assert.h>

uint32_t b_find_sysent(const struct binary *binary) {
    static const struct binary *last_binary; static uint32_t last_sysent;
    if(last_binary != binary) {
        last_binary = binary;
        last_sysent = find_int32(b_macho_segrange(binary, "__DATA"), 0x861000, true) + 4;
    }
    return last_sysent;
}

// gigantic hack
uint32_t b_lookup_sym(const struct binary *binary, char *sym) {
    if(!strcmp(sym, "_sysent")) {
        return b_find_sysent(binary);
    }

    if(sym[0] == '$' && sym[1] == 'b' && sym[2] == 'l' && sym[4] == '_') {
        uint32_t func = b_sym(binary, sym + 5, true);
        range_t range = (range_t) {binary, func, 0x1000};
        int number = sym[3] - '0';
        uint32_t bl = 0;
        while(number--) bl = find_bl(&range);
        if(!bl) {
            die("no bl for %s", sym);
        }
        return bl;
    }
    if(sym[0] == '$' && sym[1] == '_') {
        // lol...
        char *to_find = malloc(strlen(sym)+1);
        char *p = to_find;
        while(1) {
            char c = *sym++;
            switch(c) {
            case '$': c = '-'; break;
            case '_': c = ' '; break;
            case 'X': c = '.'; break;
            }
            *p++ = c;
            if(!c) break;
        }
        uint32_t result = find_data(b_macho_segrange(binary, "__TEXT"), to_find, 0, true);
        free(to_find);
        return result;
    }
    return b_sym(binary, sym, true);
}

static void relocate_area(const struct binary *binary, uint32_t reloc_base, uint32_t slide, uint32_t reloff, uint32_t nreloc) {
    struct relocation_info *things = rangeconv_off((range_t) {binary, reloff, nreloc * sizeof(struct relocation_info)}).start;
    for(int i = 0; i < nreloc; i++) {
        assert(!things[i].r_pcrel);
        assert(things[i].r_length == 2);
        assert(things[i].r_type == 0);
        uint32_t thing = reloc_base + things[i].r_address;
        uint32_t *p = rangeconv((range_t) {binary, thing, 4}).start;
        if(things[i].r_extern) {
            uint32_t sym = b_lookup_sym(binary, binary->strtab + binary->symtab[things[i].r_symbolnum].n_un.n_strx);
            *p += sym;
        } else {
            // *shrug*
            *p += slide;
        }
    }
}

void b_relocate(struct binary *binary, uint32_t slide) {
    CMD_ITERATE(binary->mach_hdr, cmd) {
        switch(cmd->cmd) {
        case LC_SYMTAB:
        case LC_DYSYMTAB:
        case LC_SEGMENT:
        case LC_ID_DYLIB:
        case LC_UUID:
            break;
        default:
            die("unrecognized load command %08x", cmd->cmd);
        }
    }
    assert(binary->symtab);
    assert(binary->dysymtab);
    
    addr_t reloc_base = 0;
    CMD_ITERATE(binary->mach_hdr, cmd) {
        if(cmd->cmd == LC_SEGMENT) {
            struct segment_command *seg = (void *) cmd;
            reloc_base = seg->vmaddr;
        }
    }
    assert(reloc_base);

    relocate_area(binary, reloc_base, slide, binary->dysymtab->locreloff, binary->dysymtab->nlocrel);
    relocate_area(binary, reloc_base, slide, binary->dysymtab->extreloff, binary->dysymtab->nextrel);

    CMD_ITERATE(binary->mach_hdr, cmd) {
        if(cmd->cmd == LC_SEGMENT) {
            struct segment_command *seg = (void *) cmd;
            binary->last_seg = seg;
            printf("%.16s %08x\n", seg->segname, seg->vmaddr);
            struct section *sections = (void *) (seg + 1);
            for(int i = 0; i < seg->nsects; i++) {
                struct section *sect = &sections[i];
                printf("   %.16s\n", sect->sectname);
                uint8_t type = sect->flags & SECTION_TYPE;
                switch(type) {
                case S_NON_LAZY_SYMBOL_POINTERS:
                case S_LAZY_SYMBOL_POINTERS: {
                    uint32_t indirect_table_offset = sect->reserved1;
                    uint32_t *indirect = rangeconv_off((range_t) {binary, binary->dysymtab->indirectsymoff + indirect_table_offset*sizeof(uint32_t), (sect->size / 4) * sizeof(uint32_t)}).start;
                    uint32_t *things = rangeconv((range_t) {binary, sect->addr, sect->size}).start;
                    for(int i = 0; i < sect->size / 4; i++) {
                        uint32_t sym = indirect[i];
                        switch(sym) {
                        case INDIRECT_SYMBOL_LOCAL:
                            things[i] += slide;
                            break;
                        case INDIRECT_SYMBOL_ABS:
                            break;
                        default:
                            if(sym >= binary->nsyms) {
                                die("sym too high: %u", sym);
                            }
                            things[i] = b_lookup_sym(binary, binary->strtab + binary->symtab[sym].n_un.n_strx);
                        }
                    }
                    break;
                }
                case S_MOD_TERM_FUNC_POINTERS:
                    // be helpful for the unload later
                    sect->reserved2 = b_find_sysent(binary);
                    break;
                case S_ZEROFILL:
                case S_MOD_INIT_FUNC_POINTERS:
                case S_REGULAR:
                case S_SYMBOL_STUBS:
                case S_CSTRING_LITERALS:
                case S_4BYTE_LITERALS:
                case S_8BYTE_LITERALS:
                case S_16BYTE_LITERALS:
                    break;
                default:
                    die("unrecognized section type %02x", type);
                }
                
                // XXX: are these relocations unique, or listed also in the dysymtab?
                // until I get one, I won't bother finding out
                assert(sect->nreloc == 0);

                relocate_area(binary, slide, reloc_base, sect->reloff, sect->nreloc);
                sect->addr += slide;
            }
            seg->vmaddr += slide;
        }
    }
}

