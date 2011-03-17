#include "link.h"
#include "find.h"
#include "loader.h"
#include "nlist.h"
#include "reloc.h"
#include <assert.h>
#include <ctype.h>

uint32_t b_find_sysent(const struct binary *binary) {
    static const struct binary *last_binary; static uint32_t last_sysent;
    if(last_binary != binary) {
        last_binary = binary;
        last_sysent = find_int32(b_macho_segrange(binary, "__DATA"), 0x861000, true) + 4;
    }
    return last_sysent;
}

// gigantic hack
uint32_t b_lookup_sym(const struct binary *binary, const char *sym, bool must_find) {
    if(!strcmp(sym, "_sysent")) {
        return b_find_sysent(binary);
    }

    // $t_XX_XX -> find "+ XX XX" in TEXT
    if(sym[0] == '$' && ((sym[1] == 't' && sym[2] == '_') || sym[1] == '_')) {
        // lol...
        char *to_find = malloc(strlen(sym)+1);
        char *p = to_find;
        while(1) {
            char c = *sym++;
            switch(c) {
            case '$': if(*sym == 't') { c = '+'; sym++; } else { c = '-'; } break;
            case '_': c = ' '; break;
            case 'X': c = '.'; break;
            }
            *p++ = c;
            if(!c) break;
        }
        uint32_t result = find_data(b_macho_segrange(binary, "__TEXT"), to_find, 0, must_find);
        free(to_find);
        return result;
    }
    
    // $vt_<name> -> find offset to me from the corresponding vtable 
    // ex: __ZN11OSMetaClass20getMetaClassWithNameEPK8OSSymbol
    if(!strncmp(sym, "$vt_", 4)) {
        sym += 4;
        uint32_t the_func = b_lookup_sym(binary, sym, must_find);
        if(!the_func) return 0;

        // find the class, and construct its vtable name
        while(*sym && !isnumber(*sym)) sym++;
        char *class;
        unsigned int len = (unsigned int) strtol(sym, &class, 10) + (class - sym);
        assert(len > 0 && len <= strlen(sym));
        char *vt_name = malloc(len + 6);
        memcpy(vt_name, "__ZTV", 5);
        memcpy(vt_name + 5, sym, len);
        vt_name[len + 5] = 0;
        
        uint32_t vtable = b_sym(binary, vt_name, true, must_find);
        if(!vtable) return 0;
        uint32_t loc_in_vtable = find_int32((range_t) {binary, vtable, 0x1000}, the_func, true);

        uint32_t diff = loc_in_vtable - (vtable + 8);

        fprintf(stderr, "b_lookup_sym: vtable index %d for %s = %x - %x\n", diff/4, sym, loc_in_vtable, vtable + 8);
        return diff;
    }

    return b_sym(binary, sym, true, must_find);
}

static uint32_t b_lookup_nlist(const struct binary *target, const struct binary *source, uint32_t symbolnum) {
    struct nlist *nl = source->symtab + symbolnum;
    bool weak = nl->n_desc & N_WEAK_REF;
    const char *name = source->strtab + nl->n_un.n_strx;
    uint32_t sym = b_lookup_sym(target, name, !weak);
    if(weak && !sym) {
        fprintf(stderr, "relocate_area: couldn't find weak symbol %s\n", name);
    }
    return sym;
}

static void relocate_area(const struct binary *binary, const struct binary *kern, uint32_t slide, uint32_t reloff, uint32_t nreloc) {
    struct relocation_info *things = rangeconv_off((range_t) {binary, reloff, nreloc * sizeof(struct relocation_info)}).start;
    for(uint32_t i = 0; i < nreloc; i++) {
        assert(!things[i].r_pcrel);
        assert(things[i].r_length == 2);
        assert(things[i].r_type == 0);
        uint32_t thing = /*reloc_base + */things[i].r_address;
        uint32_t *p = rangeconv((range_t) {binary, thing, 4}).start;
        if(things[i].r_extern) {
            *p += b_lookup_nlist(kern, binary, things[i].r_symbolnum);
        } else {
            // *shrug*
            *p += slide;
        }
    }
}

void b_relocate(struct binary *binary, const struct binary *kern, uint32_t slide) {
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
    
    relocate_area(binary, kern, slide, binary->dysymtab->locreloff, binary->dysymtab->nlocrel);
    relocate_area(binary, kern, slide, binary->dysymtab->extreloff, binary->dysymtab->nextrel);

    CMD_ITERATE(binary->mach_hdr, cmd) {
        if(cmd->cmd == LC_SEGMENT) {
            struct segment_command *seg = (void *) cmd;
            binary->last_seg = seg;
            printf("%.16s %08x\n", seg->segname, seg->vmaddr);
            struct section *sections = (void *) (seg + 1);
            for(uint32_t i = 0; i < seg->nsects; i++) {
                struct section *sect = &sections[i];
                printf("   %.16s\n", sect->sectname);
                uint8_t type = sect->flags & SECTION_TYPE;
                switch(type) {
                case S_NON_LAZY_SYMBOL_POINTERS:
                case S_LAZY_SYMBOL_POINTERS: {
                    uint32_t indirect_table_offset = sect->reserved1;
                    uint32_t *indirect = rangeconv_off((range_t) {binary, binary->dysymtab->indirectsymoff + indirect_table_offset*sizeof(uint32_t), (sect->size / 4) * sizeof(uint32_t)}).start;
                    uint32_t *things = rangeconv((range_t) {binary, sect->addr, sect->size}).start;
                    for(uint32_t i = 0; i < sect->size / 4; i++) {
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
                            things[i] = b_lookup_nlist(kern, binary, sym);
                        }
                    }
                    break;
                }
                case S_MOD_TERM_FUNC_POINTERS:
                    // be helpful for the unload later
                    sect->reserved2 = b_find_sysent(kern);
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

                relocate_area(binary, kern, slide, sect->reloff, sect->nreloc);
                sect->addr += slide;
            }
            seg->vmaddr += slide;
        }
    }
}

