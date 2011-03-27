#include "link.h"
#include "find.h"
#include "loader.h"
#include "nlist.h"
#include "reloc.h"
#include "arm_reloc.h"
#include <assert.h>
#include <ctype.h>

// shouldn't be here
uint32_t b_find_sysent(const struct binary *binary) {
    static const struct binary *last_binary; static uint32_t last_sysent;
    if(last_binary != binary) {
        last_binary = binary;
        last_sysent = find_int32(b_macho_segrange(binary, "__DATA"), 0x861000, true) + 4;
    }
    return last_sysent;
}

static uint32_t b_lookup_nlist(const struct binary *load, const struct binary *target, lookupsym_t lookup_sym, uint32_t symbolnum) {
    struct nlist *nl = load->symtab + symbolnum;
    bool weak = nl->n_desc & N_WEAK_REF;
    const char *name = load->strtab + nl->n_un.n_strx;
    uint32_t sym = lookup_sym(target, name);
    if(!sym) {
        if(weak) {
            fprintf(stderr, "b_lookup_nlist: couldn't find weak symbol %s\n", name);
        } else {
            die("couldn't find symbol %s\n", name);
        }
    }
    return sym;
}

static void relocate_area(const struct binary *load, const struct binary *target, lookupsym_t lookup_sym, uint32_t slide, uint32_t reloff, uint32_t nreloc) {
    struct relocation_info *things = rangeconv_off((range_t) {load, reloff, nreloc * sizeof(struct relocation_info)}).start;
    for(uint32_t i = 0; i < nreloc; i++) {
        //assert(!things[i].r_pcrel);
        assert(things[i].r_length == 2);
        uint32_t *p = rangeconv((range_t) {load, things[i].r_address, 4}).start;
        uint32_t value;
        if(things[i].r_extern) {
            value = b_lookup_nlist(load, target, lookup_sym, things[i].r_symbolnum);
        } else {
            // *shrug*
            value = slide;
        }
        switch(things[i].r_type) {
        case ARM_RELOC_VANILLA:
            *p += value;
            break;
        case ARM_RELOC_BR24: {
            assert(things[i].r_pcrel);
            uint32_t ins = *p;
            uint32_t off = ins & 0x00ffffff;
            if(ins & 0x00800000) off |= 0xff000000;
            off <<= 2;
            off += (value - slide);
            if((off & 0xfc000000) != 0 &&
               (off & 0xfc000000) != 0xfc000000) {
                die("BR24 relocation out of range");
            }
            uint32_t cond = ins >> 28;
            if(value & 1) {
                assert(cond == 0xe || cond == 0xf);
                ins = (ins & 0x0effffff) | 0xf0000000 | ((off & 2) << 24);
            } else if(cond == 0xf) {
                ins = (ins & 0x0fffffff) | 0xe0000000;
            }

            ins = (ins & 0xff000000) | ((off >> 2) & 0x00ffffff);
            *p = ins;
            break;
        }
        default:
            die("unknown relocation type %d", things[i].r_type);
        }

    }
}

void b_relocate(struct binary *load, const struct binary *target, lookupsym_t lookup_sym, uint32_t slide) {
    CMD_ITERATE(load->mach_hdr, cmd) {
        switch(cmd->cmd) {
        case LC_SYMTAB:
        case LC_DYSYMTAB:
        case LC_SEGMENT:
        case LC_ID_DYLIB:
        case LC_UUID:
            break;
        default:
            die("unrecognized load command 0x%x", cmd->cmd);
        }
    }
    assert(load->symtab);
    assert(load->dysymtab);
    
    relocate_area(load, target, lookup_sym, slide, load->dysymtab->locreloff, load->dysymtab->nlocrel);
    relocate_area(load, target, lookup_sym, slide, load->dysymtab->extreloff, load->dysymtab->nextrel);

    CMD_ITERATE(load->mach_hdr, cmd) {
        if(cmd->cmd == LC_SEGMENT) {
            struct segment_command *seg = (void *) cmd;
            load->last_seg = seg;
            //printf("%.16s %08x\n", seg->segname, seg->vmaddr);
            struct section *sections = (void *) (seg + 1);
            for(uint32_t i = 0; i < seg->nsects; i++) {
                struct section *sect = &sections[i];
                //printf("   %.16s\n", sect->sectname);
                uint8_t type = sect->flags & SECTION_TYPE;
                switch(type) {
                case S_NON_LAZY_SYMBOL_POINTERS:
                case S_LAZY_SYMBOL_POINTERS: {
                    uint32_t indirect_table_offset = sect->reserved1;
                    uint32_t *indirect = rangeconv_off((range_t) {load, load->dysymtab->indirectsymoff + indirect_table_offset*sizeof(uint32_t), (sect->size / 4) * sizeof(uint32_t)}).start;
                    uint32_t *things = rangeconv((range_t) {load, sect->addr, sect->size}).start;
                    for(uint32_t i = 0; i < sect->size / 4; i++) {
                        uint32_t sym = indirect[i];
                        switch(sym) {
                        case INDIRECT_SYMBOL_LOCAL:
                            things[i] += slide;
                            break;
                        case INDIRECT_SYMBOL_ABS:
                            break;
                        default:
                            if(sym >= load->nsyms) {
                                die("sym too high: %u", sym);
                            }
                            things[i] = b_lookup_nlist(load, target, lookup_sym, sym);
                        }
                    }
                    break;
                }
                case S_MOD_TERM_FUNC_POINTERS:
                    // XXX: be helpful for the unload later
                    sect->reserved2 = lookup_sym(target, "sysent");
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
                
                relocate_area(load, target, lookup_sym, slide, sect->reloff, sect->nreloc);
                sect->addr += slide;
            }
            seg->vmaddr += slide;
        }
    }
}

uint32_t b_lookup_sym(const struct binary *binary, const char *sym) {
    return b_sym(binary, sym, true, true);
}
