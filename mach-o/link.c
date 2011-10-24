#include "link.h"
#include "headers/loader.h"
#include "headers/nlist.h"
#include "headers/reloc.h"
#include "headers/arm_reloc.h"
#include <assert.h>
#include <ctype.h>
#include "read_dyld_info.h"

static addr_t lookup_nth_symbol(const struct binary *load, const struct binary *target, lookupsym_t lookup_sym, uint32_t symbolnum, bool userland) {
    struct nlist *nl = b_macho_nth_symbol(load, symbolnum);
    bool weak = nl->n_desc & N_WEAK_REF;
    const char *name = load->mach->strtab + nl->n_un.n_strx;
    addr_t sym = lookup_sym(target, name);
    if(!sym) {
        if(weak || userland) {
            fprintf(stderr, "lookup_nth_symbol: couldn't find %ssymbol %s\n", weak ? "weak " : "", name);
        } else {
            die("couldn't find symbol %s\n", name);
        }
    }
    return sym;
}

static void relocate_area(const struct binary *load, const struct binary *target, enum reloc_mode mode, lookupsym_t lookup_sym, addr_t slide, uint32_t reloff, uint32_t nreloc) {
    struct relocation_info *things = rangeconv_off((range_t) {load, reloff, nreloc * sizeof(struct relocation_info)}, MUST_FIND).start;
    for(uint32_t i = 0; i < nreloc; i++) {
        assert(things[i].r_length == 2);
        addr_t address = things[i].r_address;
        if(address == 0 || things[i].r_symbolnum == R_ABS) continue;
        address += b_macho_reloc_base(load);
        uint32_t *p = rangeconv((range_t) {load, address, 4}, MUST_FIND).start;

        addr_t value;
        if(things[i].r_extern) {
            if(mode == RELOC_LOCAL_ONLY) continue;
            value = lookup_nth_symbol(load, target, lookup_sym, things[i].r_symbolnum, mode == RELOC_USERLAND);
            if(value == 0 && mode == RELOC_USERLAND) continue;
        } else {
            if(mode == RELOC_EXTERN_ONLY || mode == RELOC_USERLAND) continue;
            // *shrug*
            value = slide;
        }

        things[i].r_address = 0;
        things[i].r_symbolnum = R_ABS;

        if(mode == RELOC_EXTERN_ONLY && things[i].r_type != ARM_RELOC_VANILLA) {
            die("non-VANILLA relocation but we are relocating without knowing the slide; use __attribute__((long_call)) to get rid of these");
        }
        switch(things[i].r_type) {
        case ARM_RELOC_VANILLA:
            //printf("%x, %x += %x\n", address, *p, value); 
            if(rangeconv((range_t) {load, *p, 0}, 0).start) {
                // when dyld_stub_binding_helper (which would just crash, btw) is present, entries in the indirect section point to it; usually this increments to point to the right dyld_stub_binding_helper, then that's clobbered by the indirect code.  when we do prelinking, the indirect code runs first and we would be relocating the already-correctly-located importee symbol, so we add this check (easier than actually checking that it's not in the indirect section) to make sure we're not relocating nonsense.
                *p += value;
            }
            //else printf("skipping %x\n", *p);
            break;
        case ARM_RELOC_BR24: {
            if(!things[i].r_pcrel) die("weird relocation");
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
                if(cond != 0xe && cond != 0xf) die("can't convert BL with condition to BLX (which must be unconditional)");
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

static void relocate_with_symtab(struct binary *load, const struct binary *target, enum reloc_mode mode, lookupsym_t lookup_sym, uint32_t slide) {
    if(mode != RELOC_EXTERN_ONLY && mode != RELOC_USERLAND) {
        relocate_area(load, target, mode, lookup_sym, slide, load->mach->dysymtab->locreloff, load->mach->dysymtab->nlocrel);
    }
    if(mode != RELOC_LOCAL_ONLY) {
        relocate_area(load, target, mode, lookup_sym, slide, load->mach->dysymtab->extreloff, load->mach->dysymtab->nextrel);
    }

    CMD_ITERATE(load->mach->hdr, cmd) {
        if(cmd->cmd == LC_SEGMENT) {
            struct segment_command *seg = (void *) cmd;
            //printf("%.16s %08x\n", seg->segname, seg->vmaddr);
            struct section *sections = (void *) (seg + 1);
            for(uint32_t i = 0; i < seg->nsects; i++) {
                struct section *sect = &sections[i];
                //printf("   %.16s\n", sect->sectname);
                uint8_t type = sect->flags & SECTION_TYPE;
                switch(type) {
                case S_NON_LAZY_SYMBOL_POINTERS:
                case S_LAZY_SYMBOL_POINTERS:
                case S_SYMBOL_STUBS: {
                    uint32_t indirect_table_offset = sect->reserved1;
                    uint32_t *indirect = rangeconv_off((range_t) {load, (addr_t) (load->mach->dysymtab->indirectsymoff + indirect_table_offset*sizeof(uint32_t)), (sect->size / 4) * sizeof(uint32_t)}, MUST_FIND).start;
                    uint32_t *things = rangeconv((range_t) {load, sect->addr, sect->size}, MUST_FIND).start;
                    for(uint32_t i = 0; i < sect->size / 4; i++) {
                        uint32_t sym = indirect[i];
                        switch(sym) {
                        case INDIRECT_SYMBOL_LOCAL:
                            if(mode == RELOC_EXTERN_ONLY || mode == RELOC_USERLAND) break;
                            if(type != S_SYMBOL_STUBS) things[i] += slide;
                            indirect[i] = INDIRECT_SYMBOL_ABS;
                            break;
                        case INDIRECT_SYMBOL_ABS:
                            break;
                        default: {
                            if(mode == RELOC_LOCAL_ONLY) continue;
                            //printf("setting indirect symbol %x\n", sect->addr + 4*i);
                            uint32_t addr = lookup_nth_symbol(load, target, lookup_sym, sym, mode == RELOC_USERLAND);
                            if(!addr && mode == RELOC_USERLAND) break;
                            if(type != S_SYMBOL_STUBS) things[i] = addr;
                            indirect[i] = INDIRECT_SYMBOL_ABS;
                            break;
                        }
                        }
                    }
                    break;
                }
                case S_ZEROFILL:
                case S_MOD_INIT_FUNC_POINTERS:
                case S_MOD_TERM_FUNC_POINTERS:
                case S_REGULAR:
                case S_CSTRING_LITERALS:
                case S_4BYTE_LITERALS:
                case S_8BYTE_LITERALS:
                case S_16BYTE_LITERALS:
                    break;
                default:
                    if(mode != RELOC_USERLAND) {
                        die("unrecognized section type %02x", type);
                    }
                }
                
                relocate_area(load, target, mode, lookup_sym, slide, sect->reloff, sect->nreloc);
                if(mode != RELOC_EXTERN_ONLY) sect->addr += slide;
            }
            if(mode != RELOC_EXTERN_ONLY) seg->vmaddr += slide;
        }
    }

}

static void do_bind_section(struct binary *load, const struct binary *target, bool weak, lookupsym_t lookup_sym, prange_t opcodes) {
    uint32_t nsegments = load->nsegments;
    uint8_t pointer_size = b_pointer_size(load);

    uint8_t symbol_flags;
    char *sym = NULL;
    uint8_t type = BIND_TYPE_POINTER;
    addr_t addend = 0;
    prange_t segment = {NULL, 0};
    addr_t segaddr;
    addr_t offset = 0;

    void *ptr = opcodes.start, *end = ptr + opcodes.size;
    while(ptr != end) {
        void *orig_ptr = ptr;
        uint8_t byte = read_int(&ptr, end, uint8_t);
        uint8_t immediate = byte & BIND_IMMEDIATE_MASK;
        uint8_t opcode = byte & BIND_OPCODE_MASK;

        addr_t count, skip;

        switch(opcode) {
        case BIND_OPCODE_DONE:
        case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
        case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
            // do nothing
            break;
        case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
            read_uleb128(&ptr, end);
            break;
        case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
            sym = read_cstring(&ptr, end);
            symbol_flags = immediate;
            break;
        case BIND_OPCODE_SET_TYPE_IMM:
            type = immediate;
            break;
        case BIND_OPCODE_SET_ADDEND_SLEB:
            addend = read_sleb128(&ptr, end);
            break;
        case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
            if(immediate >= nsegments) {
                die("segment too high");
            }
            segment = rangeconv_off(load->segments[immediate].file_range, MUST_FIND);
            segaddr = load->segments[immediate].vm_range.start;
            offset = read_uleb128(&ptr, end);
            break;
        case BIND_OPCODE_ADD_ADDR_ULEB:
            offset += read_uleb128(&ptr, end);
            break;
        case BIND_OPCODE_DO_BIND:
            count = 1;
            skip = pointer_size;
            goto bind;
        case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
            count = 1;
            skip = read_uleb128(&ptr, end) + pointer_size;
            goto bind;
        case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
            count = 1;
            skip = immediate * pointer_size + pointer_size;
            goto bind;
        case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
            count = read_uleb128(&ptr, end);
            skip = read_uleb128(&ptr, end);
            goto bind;
        bind: {
            if(!sym || !segment.start) die("improper bind");
            bool _64b;
            addr_t value = lookup_sym(target, sym);
            if(!value) {
                if(weak) {
                    offset += skip * count;
                    break;
                } else {
                    die("no such symbol %s", sym);
                }
            }
            value += addend;
            switch(type) {
            case BIND_TYPE_POINTER:
                _64b = pointer_size == 8;
                break;
            case BIND_TYPE_TEXT_ABSOLUTE32:
                _64b = false;
                break;
            case BIND_TYPE_TEXT_PCREL32:
                _64b = false;
                value -= (segaddr + offset + 4);
                break;
            default:
                die("bad bind type %d", (int) type);
            }
            
            while(count--) {
                if(offset >= segment.size) die("address out of range while binding");
                if(_64b) {
                    if(segment.size - offset < sizeof(uint64_t)) die("bind: out of space");
                    *((uint64_t *) (segment.start + offset)) = value;
                } else {
                    if(segment.size - offset < sizeof(uint32_t)) die("bind: out of space");
                    *((uint32_t *) (segment.start + offset)) = value;
                }

                offset += skip;
                if(type == BIND_TYPE_TEXT_PCREL32) value -= skip;
            }

            memset(orig_ptr, BIND_OPCODE_SET_TYPE_IMM, ptr - orig_ptr);
            type = BIND_TYPE_POINTER;
            break;    
        }
        default:
            die("unknown bind opcode");
        }
    }
}

static void relocate_with_dyld_info(struct binary *load, const struct binary *target, enum reloc_mode mode, lookupsym_t lookup_sym, uint32_t slide) {
    (void) slide; // assert(slide == 0)
    // It gets more complicated
    const struct dyld_info_command *dyld_info = load->mach->dyld_info;
    #define fetch(type) prange_t type = dyld_info->type##_off ? rangeconv_off((range_t) {load, dyld_info->type##_off, dyld_info->type##_size}, MUST_FIND) : (prange_t) {NULL, 0};
    // fetch(rebase)
    if(mode != RELOC_LOCAL_ONLY) {
        fetch(bind)
        fetch(weak_bind)
        fetch(lazy_bind)
        do_bind_section(load, target, mode == RELOC_USERLAND, lookup_sym, lazy_bind);
        do_bind_section(load, target, true, lookup_sym, weak_bind);
        do_bind_section(load, target, mode == RELOC_USERLAND, lookup_sym, bind);
    }
}

void b_relocate(struct binary *load, const struct binary *target, enum reloc_mode mode, lookupsym_t lookup_sym, uint32_t slide) {
    if((mode == RELOC_USERLAND || (load->mach->dyld_info && load->mach->dyld_info->cmd == LC_DYLD_INFO_ONLY)) && slide != 0) {
        die("sliding is not supported in userland mode or with LC_DYLD_INFO_ONLY");
    }

    if(mode != RELOC_USERLAND) {
        // we can be more rigorous in this mode
        CMD_ITERATE(load->mach->hdr, cmd) {
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
    }

    assert(load->mach->symtab);
    assert(load->mach->dysymtab);

    // check for overlap
    for(uint32_t i = 0; i < load->nsegments; i++) {
        struct data_segment *a = &load->segments[i];
        for(uint32_t j = 0; j < target->nsegments; j++) {
            struct data_segment *b = &target->segments[j];
            addr_t diff = b->vm_range.start - (a->vm_range.start + slide);
            if(diff < a->vm_range.size || -diff < b->vm_range.size) {
                die("segments of load and target overlap; load:%x+%zu target:%x+%zu", a->vm_range.start, a->vm_range.size, b->vm_range.start, b->vm_range.size);
            }
        }
    }
    
    (load->mach->dyld_info ? relocate_with_dyld_info : relocate_with_symtab)(load, target, mode, lookup_sym, slide);
}

