#include "running_kernel.h"
#ifdef __APPLE__
#include <mach/mach.h>
#include "loader.h"
#include "nlist.h"
#include "fat.h"
#include "link.h"
#include "find.h"
#include <assert.h>
extern host_priv_t host_priv_self();
// copied from xnu

struct proc;
typedef int32_t sy_call_t(struct proc *, void *, int *);
typedef void    sy_munge_t(const void *, void *);

struct sysent {     /* system call table */
    int16_t     sy_narg;    /* number of args */
    int8_t      sy_resv;    /* reserved  */
    int8_t      sy_flags;   /* flags */
    sy_call_t   *sy_call;   /* implementing function */
    sy_munge_t  *sy_arg_munge32; /* system call arguments munger for 32-bit process */
    sy_munge_t  *sy_arg_munge64; /* system call arguments munger for 64-bit process */
    int32_t     sy_return_type; /* system call return types */
    uint16_t    sy_arg_bytes;   /* Total size of arguments in bytes for
                     * 32-bit system calls
                     */
};
#define _SYSCALL_RET_INT_T      1   

// end copied

kern_return_t kr_assert_(kern_return_t kr, const char *name, int line) {
    if(kr) {
        die("result=%08x on line %d:\n%s", kr, line, name);
    }
    return kr;
}
#define kr_assert(x) kr_assert_((x), #x, __LINE__)

mach_port_t get_kernel_task() {
    static mach_port_t kernel_task;
    if(!kernel_task) {
        kr_assert(task_for_pid(mach_task_self(), 0, &kernel_task));
    }
    return kernel_task;
}

uint32_t b_allocate_from_running_kernel(const struct binary *binary) {
    mach_port_t kernel_task = get_kernel_task();
    if(binary->mach_hdr->flags & MH_PREBOUND) {
        CMD_ITERATE(binary->mach_hdr, cmd) {
            if(cmd->cmd == LC_SEGMENT) {
                struct segment_command *seg = (void *) cmd;
                if(seg->vmsize == 0) continue;
                vm_address_t address = seg->vmaddr;
                printf("prebound allocate %08x %08x\n", (unsigned int) address, (unsigned int) seg->vmsize);
                kr_assert(vm_allocate(kernel_task,
                                      &address,
                                      seg->vmsize,
                                      VM_FLAGS_FIXED));

                assert(address == seg->vmaddr);
                kr_assert(vm_wire(mach_host_self(),
                                  kernel_task,
                                  address,
                                  seg->vmsize,
                                  VM_PROT_READ));
            }
        }
        return 0;
    } else {
        // try to reserve some space
        uint32_t slide;
        for(slide = 0xf0000000; slide < 0xf0000000 + 0x01000000; slide += 0x10000) {
            CMD_ITERATE(binary->mach_hdr, cmd) {
                if(cmd->cmd == LC_SEGMENT) {
                    struct segment_command *seg = (void *) cmd;
                    if(seg->vmsize == 0) continue;
                    vm_address_t address = seg->vmaddr + slide;
                    printf("allocate %08x %08x for %.16s (slide=%x)\n", (int) address, (int) seg->vmsize, seg->segname, (int) slide);
                    kern_return_t kr = vm_allocate(kernel_task,
                                                   &address,
                                                   seg->vmsize,
                                                   VM_FLAGS_FIXED);
                    if(!kr) {
                        assert(address == seg->vmaddr + slide);
                        kr_assert(vm_wire(mach_host_self(),
                                          kernel_task,
                                          address,
                                          seg->vmsize,
                                          VM_PROT_READ));
                        continue;
                    }
                    // Bother, it didn't work.  So we need to increase the slide...
                    // But first we need to get rid of the gunk we did manage to allocate.
                    CMD_ITERATE(binary->mach_hdr, cmd2) {
                        if(cmd2 == cmd) break;
                        if(cmd2->cmd == LC_SEGMENT) {
                            struct segment_command *seg2 = (void *) cmd2;
                            printf("deallocate %08x %08x\n", (int) (seg2->vmaddr + slide), (int) seg2->vmsize);
                            kr_assert(vm_deallocate(kernel_task,
                                                    seg2->vmaddr + slide,
                                                    seg2->vmsize));
                        }
                    }
                    goto try_another_slide;
                }
            }
            // If we got this far, it worked!
            goto it_worked;
            try_another_slide:;
        }
        // But if we got this far, we ran out of slides to try.
        die("we couldn't find anywhere to put this thing and that is ridiculous");
        it_worked:;
        return slide;
    }
}
    

void b_inject_into_running_kernel(struct binary *to_load, uint32_t sysent) {
    // save sysent so unload can have it
    to_load->mach_hdr->filetype = sysent;

    mach_port_t kernel_task = get_kernel_task();

    CMD_ITERATE(to_load->mach_hdr, cmd) {
        if(cmd->cmd == LC_SEGMENT) {
            struct segment_command *seg = (void *) cmd;
            ((struct binary *) to_load)->last_seg = seg;
            uint32_t fs = seg->filesize;
            if(seg->vmsize < fs) fs = seg->vmsize;
            // if prebound, slide = 0
            vm_offset_t of = (vm_offset_t) rangeconv((range_t) {to_load, seg->vmaddr, seg->filesize}).start;
            vm_address_t ad = seg->vmaddr;
            while(fs > 0) {
                // complete headbang.
                //printf("(%.16s) reading %x %08x -> %08x\n", seg->segname, fs, (uint32_t) of, (uint32_t) ad);
                uint32_t tocopy = 0xfff;
                if(fs < tocopy) tocopy = fs;
                kr_assert(vm_write(kernel_task,
                                   ad,
                                   of,
                                   tocopy));
                fs -= tocopy;
                of += tocopy;
                ad += tocopy;
            }
            if(seg->vmsize > 0) {
                // This really depends on nx_disabled...
                kr_assert(vm_protect(kernel_task,
                                     seg->vmaddr,
                                     seg->vmsize,
                                     true,
                                     seg->maxprot & ~VM_PROT_EXECUTE));
                kr_assert(vm_protect(kernel_task,
                                     seg->vmaddr,
                                     seg->vmsize,
                                     false,
                                     seg->initprot & ~VM_PROT_EXECUTE));

                vm_machine_attribute_val_t val = MATTR_VAL_CACHE_FLUSH;
                kr_assert(vm_machine_attribute(kernel_task,
                                               seg->vmaddr,
                                               seg->vmsize,
                                               MATTR_CACHE,
                                               &val));
            }
        }
    }

    // okay, now do the fancy syscall stuff
    // how do I safely dispose of this file?
    int lockfd = open("/tmp/.syscall-11", O_RDWR | O_CREAT);
    assert(lockfd > 0);
    assert(!flock(lockfd, LOCK_EX));

    struct sysent orig_sysent;
    vm_size_t whatever;
    kr_assert(vm_read_overwrite(kernel_task,
                                sysent + 11 * sizeof(struct sysent),
                                sizeof(struct sysent),
                                (vm_offset_t) &orig_sysent,
                                &whatever));

    CMD_ITERATE(to_load->mach_hdr, cmd) {
        if(cmd->cmd == LC_SEGMENT) {
            struct segment_command *seg = (void *) cmd;
            ((struct binary *) to_load)->last_seg = seg;
            struct section *sections = (void *) (seg + 1);
            for(uint32_t i = 0; i < seg->nsects; i++) {
                struct section *sect = &sections[i];

                if((sect->flags & SECTION_TYPE) == S_MOD_INIT_FUNC_POINTERS) {
                    void **things = rangeconv((range_t) {to_load, sect->addr, sect->size}).start;
                    for(uint32_t i = 0; i < sect->size / 4; i++) {
                        struct sysent my_sysent = { 1, 0, 0, things[i], NULL, NULL, _SYSCALL_RET_INT_T, 0 };
                        printf("--> %p\n", things[i]);
                        kr_assert(vm_write(kernel_task,
                                           (vm_address_t) sysent + 11 * sizeof(struct sysent),
                                           (vm_offset_t) &my_sysent,
                                           sizeof(struct sysent)));
                        syscall(11);
                    }
                }
            }
        }
    }

    kr_assert(vm_write(kernel_task,
                       sysent + 11 * sizeof(struct sysent),
                       (vm_offset_t) &orig_sysent,
                       sizeof(struct sysent)));

    assert(!flock(lockfd, LOCK_UN));
}

void unload_from_running_kernel(uint32_t addr) {
    mach_port_t kernel_task = get_kernel_task();

    vm_size_t whatever;
    
    autofree struct mach_header *hdr = malloc(0x1000);
    if(vm_read_overwrite(kernel_task,
                         (vm_address_t) addr,
                         0x1000,
                         (vm_offset_t) hdr,
                         &whatever) == KERN_INVALID_ADDRESS) {
        die("invalid address %08x", addr);
    }
    kr_assert(vm_read_overwrite(kernel_task,
                                (vm_address_t) addr,
                                0xfff,
                                (vm_offset_t) hdr,
                                &whatever));
    if(hdr->magic != MH_MAGIC) {
        die("invalid header (wrong address?)");
    }
    CMD_ITERATE(hdr, cmd) {
        if(cmd->cmd == LC_SEGMENT) {
            struct segment_command *seg = (void *) cmd;
            struct section *sections = (void *) (seg + 1);
            for(uint32_t i = 0; i < seg->nsects; i++) {
                struct section *sect = &sections[i];

                if((sect->flags & SECTION_TYPE) == S_MOD_TERM_FUNC_POINTERS) {
                    uint32_t sysent = hdr->filetype; // hurf durf
                    assert(sysent);
                    autofree void **things = malloc(sect->size);
                    kr_assert(vm_read_overwrite(kernel_task,
                                                (vm_address_t) sect->addr,
                                                sect->size,
                                                (vm_offset_t) things,
                                                &whatever));
                    for(uint32_t i = 0; i < sect->size / 4; i++) {
                        struct sysent my_sysent = { 1, 0, 0, things[i], NULL, NULL, _SYSCALL_RET_INT_T, 0 };
                        printf("--> %p\n", things[i]);
                        kr_assert(vm_write(kernel_task,
                                           (vm_address_t) sysent + 11 * sizeof(struct sysent),
                                           (vm_offset_t) &my_sysent,
                                           sizeof(struct sysent)));
                        syscall(11);
                    }
                }
            }
        }
    }

    CMD_ITERATE(hdr, cmd) {
        if(cmd->cmd == LC_SEGMENT) {
            struct segment_command *seg = (void *) cmd;
            if(seg->vmsize > 0) {
                kr_assert(vm_deallocate(kernel_task,
                                        seg->vmaddr,
                                        seg->vmsize));
            }
        }
    }
}

void b_running_kernel_load_macho(struct binary *binary) {
    kern_return_t kr;

    mach_port_t kernel_task = get_kernel_task();

    char hdr_buf[0xfff];
    struct mach_header *const hdr = (void *) hdr_buf;
    
    addr_t mh_addr;
    vm_size_t size;
    for(addr_t hugebase = 0x80000000; hugebase; hugebase += 0x40000000) {
        for(addr_t pagebase = 0x1000; pagebase < 0x10000; pagebase += 0x1000) {
            mh_addr = (vm_address_t) (hugebase + pagebase);
            size = 0x1000;
            // This will return either KERN_PROTECTION_FAILURE if it's a good address, and KERN_INVALID_ADDRESS otherwise.
            // But if we use a shorter size, it will read if it's a good address, and /crash/ otherwise.
            // So we do two.
            kr = vm_read_overwrite(kernel_task, (vm_address_t) mh_addr, size, (vm_address_t) hdr_buf, &size);
            if(kr == KERN_INVALID_ADDRESS) {
                continue;
            } else if(kr && kr != KERN_PROTECTION_FAILURE) {
                die("unexpected error from vm_read_overwrite: %d", kr);
            }
            // ok, it's valid, but is it the actual header?
            size = 0xfff;
            kr_assert(vm_read_overwrite(kernel_task, (vm_address_t) mh_addr, size, (vm_address_t) hdr_buf, &size));
            if(hdr->magic == MH_MAGIC) {
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
    addr_t maxoff = 0;
    CMD_ITERATE(binary->mach_hdr, cmd) {
        if(cmd->cmd == LC_SEGMENT) {
            struct segment_command *scmd = (void *) cmd;
            addr_t newmax = scmd->fileoff + scmd->filesize;
            if(newmax > maxoff) maxoff = newmax;
        }
    }

    char *buf = malloc(maxoff);

    CMD_ITERATE(binary->mach_hdr, cmd) {
        if(cmd->cmd == LC_SEGMENT) {
            struct segment_command *scmd = (void *) cmd;
            addr_t off = scmd->fileoff;
            addr_t addr = scmd->vmaddr;
            vm_size_t size = scmd->filesize;
            // Well, uh, this sucks.  But there's some block on reading.  In fact, it's probably a bug that this works.
            while(size > 0) {
                vm_size_t this_size = (vm_size_t) size;
                if(this_size > 0xfff) this_size = 0xfff;
                kr_assert(vm_read_overwrite(kernel_task, (vm_address_t) addr, this_size, (vm_address_t) (buf + off), &this_size));

                off += this_size;
                addr += this_size;
                size -= this_size;
            }
        }
    }

    b_prange_load_macho(binary, (prange_t) {buf, maxoff}, "<running kernel>");    
}

#endif
