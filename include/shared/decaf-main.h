/*
Copyright (C) <2012> <Syracuse System Security (Sycure) Lab>

DECAF is based on QEMU, a whole-system emulator. You can redistribute
and modify it under the terms of the GNU GPL, version 3 or later,
but it is made available WITHOUT ANY WARRANTY. See the top-level
README file for more details.

For more information about DECAF and other softwares, see our
web site at:
http://sycurelab.ecs.syr.edu/

If you have any questions about DECAF,please post it on
http://code.google.com/p/decaf-platform/
*/
/*
 * DECAF_main.h
 *
 *  Created on: Oct 14, 2012
 *      Author: lok
 *  changed on: Nov 1, 2022
 *      author: 
 *  This is half of the old main.h. All of the declarations here are
 *  target independent. All of the target dependent declarations and code
 *  are in the target directory in DECAF_main_x86.h and .c for example
 */

#ifndef DECAF_MAIN_H
#define DECAF_MAIN_H

#if defined(CONFIG_2nd_CCACHE) //sina
	#define EXCP12_TNT	39
	extern int second_ccache_flag;
#endif

#include "shared/decaf-types-common.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define PAGE_LEVEL 0
#define BLOCK_LEVEL 1
#define ALL_CACHE 2

/*************************************************************************
 * The Virtual Machine control
 *************************************************************************/
// Pause the guest system
void decaf_stop_vm(void);
// Unpause the guest system
void decaf_start_vm(void);

CPUState *decaf_get_current_cpu(void);

/*************************************************************************
 * Functions for accessing the guest's memory
 *************************************************************************/
/****** Functions used by DECAF plugins ****/

/***************************************************************************************************************/
// Convert virtual address into physical address
extern gpa_t decaf_get_phys_addr(CPUState *cs, gva_t addr);

// Convert virtual address into physical address for given cr3 - cr3 is a phys addr
// The implementation is target-specific
// extern gpa_t DECAF_get_physaddr_with_cr3(CPUState *cs, decaf_target_ulong cr3, gva_t addr);
// defined in target/(i386,arm,mip)/..., TODO
extern gpa_t decaf_get_phys_addr_with_pgd(CPUState *cs, gpa_t pgd, gva_t addr);

// wrapper -- pgd is the generic term while cr3 is the register in x86
#define decaf_get_phys_addr_with_cr3(cs, _pgd, _addr) decaf_get_phys_addr_with_pgd(cs, _pgd, _addr)

/***************************************************************************************************************/
// The basic functions for reading/writing mem, which are used by some following functions
extern DECAF_errno_t decaf_memory_rw(CPUState* cs, decaf_target_ulong addr, void *buf, int len, int is_write);

DECAF_errno_t decaf_memory_rw_with_pgd(
    CPUState *cs,
    decaf_target_ulong pgd,
    gva_t addr,
    void *buf,
    int len,
    int is_write);

/***************************************************************************************************************/
// Encapsulate decaf_memory_rw and decaf_memory_rw_with_pgd for ease of use
/// \brief Read from a memory region by its virtual address.
/// @param env cpu states
/// @param vaddr virtual memory address
/// @param len length of memory region (in bytes)
/// @param buf output buffer of the value to be read
/// @return status: 0 for success and -1 for failure
///
/// If failure, it usually means that the given virtual address cannot be converted
/// into physical address. It could be either invalid address or swapped out.
extern DECAF_errno_t decaf_read_mem(CPUState *cs, gva_t vaddr, int len, void *buf);

/// \brief Write into a memory region by its virtual address.
///
/// @param vaddr virtual memory address
/// @param len length of memory region (in bytes)
/// @param buf input buffer of the value to be written
/// @return status: 0 for success and -1 for failure
///
/// If failure, it usually means that the given virtual address cannot be converted
/// into physical address. It could be either invalid address or swapped out.
extern DECAF_errno_t decaf_write_mem(CPUState *cs, gva_t vaddr, int len, void *buf);

extern DECAF_errno_t decaf_read_mem_with_pgd(CPUState *cs, decaf_target_ulong pgd, gva_t vaddr, int len, void *buf);
extern DECAF_errno_t decaf_write_mem_with_pgd(CPUState *cs, decaf_target_ulong pgd, gva_t vaddr, int len, void *buf);
DECAF_errno_t decaf_read_ptr(CPUState *env, gva_t vaddr, gva_t *pptr);
/***************************************************************************************************************/

// For keylogger plugin
extern void * DECAF_KbdState;
extern void decaf_keystroke_read(uint8_t taint_status);
extern void decaf_keystroke_place(int keycode);

/// \brief Set monitor context.
///
/// This is a boolean flag that indicates if the current execution needs to be monitored
/// and analyzed by the plugin. The default value is 1, which means that the plugin wants
/// to monitor all execution (including the OS kernel and all running applications).
/// Very often, the plugin is only interested in a single user-level process.
/// In this case, the plugin is responsible to set this flag to 1 when the execution is within
/// the specified process and to 0 when it is not.
extern int should_monitor;
extern int g_bNeedFlush;
/***************************************************************************************************************/

// For sleuthkit to read
int decaf_bdrv_pread(void *opaque, int64_t offset, void *buf, int count);

extern int DECAF_emulation_started; //will be removed

/***************************************************************************************************************/
// In DECAF - we do not use the same-per vcpu flushing behavior as in QEMU. For example
// decaf_flush_translation_cache is a wrapper for tb_flush that iterates through all of
// the virtual CPUs and calls tb_flush on that particular environment. The main reasoning
// behind this decision is that the user wants to know when an event occurs for any
// vcpu and not only for specific ones. This idea can change in the future of course.
// We have yet to decide how to handle multi-core analysis, at the program abstraction
// level or at the thread execution level or at the virtual cpu core level?
// No matter what the decision, flushing can occur using the CPUState as in QEMU
// or using DECAF's wrappers.

 #if 0
/**
 * Flush - or invalidate - the translation block for address addr in the env context.
 * @param env The cpu context
 * @param addr The block's address
 */
void decaf_flush_translation_block_fast(CPUState *cs, gva_t pc);
void decaf_flush_translation_block_fast_all(CPUState *cs, gva_t pc);

/**
 * Flush - or invalidate - all translation blocks for the page in addr.
 * Note that in most cases TARGET_PAGE_SIZE is 4k in size, which is expected.
 * However, in some cases it might only be 1k (in ARM). We use TARGET_PAGE_SIZE
 * as the mask in this function
 *
 * @param env The cpu context
 * @param addr The page address
 */
void decaf_flush_translation_page_fast(CPUState *cs, gva_t pc);
void decaf_flush_translation_block_fast_all(CPUState *cs, gva_t pc);
#endif

//These are DECAF wrappers that does flushing for all VCPUs
//Iterates through all virtual cpus and flushes the blocks
extern void decaf_flush_translation_block(CPUState *cs, gva_t pc);

//Iterates through all virtual cpus and flushes the pages
extern void decaf_flush_translation_page(CPUState *cs, gva_t pc);

// Register block/page/cache-level cache to be flushed to a single linked list named
// flush_list_internal(defined in decaf-main-internal) with type and addr
extern void register_decaf_flush_translation_cache(int type, gva_t pc);

// Do flush
extern void decaf_perform_flush(CPUState *cs);
/***************************************************************************************************************/

/* Static in monitor.c for QEMU, but we use it for plugins: */
///send a keystroke into the guest system
extern void do_send_key(const char *string);

void vmi_init(void);
// int test_find_linux(CPUState *cs);



#ifdef __cplusplus
}
#endif

#endif /* DECAF_MAIN_H */

