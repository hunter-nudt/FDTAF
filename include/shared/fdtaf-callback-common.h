/*
Copyright (C) <2012> <Syracuse System Security (Sycure) Lab>

FDTAF is based on QEMU, a whole-system emulator. You can redistribute
and modify it under the terms of the GNU GPL, version 3 or later,
but it is made available WITHOUT ANY WARRANTY. See the top-level
README file for more details.

For more information about FDTAF and other softwares, see our
web site at:
http://sycurelab.ecs.syr.edu/

If you have any questions about FDTAF,please post it on
http://code.google.com/p/fdtaf-platform/
*/
/**
 * @author Lok Yan
 * @date 12 OCT 2012
 * 
 * @change by aspen
 * @date 31 Oct 2022
 */

#ifndef FDTAF_CALLBACK_COMMON_H
#define FDTAF_CALLBACK_COMMON_H

#include "shared/fdtaf-types-common.h"

#ifdef __cplusplus
extern "C"
{
#endif


typedef enum {
    FDTAF_BLOCK_BEGIN_CB = 0,
    FDTAF_BLOCK_END_CB,
    FDTAF_INSN_BEFORE_CB,
    FDTAF_INSN_AFTER_CB,
    FDTAF_EIP_CHECK_CB,
    FDTAF_KEYSTROKE_CB,		//keystroke event
    FDTAF_NIC_REC_CB,
    FDTAF_NIC_SEND_CB,
    FDTAF_OPCODE_RANGE_CB,
    FDTAF_TLB_EXEC_CB,
    FDTAF_READ_TAINTMEM_CB,
    FDTAF_WRITE_TAINTMEM_CB,
	FDTAF_MEM_READ_CB,
    FDTAF_MEM_WRITE_CB,
	FDTAF_BLOCK_TRANS_CB,	// CONFIG_TCG_LLVM
    FDTAF_LAST_CB, 			//place holder for the last position, no other uses.
} fdtaf_callback_type_t;


//Optimized Callback type
typedef enum _OCB_t {
    /**
     * Optimized Callback Condition - Const - The value associated with this flag needs an exact match
     */
    OCB_CONST = 2,
    /**
     * Optimized callback Condition - Page - A match is found as long as the page numbers match
     */
    OCB_PAGE = 4,
    /**
     * Not used yet
     */
    OCB_CONST_NOT = 3,
    /**
     * Not used yet
     */
    OCB_PAGE_NOT = 5,
    /**
     * Optimized Callback Condition - Everything!
     */
    OCB_ALL = -1
} OCB_t;
// HU- for memory read/write callback.Memory be read/written at different grains
//(byte,word,long,quad)
typedef enum{
	FDTAF_BYTE = 1,
	FDTAF_WORD = 2,
	FDTAF_LONG = 4,
	FDTAF_QUAD = 8,
} DATA_TYPE;

typedef struct fdtaf_block_begin_params
{
    CPUState* cs;
    TranslationBlock* tb;
}fdtaf_block_begin_params;

typedef struct fdtaf_tlb_exec_params
{
	CPUState *cs;
	gva_t vaddr;  //Address loaded to tlb exec cache
} fdtaf_tlb_exec_params;

typedef struct fdtaf_block_end_params
{
    CPUState* cs;
    TranslationBlock* tb;
} fdtaf_block_end_params;

typedef struct fdtaf_insn_before_params
{
    CPUState *cs;
    uint32_t pc_first;
    uint32_t mips_opcode;
} fdtaf_insn_before_params;

typedef struct fdtaf_insn_after_params
{
    CPUState* cs;
} fdtaf_insn_after_params;

typedef struct fdtaf_mem_read_params
{
	gva_t vaddr;
	gpa_t paddr;
	DATA_TYPE dt;
	unsigned long value;

}fdtaf_mem_read_params;

typedef struct fdtaf_mem_write_params
{
	gva_t vaddr;
	gpa_t paddr;
	DATA_TYPE dt;
	unsigned long value;
}fdtaf_mem_write_params;

typedef struct fdtaf_eip_check_params
{
	gva_t source_eip;
	gva_t target_eip;
    gva_t target_eip_taint;
}fdtaf_eip_check_params;

typedef struct fdtaf_keystroke_params
{
	int32_t keycode;
	uint32_t *taint_mark;//mark if this keystroke should be monitored

}fdtaf_keystroke_params;

typedef struct fdtaf_nic_rec_params
{
	uint8_t *buf;
	int32_t size;
	int32_t cur_pos;
	int32_t start;
	int32_t stop;
}fdtaf_nic_rec_params;

typedef struct fdtaf_nic_send_params
{
	uint32_t addr;
	int size;
	uint8_t *buf;
}fdtaf_nic_send_params;

typedef struct fdtaf_read_taint_mem
{
	gva_t vaddr;
	gpa_t paddr;
	uint32_t size;
	uint8_t *taint_info;

}fdtaf_read_taint_mem;

typedef struct fdtaf_write_taint_mem
{
	gva_t vaddr;
	gpa_t paddr;
	uint32_t size;
	uint8_t *taint_info;
}fdtaf_write_taint_mem;

//LOK: A dummy type
typedef struct _fdtaf_callback_params
{
	fdtaf_handle cbhandle;
	union{
		fdtaf_block_begin_params bb;
		fdtaf_block_end_params be;
		fdtaf_insn_before_params ib;
		fdtaf_insn_after_params ia;
		fdtaf_mem_read_params mr;
		fdtaf_mem_write_params mw;
		fdtaf_eip_check_params ec;
		fdtaf_keystroke_params ks;
		fdtaf_nic_rec_params nr;
		fdtaf_nic_send_params ns;
		fdtaf_tlb_exec_params tx;
		fdtaf_read_taint_mem rt;
		fdtaf_write_taint_mem wt;
#ifdef CONFIG_TCG_LLVM
		FDTAF_Block_Trans_Params bt;
#endif /* CONFIG_TCG_LLVM */
	};
} fdtaf_callback_params;

typedef void (*fdtaf_callback_func_t)(fdtaf_callback_params*);

/***********************************************************************************************/
/// @brief register optimized block begin callback, three level page/const/all, const now is used the same as all
/// @param cb_func 
/// @param cb_cond 
/// @param addr 
/// @param type 
/// @return 
fdtaf_handle fdtaf_register_optimized_block_begin_callback(
    fdtaf_callback_func_t cb_func,
    int cb_cond,
    gva_t addr,
    OCB_t type);
int fdtaf_unregister_optimized_block_begin_callback(fdtaf_handle handle);

/// \brief Register a callback function
///
/// @param cb_type the event type
/// @param cb_func the callback function
/// @param cb_cond the boolean condition provided by the caller. Only
/// if this condition is true, the callback can be activated. This condition
/// can be NULL, so that callback is always activated.
/// @return handle, which is needed to unregister this callback later.
fdtaf_handle fdtaf_register_callback(
    fdtaf_callback_type_t cb_type,
    fdtaf_callback_func_t cb_func,
    int cb_cond);
int fdtaf_unregister_callback(fdtaf_callback_type_t cb_type, fdtaf_handle handle);

void fdtaf_callback_init(void);

/***********************************************************************************************/

#ifdef __cplusplus
}
#endif

#endif  //FDTAF_CALLBACK_COMMON_H
