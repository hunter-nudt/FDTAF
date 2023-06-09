#ifndef DECAF_TAINT_MEMORY_H
#define DECAF_TAINT_MEMORY_H

#include "exec/cpu-common.h"
#include "shared/decaf-types-common.h"
#include "exec/exec-all.h"

#ifdef __cplusplus
extern "C" 
{
#endif

#ifdef TARGET_I386
#define REGPARM __attribute__((regparm(3)))
#else
#define REGPARM
#endif

#ifdef TARGET_PAGE_BITS_MIN
#define BITPAGE_LEAF_BITS TARGET_PAGE_BITS_MIN
#else
#define BITPAGE_LEAF_BITS TARGET_PAGE_BITS
#endif /* BITPAGE_LEAF_BITS_MIN */
#define BITPAGE_MIDDLE_BITS (32 - BITPAGE_LEAF_BITS) / 2
#define LEAF_ADDRESS_MASK (1 << BITPAGE_LEAF_BITS) - 1
#define MIDDLE_ADDRESS_MASK (1 << BITPAGE_MIDDLE_BITS) - 1

/*	
In order to speed up the page table, we pre-allocate middle and leaf nodes
in two pools.  The size of these pools (in terms of nodes) is set by the
following two defines. 
*/
#define BITPAGE_LEAF_POOL_SIZE 100
#define BITPAGE_MIDDLE_POOL_SIZE 50

#ifndef MIN
#define MIN(a, b) ({\
      typeof(a) _a = a;\
      typeof(b) _b = b;\
      _a < _b ? _a : _b; })
#endif

typedef struct tbitpage_leaf {
	uint8_t bitmap[1 << BITPAGE_LEAF_BITS]; /* This is the bitwise tainting data for the page */
} tbitpage_leaf_t;

/* Middle node for holding memory taint information */
typedef struct tbitpage_middle {
  	tbitpage_leaf_t *leaf[1 << BITPAGE_MIDDLE_BITS];
} tbitpage_middle_t;

/* Pre-allocated pools for leaf and middle nodes */
typedef struct tbitpage_leaf_pool {
	uint32_t next_available_node;
	tbitpage_leaf_t *pool[BITPAGE_LEAF_POOL_SIZE];
} tbitpage_leaf_pool_t;

typedef struct tbitpage_middle_pool {
	uint32_t next_available_node;
	tbitpage_middle_t *pool[BITPAGE_MIDDLE_POOL_SIZE];
} tbitpage_middle_pool_t;

extern bool taint_tracking_enabled;
extern bool taint_nic_enabled;
extern bool taint_load_pointers_enabled;
extern bool taint_store_pointers_enabled;
extern bool taint_pointers_enabled;

extern tbitpage_middle_t **taint_memory_page_table;
extern tbitpage_leaf_pool_t leaf_pool;
extern tbitpage_middle_pool_t middle_pool;

extern uint32_t leaf_nodes_in_use;
extern uint32_t middle_nodes_in_use;

void shadow_memory_init(void);

void allocate_leaf_pool(void);
void allocate_middle_pool(void);

void allocate_taint_memory_page_table(void);
void empty_taint_memory_page_table(void);
void free_taint_memory_page_table(void) ;

/* This deallocates nodes that do not contain taint */
void garbage_collect_taint(int flag);

int is_phys_page_tainted(ram_addr_t paddr);

/* ld/st tainting functions */
#ifdef CONFIG_TCG_TAINT
// void helper_taint_ldub_mmu(gva_t vaddr, CPUArchState *env, MemOp opc);
// void helper_taint_lduw_mmu(gva_t vaddr, CPUArchState *env, MemOp opc);
// void helper_taint_ldul_mmu(gva_t vaddr, CPUArchState *env, MemOp opc);
// void helper_taint_lduq_mmu(gva_t vaddr, CPUArchState *env, MemOp opc);

// void helper_taint_stub_mmu(gva_t vaddr, CPUArchState *env, MemOp opc);
// void helper_taint_stuw_mmu(gva_t vaddr, CPUArchState *env, MemOp opc);
// void helper_taint_stul_mmu(gva_t vaddr, CPUArchState *env, MemOp opc);
// void helper_taint_stuq_mmu(gva_t vaddr, CPUArchState *env, MemOp opc);

void taint_mem(ram_addr_t paddr, int size, uint8_t *taint);
void taint_mem_check(ram_addr_t paddr, uint32_t size, uint8_t *taint);
#endif	/* CONFIG_TCG_TAINT */

uint32_t calc_tainted_bytes(void);

int do_enable_taint_nic_internal(void);

int do_disable_taint_nic_internal(void);

#ifdef __cplusplus
}
#endif

#endif /* DECAF_TAINT_MEMORY_H */