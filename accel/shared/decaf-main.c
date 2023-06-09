#include "qemu/osdep.h"
#include "shared/decaf-types-common.h"
#include "shared/decaf-main.h"
#include "shared/decaf-main-internal.h"
#include "exec/exec-all.h"
#include "exec/cpu-all.h"
#include "exec/translate-all.h"
#include "qapi/qapi-types-machine.h"
#include "accel/tcg/tb-context.h"
#include "sysemu/runstate.h"
#include "sysemu/hw_accel.h"
#if !defined(CONFIG_USER_ONLY)
#include "hw/boards.h"
#endif
#include "shared/decaf-callback-common.h"
#include "shared/decaf-callback-to-qemu.h"
#include "shared/decaf-target.h"
#include "shared/decaf-linux-vmi.h"
#include "shared/decaf-taint-memory.h"


#define GUEST_OS_THREAD_SIZE 8192

#define MAX_THREAD_INFO_SEARCH_SIZE 8192
#define MAX_TASK_STRUCT_SEARCH_SIZE 4000 

// gva_t decaf_get_esp(CPUState *cs);

// static int devices = 0;

struct tb_cmp {
    uint32_t pc;
};

flush_list flush_list_internal;

static inline bool tb_htable_cmp(const void *p, const void *d);
static inline void decaf_tb_flush_block(void *p);
static inline void decaf_tb_flush_page(void *p);

/* Pause the guest system */
void decaf_stop_vm(void)
{
	if (runstate_is_running()) {
        vm_stop(RUN_STATE_PAUSED);
    }
}

/* Unpause the guest system */
void decaf_start_vm(void)
{
    if (!runstate_is_running()) {
        vm_start();
    }
}

CPUState *decaf_get_current_cpu(void)
{
    if (!current_cpu) {
        return first_cpu;
    }
    return current_cpu;
}

static gpa_t decaf_get_phys_addr_internal(CPUState* cs, gva_t addr)
{
    CPUArchState *env = (CPUArchState *)cs->env_ptr;
    hwaddr phys_addr;
    uintptr_t mmu_idx = cpu_mmu_index(env, true);
    uintptr_t index = tlb_index(env, mmu_idx, addr);
    CPUTLBEntry *entry = tlb_entry(env, mmu_idx, addr);
    void *p;

    if (unlikely(!tlb_hit(entry->addr_code, addr))) {
        if (!victim_tlb_hit(env, mmu_idx, index, offsetof(CPUTLBEntry, addr_code), (addr) & TARGET_PAGE_MASK)) {
            phys_addr = cpu_get_phys_page_debug(cs, addr & TARGET_PAGE_MASK);
			if (phys_addr == -1)
				return -1;
			phys_addr += addr & (TARGET_PAGE_SIZE - 1);
			return (gpa_t)phys_addr;
        }
    }

    if (unlikely(entry->addr_code & TLB_MMIO)) {
        /* The region is not backed by RAM.  */
        return -1;
    }

    p = (void *)((uintptr_t)addr + entry->addend);
    return qemu_ram_addr_from_host_nofail(p);
}

gpa_t decaf_get_phys_addr(CPUState* cs, gva_t addr)
{
    CPUArchState *env = (CPUArchState *)cs->env_ptr;
    hwaddr phys_addr;
	if (env == NULL )
	{
        cs = decaf_get_current_cpu();
        cpu_synchronize_state(cs);
		env = (CPUArchState *)cs->env_ptr; 
	}

#ifdef TARGET_MIPS
	uint32_t ori_hflags = env->hflags;
	env->hflags &= ~MIPS_HFLAG_UM;
	env->hflags &= ~MIPS_HFLAG_SM;
#endif

	phys_addr = decaf_get_phys_addr_internal(cs, addr);

#ifdef TARGET_MIPS
	env->hflags = ori_hflags;   // restore hflags
#endif

	return (gpa_t)(phys_addr);
}

DECAF_errno_t decaf_memory_rw(CPUState* cs, decaf_target_ulong addr, void *buf, int len, int is_write)
{
	hwaddr page, phys_addr;
    int rest_len;

	if (cs == NULL ) 
    {
        cs = decaf_get_current_cpu();
        cpu_synchronize_state(cs);
	}

	int ret = 0;

	while (len > 0) {
		page = addr & TARGET_PAGE_MASK;
		phys_addr = decaf_get_phys_addr(cs, page);
		if (phys_addr == -1 || phys_addr > current_machine->ram_size) {
			ret = -1;
			break;
		}
		rest_len = (page + TARGET_PAGE_SIZE) - addr;
		if (rest_len > len)
			rest_len = len;

		cpu_physical_memory_rw(phys_addr + (addr & ~TARGET_PAGE_MASK), buf, rest_len, is_write);

		len -= rest_len;
		buf += rest_len;
		addr += rest_len;
	}

	return ret;
}

DECAF_errno_t decaf_read_mem(CPUState* cs, gva_t vaddr, int len, void *buf) {
	return decaf_memory_rw(cs, vaddr, buf, len, 0);
}

DECAF_errno_t decaf_write_mem(CPUState *cs, gva_t vaddr, int len, void *buf) {
    return decaf_memory_rw(cs, vaddr, buf, len, 1);
}

// DECAF_errno_t decaf_read_mem_with_pgd(CPUState *cs, decaf_target_ulong pgd, gva_t vaddr, int len, void *buf)
// {
//     return decaf_memory_rw_with_pgd(cs, pgd, vaddr, buf, len, 0);
// }

// DECAF_errno_t decaf_write_mem_with_pgd(CPUState *cs, decaf_target_ulong pgd, gva_t vaddr, int len, void *buf)
// {
//     return decaf_memory_rw_with_pgd(cs, pgd, vaddr, buf, len, 1);
// }

DECAF_errno_t decaf_read_ptr(CPUState *cs, gva_t vaddr, gva_t *pptr)
{
    int ret = decaf_read_mem(cs, vaddr, sizeof(gva_t), pptr);
	if(ret == 0)
	{
#ifdef TARGET_WORDS_BIGENDIAN
#if TARGET_LONG_BITS == 32
		bswap_32(*pptr);
#else
		bswap_64(*pptr);
#endif
#endif
	}
	return ret;
}

#if 0
void decaf_flush_translation_block_fast(CPUState *cs, gva_t pc)
{
    TranslationBlock *cpu_single_envtb;
    uint32_t hash;
    uint32_t cflags;
    cflags = cs->cflags_next_tb;

    /* we should never be trying to look up an INVALID tb */
    tcg_debug_assert(!(cflags & CF_INVALID));

    hash = tb_jmp_cache_hash_func(pc);
    tb = qatomic_rcu_read(&cs->tb_jmp_cache[hash]);
    if (likely(tb && tb->pc == pc))
    {
        tb_phys_invalidate(tb, -1);
    }
}

void decaf_flush_translation_page_fast(CPUState *cs, gva_t pc)
{
    TranslationBlock *tb;
    uint32_t hash;
    uint32_t cflags;
    cflags = cs->cflags_next_tb;

    /* we should never be trying to look up an INVALID tb */
    tcg_debug_assert(!(cflags & CF_INVALID));

    hash = tb_jmp_cache_hash_func(pc);
    tb = qatomic_rcu_read(&cs->tb_jmp_cache[hash]);
    if (likely(tb && tb->pc == pc))
    {
        tb_invalidate_phys_page_range(tb->page_addr[0], tb->page_addr[0] + TARGET_PAGE_SIZE);
    }
}

void decaf_flush_translation_block_fast_all(CPUState *cs, gva_t pc)
{
    CPU_FOREACH(cpu) {
            decaf_flush_translation_block_fast(cs, pc)
        }
    }
}

void decaf_flush_translation_block_fast_all(CPUState *cs, gva_t pc)
{
    CPU_FOREACH(cpu) {
            decaf_flush_translation_page_fast(cs, pc)
        }
    }
}
#endif

static inline bool tb_htable_cmp(const void *p, const void *d)
{
    const TranslationBlock *tb = p;
    const struct tb_cmp *cmp_pc = d;
    if(tb->pc == cmp_pc->pc)
    {
        return true;
    }
    return false;
}

static inline void decaf_tb_flush_block(void *p)
{
    TranslationBlock *tb = p;
    tb_phys_invalidate(tb, -1);
}

static inline void decaf_tb_flush_page(void *p)
{
    TranslationBlock *tb = p;
    tb_invalidate_phys_page_range(tb->page_addr[0], tb->page_addr[0] + TARGET_PAGE_SIZE);
}

void decaf_flush_translation_block(CPUState *cs, gva_t pc)
{
    struct tb_cmp cmp_pc;
    cmp_pc.pc = pc;
    qht_htable_traverse(&tb_ctx.htable, &cmp_pc, tb_htable_cmp, decaf_tb_flush_block);
}

void decaf_flush_translation_page(CPUState *cs, gva_t pc)
{
    struct tb_cmp cmp_pc;
    cmp_pc.pc = pc;
    qht_htable_traverse(&tb_ctx.htable, &cmp_pc, tb_htable_cmp, decaf_tb_flush_page);
}

void flush_list_insert(flush_list *list, int type, uint32_t addr)
{
	++list->size;
	flush_node *temp = list->head;
	flush_node *to_insert = (flush_node *)g_malloc(sizeof(flush_node));
	to_insert->type = type;
	to_insert->next = NULL;
	to_insert->addr = addr;

	if(temp == NULL) {
		list->head = to_insert;
		return;
	}

	while(temp->next != NULL) {
		temp = temp->next;
	}

	temp->next = to_insert;
}

void register_decaf_flush_translation_cache(int type, gva_t pc)
{
    flush_list_insert(&flush_list_internal, type, pc);
}

void decaf_perform_flush(CPUState *cs)
{
    flush_node *prev, *temp = flush_list_internal.head;
	while(temp!=NULL) {
		switch (temp->type) {
			case BLOCK_LEVEL:
				decaf_flush_translation_block(cs, temp->addr);
				break;
			case PAGE_LEVEL:
				decaf_flush_translation_page(cs, temp->addr);
				break;
			case ALL_CACHE:
				tb_flush(cs);
				break;
		}
		prev = temp;
		temp = temp->next;
		prev->next = NULL;
		g_free(prev);
	}
	flush_list_internal.head = NULL;
	flush_list_internal.size = 0;
}

void decaf_init(void)
{
	decaf_callback_init();
	vmi_init();
    shadow_memory_init();
    // decaf_vm_compress_init();
	// function_map_init();
	// init_hookapi();
}


#if 0
int decaf_bdrv_pread(void *opaque, int64_t offset, void *buf, int count)
{
    return bdrv_pread((BdrvChild *)opaque, offset, buf, count);
}

void decaf_bdrv_open(int index, void *opaque)
{
    unsigned long img_size = ((BlockDriverState *)opaque)->total_sectors * 512;

    if(!qemu_pread)
        qemu_pread = (qemu_pread_t)decaf_bdrv_pread;

    monitor_printf(default_mon, "inside bdrv open, drv addr= 0x%p, size= %lu\n", opaque, img_size);

    disk_info_internal[devices].bs = opaque;
    disk_info_internal[devices].img = tsk_img_open(1, (const char **) &opaque, QEMU_IMG, 0);
    disk_info_internal[devices].img->size = img_size;


    if (disk_info_internal[devices].img==NULL) {
        monitor_printf(default_mon, "img_open error! drv addr=0x%p\n", opaque);
    }

    // TODO: AVB, also add an option of 56 as offset with sector size of 4k, Sector size is now assumed to be 512 by default
    if(!(disk_info_internal[devices].fs = tsk_fs_open_img(disk_info_internal[devices].img, 0 ,TSK_FS_TYPE_EXT_DETECT)) &&
            !(disk_info_internal[devices].fs = tsk_fs_open_img(disk_info_internal[devices].img, 63 * (disk_info_internal[devices].img)->sector_size, TSK_FS_TYPE_EXT_DETECT)) &&
                !(disk_info_internal[devices].fs = tsk_fs_open_img(disk_info_internal[devices].img, 2048 * (disk_info_internal[devices].img)->sector_size , TSK_FS_TYPE_EXT_DETECT)) )
    {
        monitor_printf(default_mon, "fs_open error! drv addr=0x%p\n", opaque);
    }
    else
    {
        monitor_printf(default_mon, "fs_open = %s \n",(disk_info_internal[devices].fs)->duname);
    }

    ++devices;
}
#endif

void decaf_nic_receive(uint8_t * buf, int size, int cur_pos, int start, int stop)
{
    if (decaf_is_callback_needed(DECAF_NIC_REC_CB))
		helper_decaf_invoke_nic_rec_callback(buf, size, cur_pos, start, stop);
}

void decaf_nic_send(uint32_t addr, int size, uint8_t * buf)
{
    if (decaf_is_callback_needed(DECAF_NIC_SEND_CB))
		helper_decaf_invoke_nic_send_callback(addr, size, buf);
}

void decaf_nic_in(uint32_t addr, int size)
{
// #ifdef CONFIG_TCG_TAINT
	// CPUState cs = decaf_get_current_cpu();
    // cpu_synchronize_state(cs);
    // CPUArchState *env = (CPUArchState *)cs->env_ptr;
	// taintcheck_nic_writebuf(addr, size, (uint8_t *) &(env->tempidx));
// #endif
}

void decaf_nic_out(const uint32_t addr, const int size)
{
// #ifdef CONFIG_TCG_TAINT
	// CPUState cs = decaf_get_current_cpu();
    // cpu_synchronize_state(cs);
    // CPUArchState *env = (CPUArchState *)cs->env_ptr;
    // taintcheck_nic_readbuf(addr, size, (uint8_t *) &(env->tempidx));
// #endif
}

// void decaf_read_keystroke(void *s);
// void decaf_after_loadvm(const char *); 
// void decaf_update_cpl(int cpl);
// void decaf_after_iret_protected(void);
// void decaf_loadvm(void *opaque);


// void test_temp(void);
// void test_temp(void)
// {
//     printf("11111\n");
// }
// gva_t test_load_proc_info(CPUState *cs, gva_t threadinfo);
// gva_t test_load_proc_info(CPUState *cs, gva_t threadinfo)
// {
//     uint32_t i = 0;
//     uint32_t j = 0;
//     gva_t temp = 0;
//     gva_t temp2 = 0;
//     gva_t candidate = 0; 
    
//     //iterate through the thread info structure
//     for (i = 0; i < MAX_THREAD_INFO_SEARCH_SIZE; i+= sizeof(uint32_t))
//     {
//         temp = (threadinfo + i);
//         candidate = 0;
//         // candidate = (get_uint32_t_at(env, temp));
//         decaf_read_ptr(cs, temp, &candidate);
//         //if it looks like a kernel address
//         if (candidate > 0xc0000000 && candidate < 0xF8000000 - 1)
//         {
//             //iterate through the potential task struct 
//             for (j = 0; j < MAX_TASK_STRUCT_SEARCH_SIZE; j += sizeof(uint32_t))
//             {
//                 temp2 = (candidate + j);
//                 //if there is an entry that has the same 
//                 // value as threadinfo then we are set
//                 uint32_t val = 0;
//                 decaf_read_ptr(cs, temp2, &val);
//                 if (val == threadinfo)
//                 {
//                     return 0;
//                 }
//             }
//         }
//     }
//     return (1);
// }

// gva_t decaf_get_esp(CPUState *cs)
// {  
// #ifdef TARGET_I386
//     CPUArchState *env = (CPUArchState *)cs->env_ptr;
//     return (env->regs[R_ESP]);
// #elif defined(TARGET_ARM)
//     CPUArchState *env = (CPUArchState *)cs->env_ptr;
//     return (env->regs[13]);
// #elif defined(TARGET_MIPS)
//     CPUArchState *env = (CPUArchState *)cs->env_ptr;
//     return (env->active_tc.gpr[29]);
// #endif 
//     return 0;
// }

// int test_find_linux(CPUState *cs)
// {
//     uint32_t thread_info = decaf_get_esp(cs) & ~ (GUEST_OS_THREAD_SIZE - 1);
//     static uint32_t last_thread_info = 0;

//     // if current address is tested before, save time and do not try it again
//     if (thread_info == last_thread_info || thread_info <= 0x80000000)
//         return 0;

//     if(0 == test_load_proc_info(cs, thread_info)) {
//         test_temp();
//         return 1;
//     }
//     return 0;
// }

// void decaf_physical_memory_rw(
//     CPUState *cs,
//     gpa_t addr,
//     uint8_t *buf,
//     int len,
//     int is_write)
// {

// }


