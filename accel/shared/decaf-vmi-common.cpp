//  2022 Nov 14
//  Author: aspen
#include "shared/decaf-vmi-common.h"
#include "shared/decaf-callback-common.h"
#include "shared/decaf-basic-callback.h"
#include "shared/decaf-vmi-callback.h"
#include "shared/decaf-output.h"
#include "shared/decaf-linux-vmi.h"
#include "shared/decaf-main.h"

#include <unordered_map>
#include <unordered_set>
using namespace std;

//map cr3 to process_info_t
unordered_map < decaf_target_ulong, process * > process_map;
//map pid to process_info_t
unordered_map < decaf_target_ulong, process * > process_pid_map;
//map module_name to module_info
unordered_map < string, module * > module_name;

uint32_t GuestOS_index_c = 11;

uintptr_t insn_handle_c = 0;

decaf_target_ulong VMI_guest_kernel_base = 0;

static basic_callback_t VMI_callbacks[VMI_LAST_CB];

// static os_handle_c handle_funds_c[] = {
// #ifdef TARGET_I386
// 		{ WINXP_SP2_C, &find_winxpsp2, &win_vmi_init, },
// 		{ WINXP_SP3_C, &find_winxpsp3, &win_vmi_init, },
// 		{ WIN7_SP0_C, &find_win7sp0, &win_vmi_init, },
// 		{ WIN7_SP1_C, &find_win7sp1, &win_vmi_init, },
// #endif
// 		{ LINUX_GENERIC_C, &find_linux, &linux_vmi_init,},
// };

static void guest_os_confirm(DECAF_Callback_Params* param)
{
    static long long count_out = 0x8000000000L;	// detection fails after 1000 basic blocks
    int found_guest_os = 0;

    // Probing guest OS for every basic block is too expensive and wasteful.
    // Let's just do it once every 256 basic blocks
    if((count_out & 0xff) != 0)
	{
		goto _skip_probe;
	}
    	
	found_guest_os = find_linux(param->tx.cs);
// 	for(size_t i=0; i<sizeof(handle_funds_c)/sizeof(handle_funds_c[0]); i++) {
		// if(handle_funds_c[i].find(temp->ie.cs, insn_handle_c) == 1)
// 		{
// 			GuestOS_index_c = i;
// 			found_guest_os = 1;
// 		}
    // }

// #ifdef TARGET_I386
// 	if(GuestOS_index_c == 0 || GuestOS_index_c == 1)
// 		printf("its win xp \n");
// 	else if(GuestOS_index_c == 2 || GuestOS_index_c == 3)
// 		printf("its win 7 \n");
// 	else if(GuestOS_index_c == 4)
// 		printf("its linux \n");
// #endif

	if(found_guest_os) {
		decaf_unregister_callback(DECAF_TLB_EXEC_CB, insn_handle_c);
		linux_vmi_init();
	}

_skip_probe:

	if (count_out-- <= 0) // not find 
	{
		decaf_unregister_callback(DECAF_TLB_EXEC_CB, insn_handle_c);
		printf("oops! guest OS type cannot be decided. \n");
	}
}

module * vmi_find_module_by_key(const char *key)
{

	string temp(key);
	unordered_map < string, module * >::iterator iter = module_name.find(temp);
	if (iter != module_name.end()){
		return iter->second;
	}
	return NULL;
}

module * vmi_find_module_by_base(gva_t pgd, gva_t base)
{
	unordered_map < decaf_target_ulong, process *>::iterator iter = process_map.find(pgd);
	process *proc;
	CPUState *cs;

	if (iter == process_pid_map.end()) //pid not found
		return NULL;

	proc = iter->second;

	if(!proc->modules_extracted) {
		cs = decaf_get_current_cpu();
		traverse_mmap(cs, proc);
	}
		
	unordered_map < decaf_target_ulong, module *>::iterator iter_m = proc->module_list.find(base);
	if(iter_m == proc->module_list.end())
		return NULL;

	return iter_m->second;
}

module * vmi_find_module_by_pc(gva_t pc, gva_t pgd, gva_t *base)
{
	process *proc;
	CPUState *cs;
	if (pc >= VMI_guest_kernel_base) {
		proc = process_pid_map[0];
	}
    else {
		unordered_map < decaf_target_ulong, process * >::iterator iter_p = process_map.find(pgd);
		if (iter_p == process_map.end())
			return NULL;

		proc = iter_p->second;
	}

	if(!proc->modules_extracted) {
		cs = decaf_get_current_cpu();
		traverse_mmap(cs, proc);
	}
		

	unordered_map< uint32_t, module * >::iterator iter;
	for (iter = proc->module_list.begin(); iter != proc->module_list.end(); iter++) {
		module *mod = iter->second;
		if (iter->first <= pc && mod->size + iter->first > pc) {
			*base = iter->first;
			return mod;
		}
	}

    return NULL;
}

module * vmi_find_module_by_name(const char *name, gva_t pgd, gva_t *base)
{
	CPUState *cs;
	unordered_map < decaf_target_ulong, process * >::iterator iter_p = process_map.find(pgd);
	if (iter_p == process_map.end())
		return NULL;

	process *proc = iter_p->second;

	if(!proc->modules_extracted) {
		cs = decaf_get_current_cpu();
		traverse_mmap(cs, proc);
	}
		
	unordered_map< decaf_target_ulong, module * >::iterator iter;
	for (iter = proc->module_list.begin(); iter != proc->module_list.end(); iter++) {
		module *mod = iter->second;
		if (strcasecmp(mod->name, name) == 0) {
			*base = iter->first;
			return mod;
		}
	}

	return NULL;
}

process * vmi_find_process_by_pid(uint32_t pid)
{
	unordered_map < decaf_target_ulong, process * >::iterator iter = process_pid_map.find(pid);

	if (iter == process_pid_map.end())
		return NULL;

	return iter->second;
}

process * vmi_find_process_by_pgd(gva_t pgd)
{
    unordered_map < decaf_target_ulong, process * >::iterator iter = process_map.find(pgd);

    if (iter != process_map.end())
		return iter->second;

	return NULL;
}

process * vmi_find_process_by_name(const char *name)
{
	unordered_map < decaf_target_ulong, process * >::iterator iter;
	for (iter = process_map.begin(); iter != process_map.end(); iter++) {
		process * proc = iter->second;
		if (strcmp((const char *)name,proc->name) == 0) {
			return proc;
		}
	}
	return 0;
}

int vmi_create_process(process *proc)
{	
	VMI_Callback_Params params;

	proc->modules_extracted = true;
	
	params.cp.cr3 = proc->cr3;
	params.cp.pid = proc->pid;
	params.cp.name = proc->name;
    unordered_map < decaf_target_ulong, process * >::iterator iter1 = process_pid_map.find(proc->pid);
    if (iter1 != process_pid_map.end()) {
    	// Found an existing process with the same pid
    	// We force to remove that one.
        // monitor_printf(default_mon, "remove process pid %d", proc->pid);
    	vmi_remove_process(proc->pid);
    }

    unordered_map < decaf_target_ulong, process * >::iterator iter2 = process_map.find(proc->cr3);
    if (iter2 != process_map.end()) {
    	// Found an existing process with the same CR3
    	// We force to remove that process
        // monitor_printf(default_mon, "removing due to cr3 0x%08x\n", proc->cr3);
    	vmi_remove_process(iter2->second->pid);
    }

   	process_pid_map[proc->pid] = proc;
   	process_map[proc->cr3] = proc;

	basic_callback_dispatch(&VMI_callbacks[VMI_CREATEPROC_CB], &params);

	return 0;
}

int vmi_remove_process(uint32_t pid)
{
	VMI_Callback_Params params;
	unordered_map < decaf_target_ulong, process * >::iterator iter = process_pid_map.find(pid);

	if(iter == process_pid_map.end())
	    return -1;

	// params.rp.proc = iter->second;

	params.rp.cr3 = iter->second->cr3;
	params.rp.pid = iter->second->pid;
	params.rp.name = iter->second->name;
	// printf("removing %d %x %s\n", params.rp.pid, params.rp.cr3, params.rp.name);
	basic_callback_dispatch(&VMI_callbacks[VMI_REMOVEPROC_CB], &params);

	process_map.erase(iter->second->cr3);
	process_pid_map.erase(iter);
	delete iter->second;

	return 0;
}

int vmi_add_module(module *mod, const char *key){
	if(mod==NULL)
		return -1;
	string temp(key);
	unordered_map < string, module * >::iterator iter = module_name.find(temp);
	if (iter != module_name.end()) {
		return -1;
	}
	module_name[temp] = mod;
	return 1;
}

int vmi_insert_module(uint32_t pid, uint32_t base, module *mod)
{
	VMI_Callback_Params params;
	params.lm.pid = pid;
	params.lm.base = base;
	params.lm.name = mod->name;
	params.lm.size = mod->size;
	params.lm.full_name = mod->fullname;
	unordered_map < decaf_target_ulong, process *>::iterator iter = process_pid_map.find(pid);
	process *proc;

	if (iter == process_pid_map.end()) //pid not found
		return -1;

	proc = iter->second;
    	params.lm.cr3 = proc->cr3;

	//Now the pages within the module's memory region are all resolved
	//We also need to removed the previous modules if they happen to sit on the same region

	for (gva_t vaddr = base; vaddr < base + mod->size; vaddr += 4096) {
		proc->resolved_pages.insert(vaddr >> 12);
		proc->unresolved_pages.erase(vaddr >> 12);
		//TODO: UnloadModule callback
		proc->module_list.erase(vaddr);
	}

	//Now we insert the new module in module_list
	proc->module_list[base] = mod;

	//check_unresolved_hooks();

	basic_callback_dispatch(&VMI_callbacks[VMI_LOADMODULE_CB], &params);

	return 0;
}

int vmi_remove_module(uint32_t pid, uint32_t base)
{
	VMI_Callback_Params params;
	params.rm.pid = pid;
	params.rm.base = base;
	unordered_map < decaf_target_ulong, process *>::iterator iter = process_pid_map.find(pid);
	process *proc;

	if (iter == process_pid_map.end()) //pid not found
		return -1;

	proc = iter->second;
	params.rm.cr3 = proc->cr3;

	unordered_map < decaf_target_ulong, module *>::iterator m_iter = proc->module_list.find(base);
	if(m_iter == proc->module_list.end())
		return -1;

	module *mod = m_iter->second;

	params.rm.name = mod->name;
	params.rm.size = mod->size;
	params.rm.full_name = mod->fullname;

	proc->module_list.erase(m_iter);

	basic_callback_dispatch(&VMI_callbacks[VMI_REMOVEMODULE_CB], &params);

	for (uint32_t vaddr = base; vaddr < base + mod->size; vaddr += 4096) {
		proc->resolved_pages.erase(vaddr >> 12);
		proc->unresolved_pages.erase(vaddr >> 12);
	}

	return 0;
}

int vmi_dipatch_lmm(process *proc)
{

	VMI_Callback_Params params;
	params.cp.cr3 = proc->cr3;
	params.cp.pid = proc->pid;
	params.cp.name = proc->name;

	basic_callback_dispatch(&VMI_callbacks[VMI_CREATEPROC_CB], &params);

	return 0;
}

int vmi_dispatch_lm(module * m, process *p, gva_t base)	//vmi_dispatch_loadmodule
{
	VMI_Callback_Params params;
	params.lm.pid = p->pid;
	params.lm.base = base;
	params.lm.name = m->name;
	params.lm.size = m->size;
	params.lm.full_name = m->fullname;
	params.lm.cr3 = p->cr3;

	basic_callback_dispatch(&VMI_callbacks[VMI_LOADMODULE_CB], &params);

    return 0;
}

int vmi_is_module_extract_required()
{
	if(QLIST_EMPTY(&VMI_callbacks[VMI_LOADMODULE_CB]) && QLIST_EMPTY(&VMI_callbacks[VMI_REMOVEMODULE_CB]))
		return 0;

	return 1;
}

// AVB
// This functions returns if the inode_number for this particular module is 0
// This would be the case for windows modules
// int vmi_extract_symbols(module *mod, uint32_t base)
// {
// 	if(mod->inode_number == 0)
// 		return 0;
// 	if(!mod->symbols_extracted) 
//     {
// 		read_elf_info(mod->name, base, mod->inode_number);
// 		mod->symbols_extracted = 1;
// 	}
// 	return 1;
// }


DECAF_handle vmi_register_callback(
    VMI_callback_type_t cb_type,
    vmi_callback_func_t cb_func,
    int *cb_cond)
{
    if ((cb_type > VMI_LAST_CB) || (cb_type < 0)) {
        return (DECAF_NULL_HANDLE);
    }

    return (basic_callback_register(&VMI_callbacks[cb_type], (basic_callback_func_t)cb_func, cb_cond));
}

int vmi_unregister_callback(VMI_callback_type_t cb_type, DECAF_handle handle)
{
    if ((cb_type > VMI_LAST_CB) || (cb_type < 0)) {
        return (DECAF_NULL_HANDLE);
    }

    return (basic_callback_unregister(&VMI_callbacks[cb_type], handle));
}

void vmi_init(void)
{
#ifdef CONFIG_ENABLE_VMI
	printf("inside vmi init \n");
	insn_handle_c = decaf_register_callback(DECAF_TLB_EXEC_CB, guest_os_confirm, NULL);
#endif
}
