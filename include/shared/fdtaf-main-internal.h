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
#ifndef FDTAF_MAIN_INTERNAL_H
#define FDTAF_MAIN_INTERNAL_H

#include "monitor/monitor-internal.h"
#include "shared/fdtaf-types-common.h"


#ifdef __cplusplus
extern "C" 
{
#endif

/*************************************************************************
 * The Plugin interface comes first
 *************************************************************************/
/// primary structure for FDTAF plugin,
// callbacks have been removed due to the new interface
// including callbacks and states
// tainting has also been removed since we are going to
// have a new tainting interface that is dynamically
// controllable - which will be more like a util than
// something that is built directly into FDTAF
typedef struct _plugin_interface {
    // array of monitor commands
    const HMPCommand *mon_cmds; // AWH - was term_cmd_t *term_cmds
    // array of informational commands
    const HMPCommand *info_cmds; // AWH - was term_cmd_t
    /*!
    * \brief callback for cleaning up states in plugin.
    * TEMU plugin must release all allocated resources in this function
    */
    void (*plugin_cleanup)(void);

    //TODO: may need to remove it.
    //void (*send_keystroke) (int reg);

    //TODO: need to change it into using our generic callback interface
    void (*after_loadvm) (const char *param);

    /// \brief CR3 of a specified process to be monitored.
    /// 0 means system-wide monitoring, including all processes and kernel.
    union
    {
        uint32_t monitored_cr3;
        uint32_t monitored_pgd; //alias
    };
} plugin_interface_t;

extern plugin_interface_t *fdtaf_plugin;

/**
 * Flush related structs AVB
 */
typedef struct __flush_node flush_node;
typedef struct __flush_list flush_list;

typedef struct __flush_node{
	int type; //Type of cache to flush
	unsigned int addr;
	flush_node *next;
} flush_node;

typedef struct __flush_list {
	flush_node *head;
	size_t size;
} flush_list;

extern flush_list flush_list_internal;

extern void flush_list_insert(flush_list *list, int type, uint32_t addr);

//LOK: Separate data structure for FDTAF commands and plugin commands
extern HMPCommand FDTAF_mon_cmds[];
extern HMPCommand FDTAF_info_cmds[];

extern void fdtaf_bdrv_open(int index, void *opaque);

/****** Functions used internally ******/
extern void fdtaf_nic_receive(uint8_t * buf, int size, int cur_pos, int start, int stop);
extern void fdtaf_nic_send(uint32_t addr, int size, uint8_t * buf);
extern void fdtaf_nic_in(uint32_t addr, int size);
extern void fdtaf_nic_out(uint32_t addr, int size);

extern void fdtaf_read_keystroke(void *s);

extern void fdtaf_after_loadvm(const char *);
extern void fdtaf_init(void);

extern void fdtaf_update_cpl(int cpl);
//extern void FDTAF_do_interrupt(int intno, int is_int, target_ulong next_eip);
extern void fdtaf_after_iret_protected(void);
//extern void TEMU_update_cpustate(void);
extern void fdtaf_loadvm(void *opaque);

#ifdef __cplusplus
}
#endif

#endif //FDTAF_MAIN_INTERNAL_H