/*
Copyright (C) <2012> <Syracuse System Security (Sycure) Lab>

FDTAF is based on QEMU, a whole-system emulator. You can redistribute
and modify it under the terms of the GNU LGPL, version 2.1 or later,
but it is made available WITHOUT ANY WARRANTY. See the top-level
README file for more details.

For more information about FDTAF and other softwares, see our
web site at:
http://sycurelab.ecs.syr.edu/

If you have any questions about FDTAF,please post it on
http://code.google.com/p/fdtaf-platform/
*/

/*
 *  fdtaf-vmi-callback.h
 *
 *  Created on: Oct 16, 2012
 *      Author: lok
 *  changed on: Oct 31, 2022
 *      author: aspen
 *  The idea behind this file is to create a simple data structure for
 *  maintaining a simple callback interface. In this way the core developers
 *  can expose their own callbacks. For example, procmod can now expose
 *  callbacks for loadmodule instead of having the plugin directly set the
 *  single loadmodule_notifier inside procmod, which is messy
 */

#ifndef BASIC_CALLBACK_H
#define BASIC_CALLBACK_H

#include "qemu/queue.h"
#include "shared/fdtaf-types-common.h"


#ifdef __cplusplus
extern "C"
{
#endif

typedef void (*basic_callback_func_t) (void* params);

typedef struct basic_callback_entry{
        int enabled;
        basic_callback_func_t callback;
        QLIST_ENTRY(basic_callback_entry) link;
}basic_callback_entry_t;

typedef QLIST_HEAD(basic_callback_list_head, basic_callback_entry) basic_callback_t; 

basic_callback_t* basic_callback_new(void);

fdtaf_errno_t basic_callback_init(basic_callback_t* p_list);

fdtaf_errno_t basic_callback_clear(basic_callback_t* p_list);

fdtaf_errno_t basic_callback_delete(basic_callback_t* p_list);

void basic_callback_dispatch(basic_callback_t* p_list, void* params);

fdtaf_handle basic_callback_register(
    basic_callback_t* p_list,
    basic_callback_func_t cb_func,
    int cb_cond);

fdtaf_errno_t basic_callback_unregister(basic_callback_t* p_list, fdtaf_handle handle);

#ifdef __cplusplus
}
#endif

#endif /* BASIC_CALLBACK_H */
