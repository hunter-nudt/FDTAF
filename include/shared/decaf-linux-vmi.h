
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


 * linux_vmi_new.h
 *
 *  Created on: June 26, 2015
 *      Author: Abhishek V B
 *  changed on: Nov 3, 2022
 *      author: aspen
 */


#ifndef DECAF_LINUX_VMI_H
#define DECAF_LINUX_VMI_H

#include "shared/decaf-types-common.h"

#ifdef __cplusplus
extern "C" 
{
#endif

#define GUEST_OS_THREAD_SIZE 8192

#define SIZEOF_COMM 16

int find_linux(CPUState *cs);
void linux_vmi_init(void);
gpa_t mips_get_cur_pgd(CPUState *cs);
void traverse_mmap(CPUState *cs, void *opaque);
void print_loaded_modules(CPUState *cs);

#ifdef __cplusplus
}
#endif

#endif /* DECAF_LINUX_VMI_H */


