/*
Copyright (C) <2012> <Syracuse System Security (Sycure) Lab>

fdtaf is based on QEMU, a whole-system emulator. You can redistribute
and modify it under the terms of the GNU LGPL, version 2.1 or later,
but it is made available WITHOUT ANY WARRANTY. See the top-level
README file for more details.

For more information about fdtaf and other softwares, see our
web site at:
http://sycurelab.ecs.syr.edu/

If you have any questions about fdtaf,please post it on
http://code.google.com/p/fdtaf-platform/
*/
/*
 * Output.h
 *
 *  Created on: Sep 29, 2011
 *      Author: lok
 */

#ifndef OUTPUT_H
#define OUTPUT_H

#include "qemu/osdep.h"

#ifdef __cplusplus
extern "C"
{
#endif

void fdtaf_printf(const char* fmt, ...);
void fdtaf_mprintf(const char* fmt, ...);
void fdtaf_fprintf(FILE* fp, const char* fmt, ...);
void fdtaf_vprintf(FILE* fp, const char* fmt, va_list ap);
void fdtaf_flush(void);
void fdtaf_fflush(FILE* fp);

FILE* fdtaf_get_output_fp(void);
Monitor* fdtaf_get_output_mon(void);
const FILE* fdtaf_get_monitor_fp(void);

void fdtaf_do_set_output_file(Monitor* mon, const char* fileName);
void fdtaf_output_init(Monitor* mon);
void fdtaf_output_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif /* OUTPUT_H */