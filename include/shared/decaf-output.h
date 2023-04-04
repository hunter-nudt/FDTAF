/*
Copyright (C) <2012> <Syracuse System Security (Sycure) Lab>

decaf is based on QEMU, a whole-system emulator. You can redistribute
and modify it under the terms of the GNU LGPL, version 2.1 or later,
but it is made available WITHOUT ANY WARRANTY. See the top-level
README file for more details.

For more information about decaf and other softwares, see our
web site at:
http://sycurelab.ecs.syr.edu/

If you have any questions about decaf,please post it on
http://code.google.com/p/decaf-platform/
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

void decaf_printf(const char* fmt, ...);
void decaf_mprintf(const char* fmt, ...);
void decaf_fprintf(FILE* fp, const char* fmt, ...);
void decaf_vprintf(FILE* fp, const char* fmt, va_list ap);
void decaf_flush(void);
void decaf_fflush(FILE* fp);

FILE* decaf_get_output_fp(void);
Monitor* decaf_get_output_mon(void);
const FILE* decaf_get_monitor_fp(void);

void decaf_do_set_output_file(Monitor* mon, const char* fileName);
void decaf_output_init(Monitor* mon);
void decaf_output_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif /* OUTPUT_H */