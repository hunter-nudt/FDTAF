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
 * Output.c
 *
 *    Created on: Sep 29, 2011
 *            Author: lok
 *    changed on: Oct 24, 2022
 *            author: aspen
 */

#include "shared/decaf-output.h"
#include "monitor/monitor.h"

// file pointers should never be in the kernel memory range so this should work
static const void* DECAF_OUTPUT_MONITOR_FD = (void*)0xFEEDBEEF;

FILE* ofp = NULL;
Monitor* p_mon = NULL;

void decaf_printf(const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    decaf_vprintf(ofp, fmt, ap);
    va_end(ap);
}

void decaf_fprintf(FILE* fp, const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    if ( (p_mon != NULL) && (((void*)fp == (void*)p_mon) || (fp == DECAF_OUTPUT_MONITOR_FD)) )
    {
        monitor_vprintf(p_mon, fmt, ap);
    }
    else
    {
        decaf_vprintf(fp, fmt, ap);
    }
    va_end(ap);
}

void decaf_mprintf(const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    if (p_mon != NULL)
    {
        monitor_vprintf(p_mon, fmt, ap);
    }
    else
    {
        vprintf(fmt, ap);
    }
    va_end(ap);
}

void decaf_vprintf(FILE* fp, const char *fmt, va_list ap)
{
    if (fp == NULL)
    {
        //that means either use stdout or monitor
        if (p_mon != NULL)
        {
            monitor_vprintf(p_mon, fmt, ap);
        }
        else
        {
            vprintf(fmt, ap);
        }
    }
    else
    {
        vfprintf(fp, fmt, ap);
    }
}

void decaf_flush(void)
{
    decaf_fflush(ofp);
}

void decaf_fflush(FILE* fp)
{
    if (fp == NULL)
    {
        if (p_mon != NULL)
        {
            //nothing to do here
        }
        else
        {
            fflush(stdout);
        }
    }
    else
    {
        fflush(fp);
    }
}

void decaf_do_set_output_file(Monitor *mon, const char* fileName)
{
    if (ofp != NULL)
    {
        return;
    }

    if (strcmp(fileName, "stdout") == 0)
    {
        decaf_output_cleanup();
        return;
    }
    p_mon = mon; //make a local copy of the monitor
    //open the file
    ofp = fopen(fileName, "w");
    if (ofp == NULL)
    {
        decaf_printf("Could not open the file [%s]\n", fileName);
    }
}

void decaf_output_init(Monitor *mon)
{
    if (mon != NULL)
    {
        p_mon = mon;
    }
    else
    {
        return;
    }
}

void decaf_output_cleanup(void)
{
    if (ofp != NULL)
    {
        fflush(ofp);
        fclose(ofp);
    }
    ofp = NULL;
    p_mon = NULL;
}


FILE* decaf_get_output_fp(void)
{
    return (ofp);
}

Monitor* decaf_get_output_mon(void)
{
    return (p_mon);
}

const FILE* decaf_get_monitor_fp(void)
{
    return (DECAF_OUTPUT_MONITOR_FD);
}

// void test_hello(void)
// {
//     printf("hello world!\n");
// }