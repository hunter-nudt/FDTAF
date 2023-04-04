//  2022 Nov 14
//  Author: aspen

#include "qemu/osdep.h"
#include "shared/decaf-main.h"
#include "hw/core/cpu.h"

CPUState *decaf_get_current_cpu(void)
{
    return current_cpu;
}