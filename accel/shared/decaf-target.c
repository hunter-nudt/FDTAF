#include "qemu/osdep.h"
#include "hw/core/cpu.h"
#include "exec/exec-all.h"
#include "exec/cpu-all.h"
#include "shared/decaf-target.h"

#ifdef TARGET_MIPS      /* DECAF_TARGET_MIPS */

/* Check if the current execution of guest system is in kernel mode (i.e., ring-0) */ 
int decaf_is_in_kernel(CPUState *cs)
{
    CPUMIPSState *env = (CPUMIPSState *)cs->env_ptr;
    return ((env->hflags & MIPS_HFLAG_MODE) == MIPS_HFLAG_KM);
}


gva_t decaf_get_pc(CPUState* cs)
{
    CPUMIPSState *env = (CPUMIPSState *)cs->env_ptr;
    return (env->active_tc.PC);
}

gpa_t decaf_get_pgd(CPUState* cs)
{
    CPUMIPSState *env = (CPUMIPSState *)cs->env_ptr;
    return (env->CP0_EntryHi);
}

gva_t decaf_get_esp(CPUState* cs)
{
    CPUMIPSState *env = (CPUMIPSState *)cs->env_ptr;
  /* AWH - General-purpose register 29 (of 32) is the stack pointer */
    return (env->active_tc.gpr[29]);
}

int is_kernel_address(gva_t addr)
{
    if(((addr >= TARGET_KERNEL_START) && (addr < TARGET_KERNEL_END))
    || ((addr >= TARGET_KERNEL_IMAGE_START) && (addr < (TARGET_KERNEL_IMAGE_START + TARGET_KERNEL_IMAGE_SIZE))))
    {
        return 1;
    }
    else
    {
        return 0;
    }
}
#elif defined(TARGET_I386)    /* DECAF_TARGET_X86 */

/* Check if the current execution of guest system is in kernel mode (i.e., ring-0) */
int decaf_is_in_kernel(CPUState *cs)
{
    CPUX86State *env = (CPUX86State *)cs->env_ptr;
    return ((env->hflags & HF_CPL_MASK) == 0);
}

gva_t decaf_get_pc(CPUState* cs)
{
    CPUX86State *env = (CPUX86State *)cs->env_ptr;
    return (env->eip + env->segs[R_CS].base);
}

gpa_t decaf_get_pgd(CPUState* cs)
{
    CPUX86State *env = (CPUX86State *)cs->env_ptr;
    return (env->cr[3]);
}

gva_t decaf_get_esp(CPUState* cs)
{
    CPUX86State *env = (CPUX86State *)cs->env_ptr;
    return (env->regs[R_ESP]);
}

int is_kernel_address(gva_t addr)
{
    if(((addr >= TARGET_KERNEL_START) && (addr < TARGET_KERNEL_END))
    || ((addr >= TARGET_KERNEL_IMAGE_START) && (addr < (TARGET_KERNEL_IMAGE_START + TARGET_KERNEL_IMAGE_SIZE))))
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

#elif defined(TARGET_ARM)   /* DECAF_TARGET_ARM */
#include "target/arm/internals.h"
int decaf_is_in_kernel(CPUState *cs)
{
    CPUARMState *env = (CPUARMState *)cs->env_ptr;
    return ((env->uncached_cpsr & CPSR_M) != ARM_CPU_MODE_USR);
}

gva_t decaf_get_pc(CPUState* cs)
{
    CPUARMState *env = (CPUARMState *)cs->env_ptr;
    return (env->regs[15]);
}

//Based this off of helper.c in get_level1_table_address
gpa_t decaf_get_pgd(CPUState* cs)
{
    CPUARMState *env = (CPUARMState *)cs->env_ptr;
    ARMMMUIdx mmu_idx = arm_mmu_idx(env);
    TCR *tcr = regime_tcr(env, mmu_idx);
    uint64_t regime;
    if (mmu_idx == ARMMMUIdx_Stage2) {
        regime = env->cp15.vttbr_el2;
    }
    else if (mmu_idx == ARMMMUIdx_Stage2_S) {
        regime = env->cp15.vsttbr_el2;
    }
    else {
        regime = env->cp15.ttbr0_el[regime_el(env, mmu_idx)];
    }
    return regime & tcr->base_mask;
}

gva_t decaf_get_esp(CPUState* cs)
{
    CPUARMState *env = (CPUARMState *)cs->env_ptr;
    return (env->regs[13]);
}

int is_kernel_address(gva_t addr)
{
    if(((addr >= TARGET_KERNEL_START) && (addr < TARGET_KERNEL_END))
    || ((addr >= TARGET_KERNEL_IMAGE_START) && (addr < (TARGET_KERNEL_IMAGE_START + TARGET_KERNEL_IMAGE_SIZE))))
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

#else

int decaf_is_in_kernel(CPUState *cs)
{
    return 0;
}

gva_t decaf_get_pc(CPUState* cs)
{
    return 0;
}

//Based this off of helper.c in get_level1_table_address
gpa_t decaf_get_pgd(CPUState* cs)
{
    return 0;
}

gva_t decaf_get_esp(CPUState* cs)
{
    return 0;
}

int is_kernel_address(gva_t addr)
{
    return 0;
}

#endif