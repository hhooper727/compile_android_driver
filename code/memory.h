#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/mm.h> /* for high_memory, phys_addr_t */

phys_addr_t translate_linear_address(struct mm_struct *mm, uintptr_t va);

bool read_physical_address(phys_addr_t pa, void *buffer, size_t size);

bool write_physical_address(phys_addr_t pa, void *buffer, size_t size);

bool read_process_memory(pid_t pid, uintptr_t addr, void *buffer, size_t size);

bool write_process_memory(pid_t pid, uintptr_t addr, void *buffer, size_t size);

#ifndef ARCH_HAS_VALID_PHYS_ADDR_RANGE
/*
 * Provide a local inline implementation so that every .c including this
 * header gets its own definition (no external symbol produced).
 *
 * Using static inline avoids creating an external symbol; inlining
 * keeps calls local to each translation unit.
 */
static inline int valid_phys_addr_range(phys_addr_t addr, size_t count)
{
    /* Ensure overflow is handled and compare against physical high_memory */
    if (count == 0)
        return 1;
    if (addr + (phys_addr_t)count < addr) /* overflow */
        return 0;
    return addr + count <= __pa(high_memory);
}
#endif
