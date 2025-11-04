#ifndef KERNELDRIVER_MEMORY_H
#define KERNELDRIVER_MEMORY_H

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/mm.h> /* for high_memory, phys_addr_t */
#include <linux/uaccess.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/version.h>


phys_addr_t translate_linear_address(struct mm_struct *mm, uintptr_t va);
bool read_physical_address(phys_addr_t pa, void *buffer, size_t size);
bool write_physical_address(phys_addr_t pa, void *buffer, size_t size);

#ifndef ARCH_HAS_VALID_PHYS_ADDR_RANGE
static inline int valid_phys_addr_range(phys_addr_t addr, size_t count)
{
    if (count == 0)
        return 1;
    if (addr + (phys_addr_t)count < addr) /* overflow */
        return 0;
    return addr + count <= __pa(high_memory);
}
#endif

static inline bool read_process_memory_inline(pid_t pid, uintptr_t addr, void *buffer, size_t size)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct pid *pid_struct;
    phys_addr_t pa;
    bool result = false;

    pid_struct = find_get_pid(pid);
    if (!pid_struct)
        return false;
    task = get_pid_task(pid_struct, PIDTYPE_PID);
    if (!task)
        return false;
    mm = get_task_mm(task);
    if (!mm)
        return false;

    pa = translate_linear_address(mm, addr);
    if (pa)
        result = read_physical_address(pa, buffer, size);

    mmput(mm);
    return result;
}

static inline bool write_process_memory_inline(pid_t pid, uintptr_t addr, void *buffer, size_t size)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct pid *pid_struct;
    phys_addr_t pa;
    bool result = false;

    pid_struct = find_get_pid(pid);
    if (!pid_struct)
        return false;
    task = get_pid_task(pid_struct, PIDTYPE_PID);
    if (!task)
        return false;
    mm = get_task_mm(task);
    if (!mm)
        return false;

    pa = translate_linear_address(mm, addr);
    if (pa)
        result = write_physical_address(pa, buffer, size);

    mmput(mm);
    return result;
}

static inline bool read_process_memory(pid_t pid, uintptr_t addr, void *buffer, size_t size)
{
    return read_process_memory_inline(pid, addr, buffer, size);
}

static inline bool write_process_memory(pid_t pid, uintptr_t addr, void *buffer, size_t size)
{
    return write_process_memory_inline(pid, addr, buffer, size);
}

#endif /* KERNELDRIVER_MEMORY_H */
