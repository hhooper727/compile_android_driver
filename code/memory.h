#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/mm.h> /* for high_memory, phys_addr_t */
#include <linux/uaccess.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/version.h>

phys_addr_t translate_linear_address(struct mm_struct *mm, uintptr_t va);

/* Physical read/write helpers (kept as extern prototypes for clarity) */
bool read_physical_address(phys_addr_t pa, void *buffer, size_t size);
bool write_physical_address(phys_addr_t pa, void *buffer, size_t size);

/* Process memory helpers - we provide inline implementations so each .c
 * that includes this header has its own definition (no external symbol).
 */
bool read_process_memory(pid_t pid, uintptr_t addr, void *buffer, size_t size);
bool write_process_memory(pid_t pid, uintptr_t addr, void *buffer, size_t size);

#ifndef ARCH_HAS_VALID_PHYS_ADDR_RANGE
/*
 * Provide a local inline implementation so that every .c including this
 * header gets its own definition (no external symbol produced).
 */
static inline int valid_phys_addr_range(phys_addr_t addr, size_t count)
{
    if (count == 0)
        return 1;
    if (addr + (phys_addr_t)count < addr) /* overflow */
        return 0;
    return addr + count <= __pa(high_memory);
}
#endif

/* Implement read_process_memory / write_process_memory as static inline.
 * This avoids external symbol dependencies between .o files (safe for LTO).
 * They call translate_linear_address and physical read/write helpers.
 */
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

/* Provide non-inline wrapper names so existing callers that expect the
 * function names read_process_memory / write_process_memory still work.
 * These wrappers are declared static inline and simply call the inline
 * implementations above (keeps symbol local to each TU).
 */
static inline bool read_process_memory(pid_t pid, uintptr_t addr, void *buffer, size_t size)
{
    return read_process_memory_inline(pid, addr, buffer, size);
}

static inline bool write_process_memory(pid_t pid, uintptr_t addr, void *buffer, size_t size)
{
    return write_process_memory_inline(pid, addr, buffer, size);
}
