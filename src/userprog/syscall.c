#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/shutdown.h"
#include "userprog/pagedir.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static void syscall_handler(struct intr_frame *);

static void check_vaddr(const void *vaddr);

static void syscall_halt(void);

/* Registers the system call interrupt handler. */
void syscall_init(void)
{
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/* Pops the system call number and handles system call
   according to it. */
static void
syscall_handler(struct intr_frame *f UNUSED)
{
    void *esp = f->esp;
    int syscall_num;

    check_vaddr(esp);
    check_vaddr(esp + sizeof(int) - 1);

    syscall_num = *(int *)esp;

    switch (syscall_num)
    {
    case SYS_HALT:
    {
        syscall_halt();
        NOT_REACHED();
    }
    case SYS_EXIT:
    {
        check_vaddr(esp + sizeof(int));
        check_vaddr(esp + 2 * sizeof(int) - 1);
        int status = *(int *)(esp + sizeof(int));
        syscall_exit(status);
        NOT_REACHED();
    }
    default:
        syscall_exit(-1);
    }
}

/* Checks user-provided virtual address. If it is
   invalid, terminates the current process. */
static void
check_vaddr(const void *vaddr)
{
    if (!vaddr || !is_user_vaddr(vaddr) ||
        !pagedir_get_page(thread_get_pagedir(), vaddr))
        syscall_exit(-1);
}

/* Handles halt() system call. */
static void syscall_halt(void)
{
    shutdown_power_off();
}

/* Handles exit() system call. */
void syscall_exit(int status)
{
    printf("%s: exit(%d)\n", thread_name(), status);
    thread_exit();
}
