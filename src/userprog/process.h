#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "lib/user/syscall.h"
#include "threads/synch.h"
#include "threads/thread.h"

#define MAX_ARGS 128

/* A process control block. */
struct process
{
    /* Owned by process.c. */
    const char *file_name; /* File name to execute. */

    /* Shared between process.c and syscall.c. */
    pid_t pid;                  /* Process identifier. */
    struct thread *parent;      /* Parent process. */
    struct list_elem childelem; /* List element for children list. */
    bool is_loaded;             /* Whether program is loaded. */
    struct semaphore load_sema; /* Semaphore for waiting until load. */
    bool is_exited;             /* Whether process is exited. */
    struct semaphore exit_sema; /* Semaphore for waiting until exit. */
    int exit_status;            /* Exit status. */
};

tid_t process_execute(const char *file_name);
int process_wait(tid_t);
void process_exit(void);
void process_activate(void);

struct process *process_get_child(pid_t);
void process_remove_child(struct process *);

#endif /* userprog/process.h */
