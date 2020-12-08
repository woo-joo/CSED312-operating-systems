#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/synch.h"
#include "threads/thread.h"
#ifdef VM
#include "filesys/off_t.h"
#endif

/* Process identifier. */
typedef int pid_t;
#define PID_ERROR ((pid_t)-1)

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

/* A file descriptor entry. */
struct file_descriptor_entry
{
    int fd;                   /* File descriptor. */
    struct file *file;        /* File. */
    struct list_elem fdtelem; /* List element for file descriptor table. */
};

#ifdef VM
/* A mmap descriptor entry. */
struct mmap_descriptor_entry
{
    /* Shared between process.c and syscall.c. */
    mapid_t mapid;            /* Memory mapping identifier. */
    struct file *file;        /* File. */
    off_t size;               /* File size. */
    void *upage;              /* Mapped user virtual page. */
    struct list_elem mdtelem; /* List element for mmap descriptor table. */
};
#endif

tid_t process_execute(const char *);
int process_wait(tid_t);
void process_exit(void);
void process_activate(void);

struct process *process_get_child(pid_t);
void process_remove_child(struct process *);
struct file_descriptor_entry *process_get_fde(int);

#ifdef VM
struct mmap_descriptor_entry *process_get_mde(mapid_t);
#endif

#endif /* userprog/process.h */
