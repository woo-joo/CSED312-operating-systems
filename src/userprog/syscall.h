#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init(void);

struct lock *syscall_get_filesys_lock(void);

void syscall_exit(int);
void syscall_close(int);
#ifdef VM
void syscall_munmap(mapid_t);
#endif

#endif /* userprog/syscall.h */
