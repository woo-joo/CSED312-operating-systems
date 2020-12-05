#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "threads/palloc.h"
#include "threads/thread.h"

/* Initialization. */
void frame_init(void);

/* Allocation, free. */
void *frame_allocate(enum palloc_flags, void *);
void frame_free(void *);
void frame_delete_all(tid_t);

/* Pin. */
void frame_pin(void *);
void frame_unpin(void *);

/* Lock. */
struct lock *frame_get_frame_table_lock(void);

#endif /* vm/frame.h */
