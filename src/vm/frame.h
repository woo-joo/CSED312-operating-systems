#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "threads/palloc.h"

/* Initialization. */
void frame_init(void);

/* Allocation, free. */
void *frame_allocate(enum palloc_flags, void *);
void frame_free(void *);

/* Pin. */
void frame_pin(void *);
void frame_unpin(void *);

#endif /* vm/frame.h */
