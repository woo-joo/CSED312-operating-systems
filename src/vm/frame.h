#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "threads/palloc.h"

/* Initialization. */
void frame_init(void);

/* Allocation. */
void *frame_allocate(enum palloc_flags, void *);

#endif /* vm/frame.h */
