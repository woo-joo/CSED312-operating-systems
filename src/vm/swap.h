#ifndef VM_SWAP_H
#define VM_SWAP_H

#include <stddef.h>

/* Initialization. */
void swap_init(void);

/* Swap. */
void swap_in(size_t, void *);
size_t swap_out(void *);

#endif /* vm/swap.h */
