#include "vm/swap.h"
#include "devices/block.h"
#include <bitmap.h>
#include "threads/synch.h"
#include "threads/vaddr.h"

#define NUM_SECTORS_PER_PAGE (PGSIZE / BLOCK_SECTOR_SIZE)

/* A swap block. */
static struct block *swap_block;

/* A swap table. Free slots are represented as 0. */
static struct bitmap *swap_table;
static size_t swap_table_size;

/* A lock for swap table synchronization. The swap
   table is global so that it should be synchronized. */
static struct lock swap_table_lock;

/* Initializes the frame allocator. */
void swap_init(void)
{
    swap_block = block_get_role(BLOCK_SWAP);
    swap_table_size = block_size(swap_block) / NUM_SECTORS_PER_PAGE;
    swap_table = bitmap_create(swap_table_size);
    lock_init(&swap_table_lock);
}
