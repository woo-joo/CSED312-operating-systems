#include "vm/frame.h"
#include <stdbool.h>
#include <stdint.h>
#include <hash.h>
#include "threads/synch.h"
#include "threads/thread.h"

/* A frame table entry. */
struct frame
{
    /* Shared between vm/frame.c and userprog/process.c. */
    void *kpage; /* Kernel virtual page. */
    void *upage; /* User virtual page. */

    /* Shared between vm/frame.c and threads/thread.c. */
    tid_t tid; /* Id of thread occupying frame. */

    /* Shared between vm/frame.c and userprog/process.c. */
    struct hash_elem ftelem; /* Hash element for frame table. */
};

/* A frame table. */
static struct hash frame_table;

/* A lock for frame table synchronization. The frame
   table is global so that it should be synchronized. */
static struct lock frame_table_lock;

/* Helper functions. */
static hash_hash_func frame_hash;
static hash_less_func frame_less;

/* Initializes the frame allocator. */
void frame_init(void)
{
    hash_init(&frame_table, frame_hash, frame_less, NULL);
    lock_init(&frame_table_lock);
}

/* Returns a hash of KPAGE of F that E is embedded inside. */
static unsigned int frame_hash(const struct hash_elem *e, void *aux UNUSED)
{
    struct frame *f = hash_entry(e, struct frame, ftelem);

    return hash_bytes(&f->kpage, sizeof f->kpage);
}

/* Compares KPAGE of two hash elements A and B. Returns
   true if A is less than B, or false if A is greater
   than or equal to B. */
static bool frame_less(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
    struct frame *a_f = hash_entry(a, struct frame, ftelem);
    struct frame *b_f = hash_entry(b, struct frame, ftelem);

    return a_f->kpage < b_f->kpage;
}
