#include "vm/frame.h"
#include <stdbool.h>
#include <stdint.h>
#include <hash.h>
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"

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

/* Search. */
static struct frame *frame_lookup(void *);

/* Helper functions. */
static hash_hash_func frame_hash;
static hash_less_func frame_less;

/* Initializes the frame allocator. */
void frame_init(void)
{
    hash_init(&frame_table, frame_hash, frame_less, NULL);
    lock_init(&frame_table_lock);
}

/* Allocates a frame for UPAGE and returns its address,
   KPAGE. */
void *frame_allocate(enum palloc_flags flags, void *upage)
{
    struct frame *f;
    void *kpage;

    ASSERT(flags & PAL_USER);
    ASSERT(is_user_vaddr(upage));

    lock_acquire(&frame_table_lock);

    kpage = palloc_get_page(flags);

    if (kpage)
    {
        f = (struct frame *)malloc(sizeof *f);

        f->kpage = kpage;
        f->upage = upage;

        f->tid = thread_tid();

        hash_insert(&frame_table, &f->ftelem);
    }

    lock_release(&frame_table_lock);

    return kpage;
}

/* Frees a frame associated with KPAGE. */
void frame_free(void *kpage)
{
    struct frame *f;

    ASSERT(is_kernel_vaddr(kpage));

    lock_acquire(&frame_table_lock);

    f = frame_lookup(kpage);
    if (!f)
        PANIC("Invalid kpage");

    hash_delete(&frame_table, &f->ftelem);
    palloc_free_page(f->kpage);
    pagedir_clear_page(thread_get_from_tid(f->tid)->pagedir, f->upage);
    free(f);

    lock_release(&frame_table_lock);
}

/* Returns the frame containing the given virtual KPAGE,
   or a null pointer if no such frame exists. */
static struct frame *frame_lookup(void *kpage)
{
    struct frame p;
    struct hash_elem *e;

    p.kpage = kpage;
    e = hash_find(&frame_table, &p.ftelem);

    return e != NULL ? hash_entry(e, struct frame, ftelem) : NULL;
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
