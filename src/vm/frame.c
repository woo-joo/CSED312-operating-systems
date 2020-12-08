#include "vm/frame.h"
#include <stdbool.h>
#include <stdint.h>
#include <hash.h>
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"

/* A frame table entry. */
struct frame
{
    /* Shared between vm/frame.c, userprog/process.c, and vm/page.c. */
    void *kpage; /* Kernel virtual page. */
    void *upage; /* User virtual page. */

    /* Shared between vm/frame.c and threads/thread.c. */
    tid_t tid; /* Id of thread occupying frame. */

    /* Shared between vm/frame.c, userprog/process.c, and vm/page.c. */
    bool is_pinned; /* Whether frame is pinned. */

    /* Shared between vm/frame.c, userprog/process.c, and vm/page.c. */
    struct hash_elem ftelem; /* Hash element for frame table. */
    struct list_elem fcelem; /* List element for frame clock. */
};

/* A frame table. */
static struct hash frame_table;

/* A frame clock. Used for clock algorithm. */
static struct list frame_clock;
static struct list_elem *frame_clock_hand;

/* A lock for frame table synchronization. The frame
   table is global so that it should be synchronized. */
static struct lock frame_table_lock;

/* Search. */
static struct frame *frame_lookup(void *);

/* Eviction. */
static void frame_evict(void);
static struct frame *frame_find_victim(void);
static struct list_elem *frame_clock_next(struct list_elem *);

/* Helper functions. */
static hash_hash_func frame_hash;
static hash_less_func frame_less;

/* Initializes the frame allocator. */
void frame_init(void)
{
    hash_init(&frame_table, frame_hash, frame_less, NULL);
    list_init(&frame_clock);
    frame_clock_hand = list_head(&frame_clock);
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

    if (!kpage)
    {
        frame_evict();
        kpage = palloc_get_page(flags);

        ASSERT(kpage != NULL);
    }

    f = (struct frame *)malloc(sizeof *f);

    f->kpage = kpage;
    f->upage = upage;

    f->tid = thread_tid();

    f->is_pinned = true;

    hash_insert(&frame_table, &f->ftelem);
    list_push_back(&frame_clock, &f->fcelem);

    lock_release(&frame_table_lock);

    return kpage;
}

/* Frees a frame associated with KPAGE. */
void frame_free(void *kpage)
{
    struct frame *f;
    bool is_held = lock_held_by_current_thread(&frame_table_lock);

    ASSERT(is_kernel_vaddr(kpage));

    if (!is_held)
        lock_acquire(&frame_table_lock);

    f = frame_lookup(kpage);
    if (!f)
        PANIC("Invalid kpage");

    hash_delete(&frame_table, &f->ftelem);
    list_remove(&f->fcelem);
    palloc_free_page(f->kpage);
    pagedir_clear_page(thread_get_from_tid(f->tid)->pagedir, f->upage);
    free(f);

    if (!is_held)
        lock_release(&frame_table_lock);
}

/* Deletes all frames with tid TID. Just deletes entries from
   the frame table. Does not free pages. */
void frame_delete_all(tid_t tid)
{
    struct list_elem *e;

    lock_acquire(&frame_table_lock);

    for (e = list_begin(&frame_clock); e != list_end(&frame_clock);)
    {
        struct frame *f = list_entry(e, struct frame, fcelem);

        if (f->tid == tid)
        {
            hash_delete(&frame_table, &f->ftelem);
            e = list_remove(e);
            free(f);
        }
        else
            e = list_next(e);
    }

    lock_release(&frame_table_lock);
}

/* Pins a frame associated with KPAGE. */
void frame_pin(void *kpage)
{
    struct frame *f;
    bool is_held = lock_held_by_current_thread(&frame_table_lock);

    if (!is_held)
        lock_acquire(&frame_table_lock);

    f = frame_lookup(kpage);
    if (!f)
        PANIC("Invalid kpage");

    f->is_pinned = true;

    if (!is_held)
        lock_release(&frame_table_lock);
}

/* Unpins a frame associated with KPAGE. */
void frame_unpin(void *kpage)
{
    struct frame *f;

    lock_acquire(&frame_table_lock);

    f = frame_lookup(kpage);
    if (!f)
        PANIC("Invalid kpage");

    f->is_pinned = false;

    lock_release(&frame_table_lock);
}

struct lock *frame_get_frame_table_lock(void)
{
    return &frame_table_lock;
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

/* Evicts a frame. */
static void frame_evict(void)
{
    struct frame *victim_f = frame_find_victim();
    struct thread *victim_t = thread_get_from_tid(victim_f->tid);
    bool is_dirty = pagedir_is_dirty(victim_t->pagedir, victim_f->upage);

    page_evict(&victim_t->spt, victim_f->upage, is_dirty);
    frame_free(victim_f->kpage);
}

/* Finds a victim frame. */
static struct frame *frame_find_victim(void)
{
    size_t size = list_size(&frame_clock);
    size_t i;

    for (i = 0; i < 2 * size; i++)
    {
        struct frame *f;
        struct thread *t;

        frame_clock_hand = frame_clock_next(frame_clock_hand);
        f = list_entry(frame_clock_hand, struct frame, fcelem);
        t = thread_get_from_tid(f->tid);

        if (!t)
            PANIC("Invalid tid");

        if (!f->is_pinned)
            if (!pagedir_is_accessed(t->pagedir, f->upage))
                return f;
            else
                pagedir_set_accessed(t->pagedir, f->upage, false);
    }

    PANIC("Cannot find victim");
}

/* Returns the element after E in frame clock list. */
static struct list_elem *frame_clock_next(struct list_elem *e)
{
    return list_next(frame_clock_hand) == list_end(&frame_clock)
               ? list_begin(&frame_clock)
               : list_next(frame_clock_hand);
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
