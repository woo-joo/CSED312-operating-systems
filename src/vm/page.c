#include "vm/page.h"
#include <string.h>
#include <debug.h>
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "vm/frame.h"
#include "vm/swap.h"

/* Helper functions. */
static hash_hash_func page_hash;
static hash_less_func page_less;

/* Initializes supplemental page table SPT. */
void page_spt_init(struct hash *spt)
{
    hash_init(spt, page_hash, page_less, NULL);
}

/* Adds a page with status PAGE_FILE to SPT. */
void page_install_file(struct hash *spt, void *upage, struct file *file, off_t ofs, uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
    struct page *p;

    ASSERT(is_user_vaddr(upage));
    ASSERT(file != NULL);
    ASSERT(read_bytes + zero_bytes == PGSIZE);

    p = (struct page *)malloc(sizeof *p);

    p->upage = upage;
    p->kpage = NULL;

    p->status = PAGE_FILE;

    p->file = file;
    p->ofs = ofs;
    p->read_bytes = read_bytes;
    p->zero_bytes = zero_bytes;
    p->writable = writable;

    p->swap_idx = -1;
    p->is_dirty = false;

    if (hash_insert(spt, &p->sptelem))
        syscall_exit(-1);
}

/* Adds a page with status PAGE_ZERO to SPT. */
void page_install_zero(struct hash *spt, void *upage)
{
    struct page *p;

    ASSERT(is_user_vaddr(upage));

    p = (struct page *)malloc(sizeof *p);

    p->upage = upage;
    p->kpage = NULL;

    p->status = PAGE_ZERO;

    p->file = NULL;
    p->writable = true;

    p->swap_idx = -1;
    p->is_dirty = false;

    if (hash_insert(spt, &p->sptelem))
        syscall_exit(-1);
}

/* Adds a page with status PAGE_FRAME to SPT. */
void page_install_frame(struct hash *spt, void *upage, void *kpage)
{
    struct page *p;

    ASSERT(is_user_vaddr(upage));
    ASSERT(is_kernel_vaddr(kpage));

    p = (struct page *)malloc(sizeof *p);

    p->upage = upage;
    p->kpage = kpage;

    p->status = PAGE_FRAME;

    p->file = NULL;
    p->writable = true;

    p->swap_idx = -1;
    p->is_dirty = false;

    if (hash_insert(spt, &p->sptelem))
        syscall_exit(-1);
}

/* Deletes a page associated with UPAGE from SPT. */
void page_delete(struct hash *spt, void *upage, bool is_dirty)
{
    struct page *p;

    ASSERT(is_user_vaddr(upage));

    p = page_lookup(spt, upage);
    if (!p)
        syscall_exit(-1);

    switch (p->status)
    {
    case PAGE_FILE:
    case PAGE_ZERO:
        break;
    case PAGE_SWAP:
        page_load(spt, upage, false);
        is_dirty = true;
    case PAGE_FRAME:
    {
        frame_pin(p->kpage);

        if (p->file && (p->is_dirty || is_dirty))
            file_write_at(p->file, upage, p->read_bytes, p->ofs);

        frame_free(p->kpage);

        break;
    }
    default:
        syscall_exit(-1);
    }

    hash_delete(spt, &p->sptelem);
    free(p);
}

/* Evicts page. Status is set properly. */
void page_evict(struct hash *spt, void *upage, bool is_dirty)
{
    struct page *p;

    ASSERT(is_user_vaddr(upage));

    p = page_lookup(spt, upage);
    if (!p)
        syscall_exit(-1);

    ASSERT(p->status == PAGE_FRAME);
    ASSERT(p->kpage != NULL);

    if (p->is_dirty || is_dirty)
    {
        p->status = PAGE_SWAP;
        p->swap_idx = swap_out(p->kpage);
        p->is_dirty = true;
    }
    else if (p->file)
        p->status = PAGE_FILE;
    else
        p->status = PAGE_ZERO;

    p->kpage = NULL;
}

/* Loads data into P according to its state. */
void page_load(struct hash *spt, void *upage, bool unpin)
{
    struct page *p;
    struct lock *filesys_lock;
    uint32_t *pagedir;
    void *kpage;

    ASSERT(is_user_vaddr(upage));

    p = page_lookup(spt, upage);
    if (!p)
        goto fail;

    kpage = frame_allocate(PAL_USER, upage);
    if (kpage == NULL)
        goto fail;

    switch (p->status)
    {
    case PAGE_FILE:
        filesys_lock = syscall_get_filesys_lock();

        lock_acquire(filesys_lock);

        if (file_read_at(p->file, kpage, p->read_bytes, p->ofs) != p->read_bytes)
        {
            frame_free(kpage);
            lock_release(filesys_lock);
            goto fail;
        }
        memset(kpage + p->read_bytes, 0, p->zero_bytes);

        lock_release(filesys_lock);

        break;
    case PAGE_ZERO:
        memset(kpage, 0, PGSIZE);

        break;
    case PAGE_SWAP:
        swap_in(p->swap_idx, kpage);
        p->swap_idx = -1;

        break;
    default:
        goto fail;
    }

    pagedir = thread_get_pagedir();
    if (!pagedir_set_page(pagedir, upage, kpage, p->writable))
    {
        frame_free(kpage);
        goto fail;
    }

    p->kpage = kpage;
    p->status = PAGE_FRAME;

    if (unpin)
        frame_unpin(kpage);

    return;

fail:
    syscall_exit(-1);
}

/* Returns the page containing the given virtual UPAGE,
   or a null pointer if no such page exists. */
struct page *page_lookup(struct hash *spt, void *upage)
{
    struct page p;
    struct hash_elem *e;

    p.upage = upage;
    e = hash_find(spt, &p.sptelem);

    return e != NULL ? hash_entry(e, struct page, sptelem) : NULL;
}

/* Returns a hash of UPAGE of P that E is embedded inside. */
static unsigned int page_hash(const struct hash_elem *e, void *aux UNUSED)
{
    struct page *p = hash_entry(e, struct page, sptelem);

    return hash_bytes(&p->upage, sizeof p->upage);
}

/* Compares UPAGE of two hash elements A and B. Returns
   true if A is less than B, or false if A is greater
   than or equal to B. */
static bool page_less(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
    struct page *a_p = hash_entry(a, struct page, sptelem);
    struct page *b_p = hash_entry(b, struct page, sptelem);

    return a_p->upage < b_p->upage;
}
