#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <stdbool.h>
#include <stdint.h>
#include <hash.h>
#include "filesys/file.h"
#include "filesys/off_t.h"

/* States of a page. */
enum page_status
{
    PAGE_FILE, /* Data is in file system. */
    PAGE_ZERO, /* Data is all-zero. */
    PAGE_SWAP, /* Data is in swap slot. */
    PAGE_FRAME /* Data is in frame. */
};

/* A supplemental page table entry. */
struct page
{
    /* Shared between vm/page.c, userprog/exception.c,
     userprog/process.c, and userprog/syscall.c. */
    void *upage; /* User virtual page. */
    void *kpage; /* Kernel virtual page. */

    /* Owned by page.c. */
    enum page_status status; /* Page state. */

    /* Shared between vm/page.c, userprog/process.c, and userprog/syscall.c. */
    struct file *file;               /* File to read. */
    off_t ofs;                       /* File offset. */
    uint32_t read_bytes, zero_bytes; /* Bytes to read or to set zero. */
    bool writable;                   /* Whether page is writable. */

    /* Shared between page.c and swap.c. */
    size_t swap_idx; /* Swap table index. */
    bool is_dirty;   /* Whether page have ever been evicted. */

    /* Shared between vm/page.c, userprog/exception.c,
     userprog/process.c, and userprog/syscall.c. */
    struct hash_elem sptelem; /* Hash element for supplemental page table. */
};

/* Basic life cycle. */
void page_spt_init(struct hash *);
void page_spt_destroy(struct hash *);

/* Installation, deletion. */
void page_install_file(struct hash *, void *, struct file *, off_t, uint32_t, uint32_t, bool);
void page_install_zero(struct hash *, void *);
void page_install_frame(struct hash *, void *, void *);
void page_delete(struct hash *, void *, bool);

/* Eviction, load, search. */
void page_evict(struct hash *, void *, bool);
void page_load(struct hash *, void *, bool);
struct page *page_lookup(struct hash *, void *);

#endif /* vm/page.h */
