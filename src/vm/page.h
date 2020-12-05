#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <stdbool.h>
#include <stdint.h>
#include <hash.h>

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
    /* Shared between vm/page.c and userprog/process.c. */
    void *upage; /* User virtual page. */
    void *kpage; /* Kernel virtual page. */

    /* Owned by page.c. */
    enum page_status status; /* Page state. */

    /* Shared between vm/page.c and userprog/process.c. */
    struct hash_elem sptelem; /* Hash element for supplemental page table. */
};

/* Basic life cycle. */
void page_spt_init(struct hash *);

/* Installation. */
void page_install_frame(struct hash *, void *, void *);

#endif /* vm/page.h */
