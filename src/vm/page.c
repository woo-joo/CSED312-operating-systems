#include "vm/page.h"
#include <string.h>
#include <debug.h>
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "userprog/syscall.h"
#include "vm/frame.h"

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

    if (hash_insert(spt, &p->sptelem))
        syscall_exit(-1);
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
