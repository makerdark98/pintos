#include "vm/page.h"
#include "vm/frame.h"
#include "vm/swap.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/interrupt.h"
#include "userprog/pagedir.h"
#include "filesys/opened_file.h"
#include <string.h>

static bool install_page (void *upage, void *kpage, bool writable);
static unsigned page_hash (const struct hash_elem *, void * UNUSED);
static bool page_less (const struct hash_elem *,
    const struct hash_elem *, void * UNUSED);
static void page_action (struct hash_elem *, void * UNUSED);
static bool mmap_page (struct page_entry *, struct file *, off_t, void*,
    uint32_t, uint32_t);
static int allocate_md (struct thread *);

/* Initializes the page hashes. */
void 
page_table_init (struct hash *page_table) 
{
  hash_init (page_table, page_hash, page_less, NULL);
}

/* Returns the page containing the given virtual address,
 * or a null pointer if no such page exists. */

struct page_entry *
page_lookup (void *address)
{
  struct hash_elem *e;
  struct page_entry p;

  struct hash *page_table;

  page_table = &thread_current ()->pt;
  p.uva = pg_round_down (address);
  e = hash_find (page_table, &p.elem);
  return e == NULL ? NULL : hash_entry (e, struct page_entry, elem);
}

void
page_table_destroy (struct hash *pt)
{
  hash_destroy (pt, page_action);
}

bool
page_load (struct page_entry *pe)
{
  bool success = false;

  page_set_pinned (pe, true);
  if (page_is_loaded (pe)) {
    goto done;
  }

  switch (page_get_type (pe))
  {
    case PAGE_TYPE_FILE:
    case PAGE_TYPE_MMAP:
      success = page_load_from_file (pe);
      break;

    case PAGE_TYPE_SWAP:
      success = page_load_from_swap (pe);
      break;
  }
done:
  return success;
}

bool
page_load_from_file (struct page_entry *pe)
{
  uint8_t *frame;
  off_t read_offset;
  enum palloc_flags flags;
  bool success = false;

  flags = PAL_USER;

  if (pe->read_bytes == 0)
    flags |= PAL_ZERO;

  frame = frame_alloc (flags, pe);
  if (!frame)
    goto done;

  if (pe->read_bytes > 0) 
  {
    lock_acquire (&file_lock);
    read_offset = file_read_at (pe->file, frame, pe->read_bytes, pe->offset);
    lock_release (&file_lock);

    if ((int)pe->read_bytes != read_offset) 
      goto done;

    memset (frame + pe->read_bytes, 0, pe->zero_bytes);
  }

  if (!install_page (pe->uva, frame, page_is_writable (pe)))
  {
    goto done;
  }

  page_set_load (pe, true);
  success = true;
done:
  if (!success && !frame)
    frame_free (frame);

  return success;
}

bool
page_load_from_swap (struct page_entry *pe)
{
  uint8_t *frame = frame_alloc (PAL_USER, pe);
  if (!frame)
    return false;

  if (!install_page(pe->uva, frame, page_is_writable(pe)))
  {
    frame_free(frame);
    return false;
  }

  swap_in (pe->swap_index, pe->uva);
  page_set_load (pe, true);
  return true;
}

bool
page_add_file_to_page_table (
    struct file* file,
    off_t offset,
    uint8_t *upage,
    uint32_t read_bytes,
    uint32_t zero_bytes,
    bool writable
    )
{
  struct page_entry *pe;
  struct thread *current;

  current = thread_current ();
  
  pe = (struct page_entry *) malloc (sizeof (struct page_entry));

  if (!pe) return false;

  pe->file = file;
  pe->offset = offset;
  pe->uva = upage;
  pe->read_bytes = read_bytes;
  pe->zero_bytes = zero_bytes;
  pe->flags = 0;
  page_set_writable (pe, writable);
  page_set_load (pe, false);
  page_set_type (pe, PAGE_TYPE_FILE);
  page_set_pinned (pe, false);

  return hash_insert (&current->pt, &pe->elem) == NULL;
}

bool
page_destroy_mmap_list (struct list *mmap_list)
{
  struct list_elem *e;
  struct mmap_file *mf;

  e = list_begin (mmap_list);
  while (e != list_end (mmap_list))
  {
    mf = list_entry (e, struct mmap_file, elem);
    e = list_remove (e);
    page_unmap (mf);
  }

  return true;
}

struct mmap_file*
page_mmap (
    struct opened_file *of,
    void *addr)
{
  if (of == NULL || !is_user_vaddr (addr) || 
      addr < USER_VADDR_BOTTOM || (uint32_t) addr % PGSIZE != 0)
    return NULL;

  struct thread *current;
  struct page_entry *pe = NULL;
  struct mmap_file *mf;
  struct mmap_elem *me = NULL;
  struct list_elem *e;

  bool success;
  off_t left_bytes;
  off_t offset;
  uint32_t read_bytes;
  uint32_t zero_bytes;

  current = thread_current ();
  mf = (struct mmap_file *) malloc (sizeof (struct mmap_file));
  if (!mf) goto FAIL;

  mf->mapid = allocate_md (current);
  mf->of = of;
  list_init (&mf->me_list);

  left_bytes = opened_file_length (of);
  offset = 0;

  while (left_bytes)
  {
    read_bytes = left_bytes > PGSIZE ? PGSIZE : left_bytes;
    zero_bytes = PGSIZE - read_bytes;
    left_bytes -= read_bytes;

    pe = NULL;
    me = NULL;

    pe = (struct page_entry *) malloc (sizeof (struct page_entry));
    me = (struct mmap_elem *) malloc (sizeof (struct mmap_elem));
    if (!pe || !me)
      goto FAIL;

    me->pe = pe;
    success = mmap_page (pe, of->fp, offset, addr, read_bytes, zero_bytes);

    if (!success)
      goto FAIL;

    list_push_back (&mf->me_list, &me->elem);
    addr += read_bytes;
    offset += read_bytes;
  }

  list_push_back (&current->mmap_file_list, &mf->elem);

  return mf;

FAIL:
  if (pe) free (pe);
  if (me) free (me);
  if (mf)
  {
    e = list_begin (&mf->me_list);
    while (e != list_end (&mf->me_list))
    {
      me = list_entry (e, struct mmap_elem, elem);
      e = list_remove (e);
      free (me->pe);
      free (me);
    }
  }

  return NULL;
}

bool
page_unmap (struct mmap_file *mf)
{
  struct list_elem *e;
  struct mmap_elem *me;
  struct thread *current;
  
  current = thread_current ();
  e = list_begin (&mf->me_list);
  while (e != list_end (&mf->me_list))
  {
    me = list_entry (e, struct mmap_elem, elem);
    e = list_remove (e);

    page_set_pinned (me->pe, true);
    if (page_is_loaded (me->pe))
    {
      if (pagedir_is_dirty (current->pagedir, me->pe->uva))
      {
        lock_acquire (&file_lock);
        file_write_at (me->pe->file, me->pe->uva, me->pe->read_bytes, me->pe->offset);
        lock_release (&file_lock);
      }

      frame_free (pagedir_get_page (current->pagedir, me->pe->uva));
      pagedir_clear_page (current->pagedir, me->pe->uva);

    }

    if (page_get_type (me->pe) != PAGE_TYPE_ERROR)
      hash_delete (&current->pt, &me->pe->elem);

    free (me->pe);
    free (me);
  }

  list_remove (&mf->elem);
  free (mf);

  return true;
}

bool
grow_stack (void *uva)
{
  struct thread *current;
  uint8_t *frame = NULL;
  struct page_entry *pe = NULL;
  bool success = false;

  current = thread_current ();

  if ((size_t) (PHYS_BASE - pg_round_down(uva)) > MAX_STACK_SIZE)
    goto done;

  pe = (struct page_entry *) malloc (sizeof (struct page_entry));

  if (!pe)
    goto done;

  pe->uva = pg_round_down (uva);

  page_set_load (pe, true);
  page_set_writable (pe, true);
  page_set_type (pe, PAGE_TYPE_SWAP);
  page_set_pinned (pe, true);

  frame = frame_alloc (PAL_USER, pe);
  if (!frame)
    goto done;

  if (!install_page (pe->uva, frame, page_is_writable(pe)))
    goto done;

  if (intr_context())
    page_set_pinned (pe, false);

  success = hash_insert (&current->pt, &pe->elem) == NULL;

done:
  if (!success)
  {
    if (pe != NULL)
      free (pe);

    if (frame != NULL)
      frame_free (frame);
  }

  return success;
}

bool is_same_md (const struct list_elem *e, void *mapid)
{
  return list_entry(e, struct mmap_file, elem)->mapid == (int)mapid;
}

/* Returns a hash value for page p. */
static unsigned
page_hash (const struct hash_elem *p_, void *aux UNUSED)
{
  const struct page_entry *p = hash_entry (p_, struct page_entry, elem);
  return hash_bytes (&p->uva, sizeof p->uva);
}

/* Returns true if page a precedes page b. */
static bool
page_less (const struct hash_elem *a_, const struct hash_elem *b_,
    void *aux UNUSED)
{
  const struct page_entry *a = hash_entry (a_, struct page_entry, elem);
  const struct page_entry *b = hash_entry (b_, struct page_entry, elem);

  return a->uva < b->uva;
}

static void
page_action (struct hash_elem *e, void *aux UNUSED)
{
  struct thread *current;
  struct page_entry *pe;

  current = thread_current();
  pe = hash_entry (e, struct page_entry, elem);

  if (page_is_loaded(pe))
  {
    frame_free (pagedir_get_page (current->pagedir, pe->uva));
    pagedir_clear_page (current->pagedir, pe->uva);
  }

  free (pe);
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}

static bool
mmap_page (struct page_entry *pe, struct file *file, off_t offset, void* uva,
    uint32_t read_bytes, uint32_t zero_bytes)
{
  ASSERT (pe != NULL);
  struct thread *current;

  current = thread_current ();

  pe->uva = uva;
  pe->file = file_reopen(file);
  pe->offset = offset;
  pe->read_bytes = read_bytes;
  pe->zero_bytes = zero_bytes;
  page_set_writable (pe, true);
  page_set_load (pe, false);
  page_set_type (pe, PAGE_TYPE_MMAP);
  page_set_pinned (pe, false);

  if (hash_insert (&current->pt, &pe->elem) != NULL)
    return false;

  return true;
}

static int
allocate_md (struct thread *current)
{
  return current->mapid++;
}
