#include "vm/frame.h"
#include "vm/page.h"
#include "threads/palloc.h"
#include "userprog/pagedir.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "filesys/file.h"
#include "vm/swap.h"
#include <hash.h>

#define FRSHIFT 0
#define FRBITS 12
#define FRSIZE (1 << FRBITS)
#define FRMASK BITMASK(FRSHIFT, FRBITS)

static inline unsigned fr_ofs (const void *va) {
  return (uintptr_t) va & FRMASK;
}

static inline uintptr_t fr_no (const void *va) {
  return (uintptr_t) va >> FRBITS;
}

static inline bool is_same_frame (const struct list_elem *e_, void *frame)
{
  return list_entry (e_, struct frame_entry, elem)->frame == frame;
}



/* Initialize frame table per thread */
void 
frame_table_init ()
{
  list_init (&frame_table);
  lock_init (&frame_table_lock);
}

/* return Virtual Address */
void *
frame_alloc (enum palloc_flags flags, struct page_entry *pe)
{
  ASSERT (flags & PAL_USER);

  void *frame_addr;

  frame_addr = palloc_get_page (flags);

  while (frame_addr == NULL)
    frame_addr = frame_evict (flags);

  frame_push_table (frame_addr, pe);

  return frame_addr;
}

/* free frame */
void frame_free (void *address)
{
  struct list_elem *e;
  struct frame_entry *fte;
  
  lock_acquire (&frame_table_lock);

  e = list_search (&frame_table, is_same_frame, (void*) address);

  fte = list_entry (e, struct frame_entry, elem);

  list_remove (e);
  free (fte);
  palloc_free_page (address);

  lock_release (&frame_table_lock);
}

bool
frame_push_table (void *frame, struct page_entry *pe)
{
  struct frame_entry *fe;
  fe = (struct frame_entry *) malloc (sizeof (struct frame_entry));
  fe->frame = frame;
  fe->pe = pe;
  fe->holder = thread_current ();

  lock_acquire (&frame_table_lock);
  list_push_back (&frame_table, &fe->elem);
  lock_release (&frame_table_lock);

  return true;
}

void *
frame_evict (enum palloc_flags flags)
{
  struct list_elem *e;
  struct frame_entry *fe;

  lock_acquire(&frame_table_lock);
  e = list_begin (&frame_table);
  lock_release(&frame_table_lock);

  while (true)
  {
    fe = list_entry (e, struct frame_entry, elem);

    if (page_is_pinned (fe->pe))
    {
      lock_acquire(&frame_table_lock);
      e = list_next (e);
      e = e == list_end (&frame_table) ? list_begin (&frame_table) : e;
      lock_release(&frame_table_lock);
    }

    else
    {
      if (pagedir_is_accessed (fe->holder->pagedir, fe->pe->uva))
        pagedir_set_accessed (fe->holder->pagedir, fe->pe->uva, false);

      else
      {
        if (pagedir_is_dirty (fe->holder->pagedir, fe->pe->uva))
        {
          if (page_get_type (fe->pe) == PAGE_TYPE_MMAP)
          {
            lock_acquire (&file_lock);
            file_write_at (fe->pe->file, fe->frame, fe->pe->read_bytes, fe->pe->offset);
            lock_release (&file_lock);
          }

          else
            page_set_type (fe->pe, PAGE_TYPE_SWAP);
        }

        if (page_get_type (fe->pe) == PAGE_TYPE_SWAP) 
          fe->pe->swap_index = swap_out (fe->frame);
        page_set_load (fe->pe, false);

        lock_acquire(&frame_table_lock);
        list_remove (&fe->elem);
        lock_release(&frame_table_lock);

        pagedir_clear_page (fe->holder->pagedir, fe->pe->uva);
        palloc_free_page (fe->frame);
        free (fe);

        return palloc_get_page (flags);
      }
    }
  }

  NOT_REACHED ();
}
