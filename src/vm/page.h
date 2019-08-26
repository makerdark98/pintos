#ifndef VM_PAGE_H
#define VM_PAGE_H
/*
   31                12 11         0
   +-------------------+-----------+
   |     PageNumber    |   Offset  |
   +-------------------+-----------+
   Virtual Memory
   */

#include "threads/pte.h"
#include "threads/palloc.h"
#include "filesys/off_t.h"
#include <hash.h>

#define STACK_HEURISTIC 64

#define PAGE_LOAD (1 << 1)
#define PAGE_PINNED (1 << 2)
#define PAGE_WRITEABLE (1 << 3)

#define PAGE_TYPE_FILTER (3 << 4)
#define PAGE_TYPE_FILE (0 << 4)
#define PAGE_TYPE_MMAP (1 << 4)
#define PAGE_TYPE_SWAP (2 << 4)
#define PAGE_TYPE_ERROR (3 << 4)

#define MAX_STACK_SIZE (1 << 23)

#define USER_VADDR_BOTTOM ((void *) 0x08048000)

/* A page. */
struct page_entry
{
  void *uva;
  
  int8_t flags;

  struct file* file;
  off_t offset;
  uint32_t read_bytes;
  uint32_t zero_bytes;

  uint32_t swap_index;

  struct hash_elem elem;      /* Page Table Element */
  struct list_elem mmap_elem; /* MMAP File Element */
};

void page_init (void);
struct page_entry* page_lookup (void *);

void page_table_init (struct hash *);
void page_table_destroy (struct hash *);

struct page_entry* get_pe (void *);
bool page_load (struct page_entry *);
bool page_load_from_file (struct page_entry *);
bool page_load_from_swap (struct page_entry *);

bool page_add_file_to_page_table (struct file *, off_t, uint8_t *,
    uint32_t, uint32_t, bool);
bool grow_stack (void *);

struct mmap_file 
{
  int mapid;
  struct opened_file *of;
  struct list me_list;
  struct list_elem elem;
};

struct mmap_elem
{
  struct page_entry *pe;
  struct list_elem elem;
};

bool page_destroy_mmap_list (struct list *);
struct mmap_file* page_mmap (struct opened_file *, void*);
bool page_unmap (struct mmap_file *);

#define page_get_type(pe)       ((pe)->flags & PAGE_TYPE_FILTER)
#define page_set_type(pe, type) ((pe)->flags =                        \
                                  ((pe)->flags & (~PAGE_TYPE_FILTER)) | (type))

#define page_is_loaded(pe)   (((pe)->flags & PAGE_LOAD) == PAGE_LOAD)
#define page_is_pinned(pe)   (((pe)->flags & PAGE_PINNED) == PAGE_PINNED)
#define page_is_writable(pe) (((pe)->flags & PAGE_WRITEABLE) == PAGE_WRITEABLE)

#define page_set_load(pe, flag)     ((flag) ? ((pe)->flags |= PAGE_LOAD) :      \
                                      ((pe)->flags &= ~PAGE_LOAD))
#define page_set_pinned(pe, flag)   ((flag) ? ((pe)->flags |= PAGE_PINNED) :    \
                                      ((pe)->flags &= ~PAGE_PINNED))
#define page_set_writable(pe, flag) ((flag) ? ((pe)->flags |= PAGE_WRITEABLE) : \
                                      ((pe)->flags &= ~PAGE_WRITEABLE))

bool is_same_md (const struct list_elem *, void *);

#endif /* vm/page.h */
