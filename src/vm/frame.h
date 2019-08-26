#ifndef VM_FRAME_H
#define VM_FRAME_H
/*
31                12 11         0
+-------------------+-----------+
|    Frame Number   |   Offset  |
+-------------------+-----------+
        Virtual Memory
*/

#include <debug.h>
#include <hash.h>
#include <stdint.h>
#include <stdbool.h>
#include "threads/synch.h"
#include "threads/palloc.h"
#include "vm/page.h"

struct frame_entry
{
  void *frame;
  struct page_entry *pe;
  struct thread *holder;
  struct list_elem elem;
};

struct list frame_table;
struct lock frame_table_lock;

void frame_table_init (void);

void *frame_alloc (enum palloc_flags, struct page_entry *);
void frame_free (void *frame);
bool frame_push_table (void *, struct page_entry *);
void *frame_evict (enum palloc_flags);

unsigned frame_hash (const struct hash_elem *, void *);
bool frame_less (const struct hash_elem *, const struct hash_elem *, void *);
#endif /* vm/frame.h */
