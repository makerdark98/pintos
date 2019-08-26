#include "filesys/opened_file.h"
#include "filesys/filesys.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include <string.h>

static void opened_file_free (struct list *, struct opened_file *);

static struct opened_file * opened_file_alloc (struct list *, const char *, int fd);
static inline struct file *opened_file_get_file (struct opened_file *of) { return of->fp; }
static int allocate_fd (void);
static bool is_same_fd (const struct list_elem *a, void* fd);

struct list*
get_opened_file_list (struct thread *target)
{
  /*
   * struct thread *ansestor;
   * for (ancestor = t; ancestor->parent != NULL; ancestor = ancestor->parent) ;
   */
  return &target->opened_file_list;
}

bool
opened_file_list_destroy (struct thread *target)
{
  struct list_elem *e;
  struct opened_file *of;
  struct list *opened_file_list;

  opened_file_list = get_opened_file_list (target);
  e = list_begin (opened_file_list);
  while (e != list_end (opened_file_list))
  {
    of = list_entry (e, struct opened_file, elem);
    e = list_next (e);
    opened_file_close (of);
  }

  return true;
}

struct opened_file *
opened_file_open (const char* filename)
{
  struct thread *current;
  struct list *opened_file_list;
  struct opened_file *retval;

  current = thread_current ();

  opened_file_list = get_opened_file_list (current);

  retval = opened_file_alloc (opened_file_list, filename, allocate_fd());

  return retval;
}

void
opened_file_close (struct opened_file *of)
{
  struct thread *current;

  current = thread_current ();

  list_remove (&of->elem);
  opened_file_free (get_opened_file_list (current), of);
}

struct opened_file *
opened_file_get_from_fd (int fd)
{
  struct list_elem *e;
  struct thread *current;
  struct list *opened_file_list;

  current = thread_current ();
  opened_file_list = get_opened_file_list (current);
  e = list_search (opened_file_list, is_same_fd, (void *)fd);

  return e != list_end (opened_file_list) ?
          list_entry (e, struct opened_file, elem) :
          NULL;
}

off_t
opened_file_read (struct opened_file* of, void *buffer, off_t size)
{
  off_t retval;
  struct file *file;

  file = opened_file_get_file (of);

  lock_acquire (&file_lock);
  file_seek (file, of->offset);
  retval = file_read (file, buffer, size);
  of->offset = file_tell (file);
  lock_release (&file_lock);

  return retval;
}

off_t
opened_file_write (struct opened_file* of, const void *buffer, off_t size)
{
  off_t retval;
  struct file *file;

  file = opened_file_get_file (of);

  lock_acquire (&file_lock);
  file_seek (file, of->offset);
  retval = file_write (file, buffer, size);
  of->offset = file_tell (file);
  lock_release (&file_lock);

  return retval;
}

off_t
opened_file_read_at (struct opened_file* of, void *buffer, off_t size, off_t offset)
{
  off_t retval;
  struct file *file;

  file = opened_file_get_file (of);

  lock_acquire (&file_lock);
  retval = file_read_at (file, buffer, size, offset);
  lock_release (&file_lock);

  return retval;
}

off_t
opened_file_write_at (struct opened_file* of, const void *buffer, off_t size, off_t offset)
{
  off_t retval;
  struct file *file;

  file = opened_file_get_file (of);

  lock_acquire (&file_lock);
  retval = file_write_at (file, buffer, size, offset);
  lock_release (&file_lock);

  return retval;
}

void
opened_file_seek (struct opened_file *of, off_t position)
{
  lock_acquire (&file_lock);
  of->offset = position;
  lock_release (&file_lock);
}

off_t
opened_file_tell (struct opened_file *of) 
{
  return of->offset;
}

off_t
opened_file_length (struct opened_file *of)
{
  off_t retval;

  lock_acquire(&file_lock);
  retval = file_length (opened_file_get_file(of));
  lock_release(&file_lock);

  return retval;
}

bool
is_same_filename (const struct list_elem *a, void* filename)
{
  return strcmp (list_entry(a, struct opened_file, elem) -> filename, (char *)filename) == 0;
}


static int
allocate_fd (void)
{
  static int next_fd = 3;
  int fd;
  lock_acquire (&fd_lock);
  fd = next_fd++;
  lock_release (&fd_lock);
  return fd;
}

static
struct opened_file *
opened_file_alloc (struct list *list, const char *filename, int fd)
{
  struct opened_file * retval;
  size_t filename_size;
  struct list_elem *e;

  filename_size = strlen (filename) + 1;
  retval = (struct opened_file*) malloc (sizeof (struct opened_file));

  retval->fd = fd;
  retval->offset = 0;

  e = list_search (list, is_same_filename, (void *)filename);
  if (e != list_end (list)) 
  {
    retval->filename = list_entry (e, struct opened_file, elem)->filename;
    retval->fp = list_entry (e, struct opened_file, elem)->fp;
  }
  else
  {
    lock_acquire (&file_lock);
    retval->fp = filesys_open (filename);
    lock_release (&file_lock);
    if (retval->fp == NULL)
    {
      free (retval);
      retval = NULL;
      return NULL;
    }

    retval->filename = (char *) malloc (filename_size * sizeof (char));
    memcpy (retval->filename, filename, filename_size);
  }

  list_push_back (list, &retval->elem);

  return retval;
}

static void
opened_file_free (struct list *list, struct opened_file *opened)
{
  struct list_elem *e;
  e = list_search (list, is_same_filename, (void *)opened->filename);
  if (e == list_end (list)) 
  {
    file_close (opened_file_get_file (opened));
    free (opened->filename);
  }
  free (opened);
}

static bool
is_same_fd (const struct list_elem *a, void* fd)
{
  return list_entry(a, struct opened_file, elem)-> fd == (int)fd;
}

