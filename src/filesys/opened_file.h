#ifndef FILESYS_OPENED_FILE_H
#define FILESYS_OPENED_FILE_H
#include <list.h>
#include "filesys/file.h"

struct lock fd_lock;

struct opened_file
{
  int fd;               /*  */
  char *filename;
  struct file *fp;
  off_t offset;
  struct list_elem elem; /* It is used in syscall.c and thread */
};


struct list* get_opened_file_list (struct thread *);
bool opened_file_list_destroy (struct thread*);
struct opened_file * opened_file_open (const char*);
void opened_file_close (struct opened_file *);

struct opened_file * opened_file_get_from_fd (int);

off_t opened_file_read (struct opened_file*,  void*, off_t);
off_t opened_file_write (struct opened_file*, const void*, off_t);

off_t opened_file_read_at (struct opened_file*, void*, off_t, off_t);
off_t opened_file_write_at (struct opened_file*, const void*, off_t, off_t);

void opened_file_seek (struct opened_file *, off_t);
off_t opened_file_tell (struct opened_file *);
off_t opened_file_length (struct opened_file *);

bool is_same_filename (const struct list_elem *a, void* filename);

#endif
