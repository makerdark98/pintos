#ifndef FILESYS_FILE_H
#define FILESYS_FILE_H

#include "filesys/off_t.h"
#include "lib/kernel/list.h"

struct inode;

struct opend_file
{
  int fd;               /*  */
  char *filename;
  struct file *fp;
  off_t offset;
  struct list_elem elem; /* It is used in syscall.c and thread */
};


struct opend_file *
opend_file_alloc (struct list *, const char *filename, int fd);
void opend_file_free (struct list *, struct opend_file *opend);
struct file *opend_file_get_file (struct opend_file *);

/* Opening and closing files. */
struct file *file_open (struct inode *);
struct file *file_reopen (struct file *);
void file_close (struct file *);
struct inode *file_get_inode (struct file *);

/* Reading and writing. */
off_t file_read (struct file *, void *, off_t);
off_t file_read_at (struct file *, void *, off_t size, off_t start);
off_t file_write (struct file *, const void *, off_t);
off_t file_write_at (struct file *, const void *, off_t size, off_t start);

/* Preventing writes. */
void file_deny_write (struct file *);
void file_allow_write (struct file *);

/* File position. */
void file_seek (struct file *, off_t);
off_t file_tell (struct file *);
off_t file_length (struct file *);

bool is_same_filename (const struct list_elem *a, void* filename);
#endif /* filesys/file.h */
