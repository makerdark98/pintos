#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <string.h>
#include "devices/shutdown.h"
#include "devices/input.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "filesys/file.h"
#include "filesys/opened_file.h"
#include "filesys/filesys.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "vm/page.h"

#define READDIR_MAX_LEN 14

static bool is_valid_ptr (void *, const void *);
static bool is_valid_string (void *, const void *);
static bool is_valid_buffer (void *, const void *, off_t, bool);

static void syscall_handler (struct intr_frame *);

static void syscall_halt (void);
void syscall_exit (int);
static tid_t syscall_exec (const char *);
static int syscall_wait (tid_t);
static bool syscall_create (const char *, unsigned);
static bool syscall_remove (const char *);
static int syscall_open (const char *);
static int syscall_filesize (int);
static int syscall_read (int, void *, unsigned);
static int syscall_write (int, const void *, unsigned);
static void syscall_seek (int, unsigned);
static unsigned syscall_tell (int );
static void syscall_close (int);
static int syscall_mmap (int, void *);
static void syscall_munmap (int);
static bool syscall_chdir (const char *);
static bool syscall_mkdir (const char *);
static bool syscall_readdir (int, char [READDIR_MAX_LEN + 1]);
static bool syscall_isdir (int);
static int syscall_inumber (int);

static bool is_same_process_filename (const struct list_elem *, void *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&file_lock);
  lock_init (&fd_lock);
  lock_init (&md_lock);
}

static void
syscall_handler (struct intr_frame *f) 
{
  is_valid_ptr (f->esp, f->esp);
  int* NUMBER;
  NUMBER = (int*)(f->esp);

  switch (*NUMBER)
  {
    /* Project 2 */
    case SYS_HALT:
      syscall_halt(); 
      break;
    case SYS_EXIT:
      is_valid_ptr (f->esp + 4, f->esp);
      syscall_exit(*(int*)(f->esp + 4)); 
      break;
    case SYS_EXEC:
      is_valid_string (*(char**)(f->esp + 4), f->esp);
      f->eax = syscall_exec (*(const char**)(f->esp + 4)); 
      break;
    case SYS_WAIT:
      f->eax = syscall_wait (*(int*)(f->esp + 4)); 
      break;
    case SYS_CREATE:
      is_valid_ptr (*(char**)(f->esp + 16), f->esp);
      f->eax = syscall_create (*(const char**)(f->esp + 16),
          *(unsigned*)(f->esp + 20)
          ); 
      break;
    case SYS_REMOVE:
      is_valid_string (*(char**)(f->esp + 12), f->esp);
      f->eax = syscall_remove (*(const char**)(f->esp + 12)); 
      break;
    case SYS_OPEN:
      is_valid_string (*(char**)(f->esp + 4), f->esp);
      f->eax = syscall_open (*(const char**)(f->esp + 4));
      break;
    case SYS_FILESIZE:
      f->eax = syscall_filesize (*(int*)(f->esp + 4));
      break;
    case SYS_READ:
      is_valid_buffer (*(void **)(f->esp + 24), f->esp,
          *(unsigned *)(f->esp + 28), true);

      f->eax = syscall_read (*(int*)(f->esp + 20), 
          *(void**)(f->esp + 24), 
          *(unsigned *)(f->esp + 28));
      break;
    case SYS_WRITE:
      is_valid_buffer (*(void **)(f->esp + 24), f->esp,
          *(unsigned *)(f->esp + 28), false);
      f->eax = syscall_write (*(int*)(f->esp + 20),
          *(void**)(f->esp + 24),
          *(unsigned *)(f->esp + 28));
      break;
    case SYS_SEEK:
      syscall_seek(*(int*)(f->esp + 16), *(unsigned*)(f->esp + 20));
      break;
    case SYS_TELL:
      syscall_tell(*(int*)(f->esp + 20));
      break;
    case SYS_CLOSE:
      syscall_close(*(int*)(f->esp + 4));
      break;
    case SYS_MMAP:
      f->eax = (int)syscall_mmap(*(int*)(f->esp + 16), *(char**)(f->esp + 20));
      break;
    case SYS_MUNMAP:
      syscall_munmap(*(int*)(f->esp + 4));
      break;
    case SYS_CHDIR:
      f->eax = syscall_chdir(*(const char**)(f->esp + 4));
      break;
    case SYS_MKDIR:
      f->eax = syscall_mkdir(*(const char**)(f->esp + 4));
      break;
    case SYS_READDIR:
      f->eax = (int)syscall_readdir(*(int*)(f->esp + 4), *(char**)(f->esp +8));
      break;
    case SYS_ISDIR:
      f->eax = syscall_isdir(*(int*)(f->esp + 4));
      break;
    case SYS_INUMBER:
      f->eax = syscall_inumber(*(int*)(f->esp + 4));
      break;
    default:
      SYSCALL_EXIT;
  }
}

static
void syscall_halt (void) 
{
  shutdown_power_off(); 
  NOT_REACHED ();
}

void syscall_exit(int status)
{
  struct thread *current, *parent;

  current = thread_current ();
  if (thread_has_parent (current))
  {
    parent = thread_get_parent (current);
    if (!thread_spread_exit_status (parent, current->tid, status))
    {
      status = -1;
      goto done;
    }
    if (!thread_remove_child (parent, current))
    {
      status = -1;
      goto done;
    }
  }

done:
  printf("%s: exit(%d)\n", current->filename, status);
  thread_exit ();

  NOT_REACHED ();
}
static 
tid_t syscall_exec(const char *filename)
{
  tid_t tid;

  tid = process_execute (filename);

  return tid;
}
static 
int syscall_wait (tid_t tid)
{
  int result;

  result = process_wait (tid);

  return result;
}
static 
bool syscall_create (const char *filename, unsigned initial_size)
{
  return filesys_create(filename, initial_size);
}

static 
bool syscall_remove (const char *filename)
{
  bool retval;
  lock_acquire (&file_lock);
  retval =  filesys_remove (filename);
  lock_release (&file_lock);

  return retval;
}

static 
int syscall_open (const char *filename)
{
  struct opened_file* opened;

  opened = opened_file_open (filename);

  if (opened == NULL)
    return -1;

  return opened->fd;
}

static 
int syscall_filesize (int fd)
{
  int retval;
  struct opened_file* of;

  of = opened_file_get_from_fd (fd);
  if (of == NULL) SYSCALL_EXIT;

  retval = opened_file_length (of);

  return retval;
}
static 
int syscall_read (int fd, void *buffer, unsigned size)
{
  unsigned i;
  int retval;
  struct opened_file *of;

  if (fd == STDIN_FILENO) /* Standard Input */
  {
    lock_acquire(&file_lock);
    for (i = 0; i < size; i++)
      ((uint8_t*)buffer)[i] = input_getc();
    lock_release(&file_lock);
    retval = size;
  }

  else 
  {
    of = opened_file_get_from_fd (fd);

    if (of == NULL) return -1;

    retval = opened_file_read (of, buffer, size);
  }

  return retval;
}
static 
int syscall_write (int fd, const void *buffer, unsigned size)
{
  int retval;
  struct opened_file *of;
  struct list_elem *child;
  struct thread *current;

  current = thread_current ();

  if (fd == STDOUT_FILENO)
  {
  /* I don't understand Why "putbuf call" must be in critical session with file_lock 
   * If there is any race condition issue, erase comment out code */
    lock_acquire(&file_lock);
    putbuf(buffer, size);
    lock_release(&file_lock);
    retval = size;
  }
  else if (fd == STDIN_FILENO)
  {SYSCALL_EXIT;}

  else
  {
    of = opened_file_get_from_fd (fd);

    if (of == NULL)
      SYSCALL_EXIT;

    child = list_search (&current->children, is_same_process_filename,
                          (void *)of->filename);

    if (child != list_end (&current->children))
       return -1;

    retval = opened_file_write (of, buffer, size);
  }
  return retval;
}

static void
syscall_seek (int fd, unsigned position)
{
  struct opened_file *of;

  of = opened_file_get_from_fd (fd);
  if (of == NULL) SYSCALL_EXIT;

  opened_file_seek (of, position);
}

static unsigned
syscall_tell (int fd)
{
  struct opened_file *of;

  of = opened_file_get_from_fd (fd);
  if (of == NULL) SYSCALL_EXIT;

  return opened_file_tell (of);
}

static void
syscall_close (int fd)
{
  struct opened_file *of;

  of = opened_file_get_from_fd (fd);
  if (of == NULL) SYSCALL_EXIT;

  opened_file_close (of);
}

static int
syscall_mmap (int fd, void *addr)
{
  int retval;
  struct opened_file *of;
  struct mmap_file *mf;
  of = opened_file_get_from_fd (fd);

  if (of == NULL)
    SYSCALL_EXIT;
  
  mf = page_mmap (of, addr);
  if (mf == NULL) return -1;

  retval = mf->mapid;

  return retval;
}

static void
syscall_munmap (int mapid)
{
  bool success;
  struct list_elem *e;
  struct mmap_file *mf;
  struct thread *current;

  current = thread_current ();
  e = list_search (&current->mmap_file_list, is_same_md, (void*) mapid);

  if (e == list_end (&current->mmap_file_list))
    SYSCALL_EXIT;

  mf = list_entry (e, struct mmap_file, elem);

  success = page_unmap (mf);

  if (!success)
    SYSCALL_EXIT;
}

static bool syscall_chdir (const char *dir UNUSED)
{
  return false;
}
static bool syscall_mkdir (const char *dir UNUSED)
{
  return false;
}
static bool syscall_readdir (int fd UNUSED, char name[READDIR_MAX_LEN + 1] UNUSED)
{
  return false;
}
static bool syscall_isdir (int fd UNUSED)
{
  return false;
}
static int syscall_inumber (int fd UNUSED)
{
  return 0;
}

static bool
is_valid_ptr (void *vaddr, const void *esp) {
  bool load = false;
  struct page_entry *pe;

  if (!(is_user_vaddr (vaddr) && vaddr > USER_VADDR_BOTTOM))
    goto done;

  pe = page_lookup ((void *)vaddr);
  
  if (pe)
  {
    page_load (pe);
    load = page_is_loaded (pe);
  }
  else if (vaddr >= esp - STACK_HEURISTIC)
    load = grow_stack ((void *) vaddr);

done:
  if (!load) SYSCALL_EXIT;

  return load;
}

static bool
is_valid_string (void *buffer, const void *esp)
{
  char *tmp;
  char *page_end;

  tmp = buffer;
  while (is_valid_ptr (tmp, esp))
  {
    page_end = pg_round_up (tmp);
    for (tmp = buffer; tmp < page_end ; tmp ++)
    {
      if (*tmp == '\0')
        return true;
    }
    tmp ++;
  }

  NOT_REACHED ();
  return false;
}

static bool
is_valid_buffer (void *buffer, const void *esp, off_t size, bool writable)
{
  void *tmp;
  off_t remain_size;
  struct page_entry *pe;

  for (tmp = pg_round_down(buffer),
      remain_size = buffer - tmp + size;
      remain_size > 0 && is_valid_ptr (tmp, esp);
      remain_size -= PGSIZE, tmp += PGSIZE)
  {
    pe = page_lookup (tmp);

    if (writable && !page_is_writable (pe)) 
    {
      SYSCALL_EXIT;
    }
  }
  return true;
}

bool is_same_process_filename (const struct list_elem *a, void* filename)
{
  return strcmp (
      list_entry(a, struct thread, child_elem)->filename, (char *)filename
      ) == 0;
}
