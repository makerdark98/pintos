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
#include "filesys/filesys.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"

typedef int mapid_t;
#define READDIR_MAX_LEN 14
struct lock fd_lock;
#define SYSCALL_EXIT syscall_exit(-1)
//#define SYSCALL_EXIT ASSERT(1 != 1)
#define CHECK_PTR_VALIDITY(ptr) {                   \
  if (!( (void*)ptr > (void*)0x08048000             \
        && (void*)ptr < PHYS_BASE)                  \
        || (!pagedir_get_page (                     \
            thread_current ()->pagedir, ptr)))      \
    SYSCALL_EXIT;}                               
    

bool is_same_fd (const struct list_elem *a, void* fd);
bool is_same_process_filename (const struct list_elem *a, void* filename);
bool is_same_tid (const struct list_elem *a, void* tid);
static void syscall_handler (struct intr_frame *);
static void syscall_halt(void);
static void syscall_exit(int status);
static tid_t syscall_exec(const char *filename);
static int syscall_wait (tid_t tid);
static bool syscall_create (const char *file, unsigned initial_size);
static bool syscall_remove (const char *file);
static int syscall_open (const char *file);
static int syscall_filesize (int fd);
static int syscall_read (int fd, void *buffer, unsigned size);
static int syscall_write (int fd, const void *buffer, unsigned size);
static void syscall_seek (int fd, unsigned position);
static unsigned syscall_tell (int fd);
static void syscall_close (int fd);
static mapid_t syscall_mmap (int fd, void *addr);
static void syscall_munmap (mapid_t mapid);
static bool syscall_chdir (const char *dir);
static bool syscall_mkdir (const char *dir);
static bool syscall_readdir (int fd, char name[READDIR_MAX_LEN + 1]);
static bool syscall_isdir (int fd);
static int syscall_inumber (int fd);
static int allocate_fd (void);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_lock);
  lock_init(&fd_lock);
}

static void
syscall_handler (struct intr_frame *f) 
{
  int* NUMBER;
  void *arg0, *arg1, *arg2;
  NUMBER = (int*)(f->esp);
  arg0 = f->esp + sizeof(void*) * 5;
  arg1 = f->esp + sizeof(void*) * 6;
  arg2 = f->esp + sizeof(void*) * 7;
  CHECK_PTR_VALIDITY(f->esp);
  switch (*NUMBER)
  {
    /* Project 2 */
    case SYS_HALT:
      syscall_halt(); 
      break;
    case SYS_EXIT:
      CHECK_PTR_VALIDITY(f->esp + 4);
      syscall_exit(*(int*)(f->esp + 4)); 
      break;
    case SYS_EXEC:
      f->eax = syscall_exec(*(const char**)(f->esp + 4)); 
      break;
    case SYS_WAIT:
      f->eax = syscall_wait(*(int*)(f->esp + 4)); 
      break;
    case SYS_CREATE:
      f->eax = syscall_create(*(const char**)(f->esp + 16), *(unsigned*)(f->esp + 20)); 
      break;
    case SYS_REMOVE:
      f->eax = syscall_remove(*(const char**)(f->esp + 16)); 
      break;
    case SYS_OPEN:
      f->eax = syscall_open(*(const char**)(f->esp + 4));
      break;
    case SYS_FILESIZE:
      f->eax = syscall_filesize(*(int*)(f->esp + 4));
      break;
    case SYS_READ:
      f->eax = syscall_read(*(int*)arg0, *(void**)arg1, *(unsigned *)arg2);
      break;
    case SYS_WRITE:
      f->eax = 
        syscall_write(*(int*)(arg0), *(void**)arg1, *(unsigned *)(arg2));
      break;
    case SYS_SEEK:
      syscall_seek(*(int*)(f->esp + 16), *(unsigned*)(f->esp + 20));
      break;
    case SYS_TELL:
      syscall_tell(*(int*)arg0);
      break;
    case SYS_CLOSE:
      syscall_close(*(int*)(f->esp + 4));
      break;
    case SYS_PAGEFAULT:
      SYSCALL_EXIT;
      break;
    case SYS_MMAP:
      f->eax = (int)syscall_mmap(*(int*)(f->esp + 4), *(char**)(f->esp + 8));
      break;
    case SYS_MUNMAP:
      syscall_munmap(*(mapid_t*)arg0);
      break;
    case SYS_CHDIR:
      f->eax = syscall_chdir(*(const char**)arg0);
      break;
    case SYS_MKDIR:
      f->eax = syscall_mkdir(*(const char**)arg0);
      break;
    case SYS_READDIR:
      f->eax = (int)syscall_readdir(*(int*)arg0, *(char**)arg1);
      break;
    case SYS_ISDIR:
      f->eax = syscall_isdir(*(int*)arg0);
      break;
    case SYS_INUMBER:
      f->eax = syscall_inumber(*(int*)arg0);
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

static 
void syscall_exit(int status)
{
  struct thread *current = thread_current();
  struct exit_status_elem* e;
  struct list_elem *e1;

  if (current->parent != NULL)
  {
    e = malloc(sizeof(struct exit_status_elem));
    e->exit_status = status;
    e->tid = current->tid;
    list_push_back(&current->parent->exit_status_list, &e->elem);

    e1 = list_search (&current->parent->children, is_same_tid, (void *)e->tid);
    list_remove (e1);
  }

  /* 
  opend_file_list = thread_get_opend_file_list (current);
  for (e1 = list_begin (opend_file_list);
      e1 != list_end (opend_file_list);
      e1 = list_next (e1))
  {
    printf("%s :%s closed\n", __func__, 
        list_entry(e1, struct opend_file, elem) ->filename);

    list_remove (e1);
    close_opend_file (opend_file_list, 
        list_entry (e1, struct opend_file, elem));
    opend_file_free (list_entry(e1, struct opend_file, elem));
  }
        */

  printf("%s: exit(%d)\n", current->filename, status);
  thread_exit();

  NOT_REACHED ();
}
static 
tid_t syscall_exec(const char *filename)
{
  CHECK_PTR_VALIDITY(filename);
  
  tid_t tid;
  int i;
  char *tmp_filename;

  for (i = 0; filename[i] != '\0' && filename[i] !=' '; i++);

  tmp_filename = (char*)malloc((i+1) * sizeof(char));
  memcpy(tmp_filename, filename, i+1);
  tmp_filename[i] = '\0';

  if (!file_exists(tmp_filename)) 
    tid = -1;
  else 
  {
    tid = process_execute (filename);
    if (tid == -1) SYSCALL_EXIT;
  }

  free(tmp_filename);

  return tid;
}
static 
int syscall_wait (tid_t tid)
{
  int result;
  if (tid == -1) 
    return -1;

  result = process_wait(tid);

  return result;
}
static 
bool syscall_create (const char *file, unsigned initial_size)
{
  CHECK_PTR_VALIDITY(file);
  if (strcmp(file, "") == 0) 
    SYSCALL_EXIT;
  return filesys_create(file, initial_size);
}
static 
bool syscall_remove (const char *file)
{
  if (file == NULL) return false;
  bool retval = filesys_remove(file);
  return retval;
}
static 
int syscall_open (const char *filename)
{
  CHECK_PTR_VALIDITY (filename);

  struct opend_file* opend;
  struct list *opend_file_list;
  struct thread *t;

  if (filename == NULL) return -1;

  if (!file_exists(filename)) return -1;

  t = thread_current ();
  opend_file_list = thread_get_opend_file_list (t);

  opend = opend_file_alloc(filename, allocate_fd());
  list_push_back (opend_file_list, &opend->elem);

  return opend->fd;
}
static 
int syscall_filesize (int fd)
{
  int retval = 0;
  struct list *opend_file_list;
  struct file *file;
  struct opend_file *of;
  struct list_elem *e;

  opend_file_list = thread_get_opend_file_list(thread_current());
  e = list_search (opend_file_list, is_same_fd, (void *)fd);

  if (e == list_end(opend_file_list)) return -1;
  of = list_entry(e, struct opend_file, elem);

  lock_acquire(&file_lock);
  file = filesys_open(of->filename);
  retval = file_length(file);
  file_close(file);
  lock_release(&file_lock);

  return retval;
}
static 
int syscall_read (int fd, void *buffer, unsigned size)
{
  CHECK_PTR_VALIDITY(buffer);
  unsigned i;
  int retval;
  struct list *opend_file_list;
  struct opend_file *of;
  struct list_elem *e;
  struct file *file;

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
    opend_file_list = thread_get_opend_file_list(thread_current());
    e = list_search(opend_file_list, is_same_fd, (void *)fd);

    if (e == list_end(opend_file_list)) return -1;

    of = list_entry(e, struct opend_file, elem);
    lock_acquire(&file_lock);
    file = filesys_open(of->filename);
    file_seek(file, of->offset);
    retval = file_read(file, buffer, size);
    of->offset = file_tell(file);
    file_close(file);
    lock_release(&file_lock);
  }

  return retval;
}
static 
int syscall_write (int fd, const void *buffer, unsigned size)
{
  CHECK_PTR_VALIDITY(buffer);

  int retval;
  struct list *opend_file_list;
  struct opend_file *of;
  struct list_elem *e, *child;
  struct thread *t;
  struct file *file;

  if (fd == STDOUT_FILENO)
  {
    lock_acquire(&file_lock);
    putbuf(buffer, size);
    lock_release(&file_lock);
    retval = size;
  }

  else
  {
    t = thread_current ();
    opend_file_list = thread_get_opend_file_list(t);
    e = list_search(opend_file_list, is_same_fd, (void *)fd);

    if (e == list_end(opend_file_list)) return -1;
    of = list_entry(e, struct opend_file, elem);
    if (strcmp (of->filename, t->filename) == 0) return 0;

    child = list_search (&t->children, is_same_process_filename, (void *)of->filename);
    if (child != list_end (&t->children)) {
       return 0;
    }

    if (!file_exists(of->filename))
    {
      if (!filesys_create(of->filename, size))
        return -1;
    }

    lock_acquire(&file_lock);
    file = filesys_open(of->filename);
    file_seek(file, of->offset);

    retval = file_write (file, buffer, size);

    of->offset = file_tell(file);
    file_close(file);
    lock_release(&file_lock);
  }
  return retval;
}

static void syscall_seek (int fd, unsigned position)
{
  struct list_elem *e;
  struct list *opend_file_list;
  struct opend_file *of;
  opend_file_list = thread_get_opend_file_list(thread_current());
  e = list_search (opend_file_list, is_same_fd, (void *)fd);

  if (e == list_end (opend_file_list)) SYSCALL_EXIT;

  of = list_entry (e, struct opend_file, elem);
  lock_acquire (&file_lock);
  of->offset = position;
  lock_release (&file_lock);

}
static unsigned syscall_tell (int fd)
{
  struct list_elem *e;
  struct list *opend_file_list;
  struct opend_file *of;

  opend_file_list = thread_get_opend_file_list(thread_current());
  e = list_search(opend_file_list, is_same_fd, (void *)fd);

  if (e == list_end(opend_file_list)) SYSCALL_EXIT;
  of = list_entry(e, struct opend_file, elem);

  return of->offset;
}
static void syscall_close (int fd)
{
  struct list_elem *e;
  struct list *opend_file_list;
  struct opend_file *of;

  opend_file_list = thread_get_opend_file_list(thread_current());
  e = list_search(opend_file_list, is_same_fd, (void *)fd);
  
  if (e == list_end(opend_file_list)) SYSCALL_EXIT;
  of = list_entry(e, struct opend_file, elem);
  list_remove(e);

  opend_file_free (of);
}
static mapid_t syscall_mmap (int fd UNUSED, void *addr UNUSED)
{
  return 0;
}
static void syscall_munmap (mapid_t mapid UNUSED)
{
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

bool is_same_fd (const struct list_elem *a, void* fd)
{
  return list_entry(a, struct opend_file, elem)-> fd == (int)fd;
}

bool is_same_process_filename (const struct list_elem *a, void* filename)
{
  return strcmp (list_entry(a, struct thread, child_elem) -> filename, (char *)filename) == 0;
}

bool is_same_tid (const struct list_elem *a, void* tid)
{
  return list_entry(a, struct thread, child_elem) -> tid == (tid_t)tid;
}
