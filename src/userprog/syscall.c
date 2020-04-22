#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/shutdown.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "userprog/process.h"

static struct lock filesys_lock;
typedef int pid_t;
typedef void* arg_t;
static void check_address (void *addr);
static void syscall_handler (struct intr_frame *);
static void get_argument (void *esp, arg_t *arg, int count, int offset);
static void syscall_halt (void) NO_RETURN;
static pid_t syscall_exec (const char *file);
static int syscall_wait (pid_t);
static bool syscall_create (const char *file, unsigned initial_size);
static bool syscall_remove (const char *file);
static int syscall_open (const char *file);
static int syscall_filesize (int fd);
static int syscall_read (int fd, void *buffer, unsigned length);
static int syscall_write (int fd, const void *buffer, unsigned length);
static void syscall_seek (int fd, unsigned position);
static unsigned syscall_tell (int fd);
static void syscall_close (int fd);

void
syscall_init (void) 
{
  lock_init (&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  uint32_t *sp = f->esp;
  check_address ((void *)sp);
  int syscall_n = *sp;
  arg_t args[3];

  switch (syscall_n)
  {
    case SYS_HALT:                   /* Halt the operating system. */
      syscall_halt ();
      break;
    case SYS_EXIT:                   /* Terminate this process. */
      get_argument (f->esp, (void **)args, 1, 0);
      syscall_exit ((int)args[0]);
      break;
    case SYS_EXEC:                   /* Start another process. */
      get_argument (f->esp, args, 1, 0);
      f->eax = syscall_exec ((const char *)args[0]);
      break;
    case SYS_WAIT:                   /* Wait for a child process to die. */
      get_argument (f->esp, args, 1, 0);
      f->eax = syscall_wait ((int)args[0]);
      break;
    case SYS_CREATE:                 /* Create a file. */
      get_argument (f->esp, args, 2, 12);
      f->eax = syscall_create ((const char *)args[0],(unsigned)args[1]);
      break;
    case SYS_REMOVE:                 /* Delete a file. */
      get_argument (f->esp, args, 1, 0);
      f->eax = syscall_remove ((const char *)args[0]);
      break;
    case SYS_OPEN:                   /* Open a file. */
      get_argument (f->esp, args, 1, 0);
      f->eax = syscall_open ((const char *)args[0]);
      break;
    case SYS_FILESIZE:               /* Obtain a file's size. */
      get_argument (f->esp, args, 1, 0);
      f->eax = syscall_filesize ((int)args[0]);
      break;
    case SYS_READ:                   /* Read from a file. */
      get_argument (f->esp, args, 3, 4);
      f->eax = syscall_read ((int)args[0], (void *)args[1], (unsigned)args[2]);
      break;
    case SYS_WRITE:                  /* Write to a file. */
      get_argument (f->esp, args, 3, 16);
      f->eax = syscall_write ((int)args[0], (void *)args[1], (unsigned)args[2]);
      break;
    case SYS_SEEK:                   /* Change position in a file. */
      get_argument (f->esp, args, 2, 0);
      syscall_seek ((int)args[0], (unsigned)args[1]);
      break;
    case SYS_TELL:                   /* Report current position in a file. */
      get_argument (f->esp, args, 1, 0);
      f->eax = syscall_tell ((int)args[0]);
    case SYS_CLOSE:                  /* Close a file. */
      get_argument (f->esp, args, 1, 0);
      syscall_close ((int)args[0]);
    default:
      printf ("system call!\n");
      thread_exit ();
  }
}

#ifdef USERPROG
static void check_address (void *addr)
{
  if (!is_user_vaddr (addr))
    syscall_exit (-1);
}
static void get_argument (void *esp, arg_t *arg, int count, int offset)
{
  int i;
  for (i = 0; i < count; i ++)
  {
    check_address (esp + 4 * (i + 1) + offset);
    arg[i] = *(arg_t*) (esp + 4 * (i + 1) + offset);
  }
}
static void syscall_halt (void)
{
  shutdown_power_off ();
}
void syscall_exit (int status)
{
  struct thread *current = thread_current ();

  current->exit_status = status;
  printf("%s: exit(%d)\n", current->process_name, status);
  thread_exit ();
}
static pid_t syscall_exec (const char *cmd_line)
{
  pid_t retval = process_execute (cmd_line);
  if (retval == -1) syscall_exit (-1);
  return retval;
}
static int syscall_wait (pid_t pid)
{
  return process_wait (pid);
}
static bool syscall_create (const char *file, unsigned initial_size)
{
  if (file == NULL) {
    syscall_exit(-1);
  }
  return filesys_create (file, initial_size);
}
static bool syscall_remove (const char *file)
{
  return filesys_remove (file);
}
static int syscall_open (const char *filename)
{
  struct file* file = filesys_open (filename);

  if (!file)
    return -1;
  return process_add_file (file);
}
static int syscall_filesize (int fd)
{
  struct file* file = process_get_file (fd);

  if (!file)
    return -1;
  return file_length (file);
}
static int syscall_read (int fd, void *buffer, unsigned length)
{
  if (fd == 0) {
    int i;
    for (i = 0; i < length; ++ i) 
      ((uint8_t *)buffer)[i] = input_getc();
    return length;
  }

  struct file* file = process_get_file (fd);
  if (!file)
    return -1;

  int retval;
  lock_acquire (&filesys_lock);
  retval = file_read (file, buffer, length);
  lock_release (&filesys_lock);

  return retval;
}
static int syscall_write (int fd, const void *buffer, unsigned length)
{
  if (fd == 1) {
    putbuf (buffer, length);
    return length;
  }

  struct file* file = process_get_file (fd);

  if (!file)
    return -1;

  int retval;
  lock_acquire (&filesys_lock);
  retval = file_write (file, buffer, length);
  lock_release (&filesys_lock);

  return retval;
}
static void syscall_seek (int fd, unsigned position)
{
  struct file* file = process_get_file (fd);

  if (!file) return;

  lock_acquire (&filesys_lock);
  file_seek (file, position);
  lock_release (&filesys_lock);
}
static unsigned syscall_tell (int fd)
{
  struct file* file = process_get_file (fd);

  if (!file) return -1;
  unsigned retval;
  lock_acquire (&filesys_lock);
  retval = file_tell (file);
  lock_release (&filesys_lock);

  return retval;
}
static void syscall_close (int fd)
{
  process_close_file (fd);
}
#endif
