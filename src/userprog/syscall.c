#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/shutdown.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

typedef int pid_t;
typedef void* arg_t;
static void check_address (void *addr);
static void syscall_handler (struct intr_frame *);
static void get_argument (void *esp, arg_t *arg, int count);
static void syscall_halt (void) NO_RETURN;
static void syscall_exit (int status) NO_RETURN;
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
    case SYS_EXIT:                   /* Terminate this process. */
      get_argument (f->esp, (void **)args, 1);
      syscall_exit ((int)args[0]);
      break;
    case SYS_EXEC:                   /* Start another process. */
      get_argument (f->esp, args, 1);
      f->eax = syscall_exec ((const char *)args[0]);
      break;
    case SYS_WAIT:                   /* Wait for a child process to die. */
      get_argument (f->esp, args, 1);
      f->eax = syscall_wait ((int)args[0]);
      break;
    case SYS_CREATE:                 /* Create a file. */
      get_argument (f->esp, args, 2);
      f->eax = syscall_create ((const char *)args[0], (unsigned)args[1]);
      break;
    case SYS_REMOVE:                 /* Delete a file. */
      get_argument (f->esp, args, 1);
      f->eax = syscall_remove ((const char *)args[0]);
      break;
    case SYS_OPEN:                   /* Open a file. */
      get_argument (f->esp, args, 1);
      f->eax = syscall_open ((const char *)args[0]);
      break;
    case SYS_FILESIZE:               /* Obtain a file's size. */
      get_argument (f->esp, args, 1);
      f->eax = syscall_filesize ((int)args[0]);
      break;
    case SYS_READ:                   /* Read from a file. */
      get_argument (f->esp, args, 3);
      f->eax = syscall_read ((int)args[0], (void *)args[1], (unsigned)args[2]);
      break;
    case SYS_WRITE:                  /* Write to a file. */
      get_argument (f->esp, args, 3);
      f->eax = syscall_write ((int)args[0], (const void *)args[1],
          (unsigned)args[2]);
      break;
    case SYS_SEEK:                   /* Change position in a file. */
      get_argument (f->esp, args, 2);
      syscall_seek ((int)args[0], (unsigned)args[1]);
      break;
    case SYS_TELL:                   /* Report current position in a file. */
      get_argument (f->esp, args, 1);
      f->eax = syscall_tell ((int)args[0]);
    case SYS_CLOSE:                  /* Close a file. */
      get_argument (f->esp, args, 1);
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
static void get_argument (void *esp, arg_t *arg, int count)
{
  int i;
  for (i = 0; i < count; i ++)
  {
    check_address (esp + 4 * (i + 1));
    arg[i] = ((arg_t *)esp)[i+1];
  }
}
static void syscall_halt (void)
{
  shutdown_power_off ();
}
static void syscall_exit (int status)
{
  struct thread *current = thread_current ();

  current->exit_status = status;
  printf("%s: exit(%d)\n", current->process_name, status);
  thread_exit ();
}
static pid_t syscall_exec (const char *cmd_line)
{
  struct thread *current = thread_current ();
  pid_t retval = process_execute (cmd_line);
  return retval;
}
static int syscall_wait (pid_t pid)
{
  return process_wait (pid);
}
static bool syscall_create (const char *file, unsigned initial_size)
{
  return filesys_create (file, initial_size);
}
static bool syscall_remove (const char *file)
{
  return filesys_remove (file);
}
static int syscall_open (const char *file)
{
  return -1;
}
static int syscall_filesize (int fd)
{
  return -1;
}
static int syscall_read (int fd, void *buffer, unsigned length)
{
  return -1;
}
static int syscall_write (int fd, const void *buffer, unsigned length)
{
  return -1;
}
static void syscall_seek (int fd, unsigned position)
{
}
static unsigned syscall_tell (int fd)
{
}
static void syscall_close (int fd)
{
}
#endif
