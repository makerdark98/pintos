#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

typedef int mapid_t;
#define READDIR_MAX_LEN 14
void check_ptr_validity(void * ptr);
static int get_arg(void* addr);
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

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_lock);
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
  switch (*NUMBER)
  {
    /* Project 2 */
    case SYS_HALT:     
      syscall_halt(); 
      break;
    case SYS_EXIT:     
      syscall_exit(*(int*)arg0); 
      break;
    case SYS_EXEC:     
      f->eax = syscall_exec(*(const char**)arg0); 
      break;
    case SYS_WAIT:     
      f->eax = syscall_wait(*(int*)arg0); 
      break;
    case SYS_CREATE:   
      f->eax = syscall_create(*(const char**)arg0, *(unsigned*)arg1); 
      break;
    case SYS_REMOVE:   
      f->eax = syscall_remove(*(const char**)arg0); 
      break;
    case SYS_OPEN:     
      f->eax = syscall_open(*(const char**)arg0);
      break;
    case SYS_FILESIZE: 
      f->eax = syscall_filesize(*(int*)arg0);
      break;
    case SYS_READ:     
      f->eax = syscall_read(*(int*)arg0, *(void**)arg1, *(unsigned *)arg2);
      break;
    case SYS_WRITE:    
      f->eax = 
        syscall_write(*(int*)(arg0), *(void**)arg1, *(unsigned *)(arg2));
      break;
    case SYS_SEEK:     
      syscall_seek(*(int*)arg0, *(unsigned*)arg1);
      break;
    case SYS_TELL:     
      syscall_tell(*(int*)arg0);
      break;
    case SYS_CLOSE:    
      syscall_close(*(int*)arg0);
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
      f->eax = syscall_readdir(*(int*)arg0, *(char*)arg1);
      break;
    case SYS_ISDIR:
      f->eax = syscall_isdir(*(int*)arg0);
      break;
    case SYS_INUMBER:
      f->eax = syscall_inumber(*(int*)arg0);
      break;
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
  current->exit_status = status;
  // TODO : close file list
  printf("%s: exit(%d)\n", current->filename,status);
  thread_exit();

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
  result = process_wait(tid);
  return result;
}
static 
bool syscall_create (const char *file, unsigned initial_size)
{
  if (file == NULL) return false;
  return filesys_create(file, initial_size);
}
static 
bool syscall_remove (const char *file)
{
  if (file == NULL) return false;
  return filesys_remove(file);
}
static 
int syscall_open (const char *file)
{
  /* NOT IMPLEMENTED */
  struct file *f;
  if (file == NULL) return -1;
  f = filesys_open(file);
  return -1;
}
static 
int syscall_filesize (int fd)
{
  /* NOT IMPLEMENTED */
  return 0;
}
static 
int syscall_read (int fd, void *buffer, unsigned size)
{
  unsigned i;
  struct file *f;
  if (fd == 0) /* Standard Input */
  {
    for (i = 0; i < size; i++)
    {
      ((uint8_t*)buffer)[i] = input_getc();
    }
  }
  /* NOT IMPLEMENTED */
  return 0;

}
static 
int syscall_write (int fd, const void *buffer, unsigned size)
{
  struct file *f;
  check_ptr_validity(buffer);
  if (fd == 1)
  {
    lock_acquire(&file_lock);
    putbuf(buffer, size);
    lock_release(&file_lock);
  }
  /* NOT IMPLEMENTED */
  return 0;
}
static void syscall_seek (int fd, unsigned position)
{
}
static unsigned syscall_tell (int fd)
{
  return 0;
}
static void syscall_close (int fd)
{
}
static mapid_t syscall_mmap (int fd, void *addr)
{
  return 0;
}
static void syscall_munmap (mapid_t mapid)
{
}
static bool syscall_chdir (const char *dir)
{
  return false;
}
static bool syscall_mkdir (const char *dir)
{
  return false;
}
static bool syscall_readdir (int fd, char name[READDIR_MAX_LEN + 1])
{
  return false;
}
static bool syscall_isdir (int fd)
{
  return false;
}
static int syscall_inumber (int fd)
{
  return 0;
}
void
check_ptr_validity(void * ptr)
{
  if(!(ptr>0x08048000 && ptr< PHYS_BASE ))
  {
    syscall_exit(-1);
  }
  /*
  void * pointer = pagedir_get_page(thread_current()->pagedir, ptr); //check if mapped
  if(!pointer)
  {
    syscall_exit(-1);
  }
  */
  
}
