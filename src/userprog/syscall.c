#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

typedef int mapid_t;
#define READDIR_MAX_LEN 14
static void syscall_handler (struct intr_frame *);
static void halt(void);
static void exit(int status);
static tid_t exec(const char *file);
static int wait (tid_t tid);
static bool create (const char *file, unsigned initial_size);
static bool remove (const char *file);
static bool open (const char *file);
static int filesize (int fd);
static int read (int fd, void *buffer, unsigned size);
static int write (int fd, const void *buffer, unsigned size);
static void seek (int fd, unsigned position);
static unsigned tell (int fd);
static void close (int fd);
static mapid_t mmap (int fd, void *addr);
static void munmap (mapid_t mapid);
static bool chdir (const char *dir);
static bool mkdir (const char *dir);
static bool readdir (int fd, char name[READDIR_MAX_LEN + 1]);
static bool isdir (int fd);
static int inumber (int fd);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  int* NUMBER;
  void *arg0, *arg1, *arg2;
  NUMBER = (int*)(f->esp + sizeof(int));
  arg0 = f->esp + sizeof(int) + sizeof(void*) * 1;
  arg1 = f->esp + sizeof(int) + sizeof(void*) * 2;
  arg2 = f->esp + sizeof(int) + sizeof(void*) * 3;
  switch (*NUMBER)
  {
    /* Project 2 */
    case SYS_HALT:     halt(); break;
    case SYS_EXIT:     exit(*(int*)arg0); break;
    case SYS_EXEC:     exec((const char*)arg1); break;
    case SYS_WAIT:     wait(*(int*)arg0); break;
    case SYS_CREATE:   
      printf("%s %d %s\n", __func__, *NUMBER, "SYS_CREATE");
      break;
    case SYS_REMOVE:   
      printf("%s %d %s\n", __func__, *NUMBER, "SYS_REMOVE");
      break;
    case SYS_OPEN:     
      printf("%s %d %s\n", __func__, *NUMBER, "SYS_OPEN");
      break;
    case SYS_FILESIZE: 
      printf("%s %d %s\n", __func__, *NUMBER, "SYS_FILESIZE");
      break;
    case SYS_READ:     
      printf("%s %d %s\n", __func__, *NUMBER, "SYS_READ");
      break;
    case SYS_WRITE:    
      printf("%s %d %s\n", __func__, *NUMBER, "SYS_WRITE");
      break;
    case SYS_SEEK:     
      printf("%s %d %s\n", __func__, *NUMBER, "SYS_SEEK");
      break;
    case SYS_TELL:     
      printf("%s %d %s\n", __func__, *NUMBER, "SYS_TELL");
      break;
    case SYS_CLOSE:    
      printf("%s %d %s\n", __func__, *NUMBER, "SYS_CLOSE");
      break;
  }
  printf("%s %d\n", __func__, *NUMBER);
  thread_exit ();
}

static
void halt (void) { shutdown_power_off(); }

static 
void exit(int status)
{
  thread_exit();
}
static 
tid_t exec(const char *file)
{
  /* NOT IMPLEMENTED */
  return 0;
}
static 
int wait (tid_t tid)
{
  /* NOT IMPLEMENTED */
}
static 
bool create (const char *file, unsigned initial_size)
{
  /* NOT IMPLMENTED */
  return false;
}
static 
bool remove (const char *file)
{
  /* NOT IMPLMENTED */
  return false;
}
static 
bool open (const char *file)
{
  /* NOT IMPLMENTED */
  return false;
}
static 
int filesize (int fd)
{
  /* NOT IMPLEMENTED */
  return 0;
}
static 
int read (int fd, void *buffer, unsigned size)
{
  /* NOT IMPLEMENTED */
  return 0;

}
static 
int write (int fd, const void *buffer, unsigned size)
{
  /* NOT IMPLEMENTED */
  return 0;
}
static void seek (int fd, unsigned position)
{
}
static unsigned tell (int fd)
{
  return 0;
}
static void close (int fd)
{
}
static mapid_t mmap (int fd, void *addr)
{
  return 0;
}
static void munmap (mapid_t mapid)
{
}
static bool chdir (const char *dir)
{
  return false;
}
static bool mkdir (const char *dir)
{
  return false;
}
static bool readdir (int fd, char name[READDIR_MAX_LEN + 1])
{
  return false;
}
static bool isdir (int fd)
{
  return false;
}
static int inumber (int fd)
{
  return 0;
}
