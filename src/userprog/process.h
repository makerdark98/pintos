#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#ifndef USERPROG
#define USERPROG
#endif

#include "threads/thread.h"
#include "filesys/filesys.h"

struct lock filesys_lock;
tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
struct thread *get_child_process (tid_t pid);
void remove_child_process (struct thread *cp);
void detach_children_process (struct thread *parent);

int process_add_file (struct file *f);
struct file *process_get_file (int fd);
void process_close_file (int fd);

#endif /* userprog/process.h */
