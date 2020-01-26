#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#ifndef USERPROG
#define USERPROG
#endif

#include "threads/thread.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
struct thread *get_child_process (tid_t pid);
void remove_child_process (struct thread *cp);

#endif /* userprog/process.h */
