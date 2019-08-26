#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/synch.h"
#include <debug.h>
void syscall_init (void);

void syscall_exit (int);

#define SYSCALL_EXIT  syscall_exit(-1)
#endif /* userprog/syscall.h */
