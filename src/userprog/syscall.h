#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/thread.h"

void syscall_init (void);
void check_address (void *addr);
void get_argument (void *esp, int *arg, int count);

void halt (void);
void exit (int status);
tid_t exec(const char * cmd_line);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);

#endif /* userprog/syscall.h */
