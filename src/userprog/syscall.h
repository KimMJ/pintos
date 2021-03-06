#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/thread.h"

#define CLOSE_ALL -1

void syscall_init (void);
//void check_address (void *addr, void *esp);
struct vm_entry *check_address(void *addr, void *esp);
void check_valid_buffer(void *buffer, unsigned size, void *esp, bool to_write);
void check_valid_string (const void *str, void *esp);

void get_argument (void *esp, int *arg, int count);

void halt (void);
void exit (int status);
tid_t exec(const char * cmd_line);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);

struct lock filesys_lock;
int open(const char *file);
int filesize(int fd);
int read (int fd, void * buffer, unsigned size);
int write (int fd, void * buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);
int wait(tid_t tid);

mapid_t mmap(int fd, void *addr);
void munmap(mapid_t mapping);
void do_munmap(struct mmap_file *mmap_file);

#endif /* userprog/syscall.h */
