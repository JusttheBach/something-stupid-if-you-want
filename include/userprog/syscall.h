#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/thread.h"
#include <stdbool.h>

void syscall_init (void);
struct lock filesys_lock; //global lock for file accesses

void halt(void);
void exit(int status);
int fork (const char *thread_name);
int exec (const char *file_name);
int wait (tid_t pid);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);
int isValid(void *ptr);
#endif /* userprog/syscall.h */
