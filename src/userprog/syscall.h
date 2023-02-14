#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#define STDIN_FILENO 0
#define STDOUT_FILENO 1

void syscall_init(void);

int open(const char* name);
int filesize(int fd);
int read(int fd, void* buffer, unsigned size);
int write(int fd, const void* buffer, unsigned size);
unsigned tell(int fd);
void close(int fd);
void seek(int fd, unsigned position);

#endif /* userprog/syscall.h */
