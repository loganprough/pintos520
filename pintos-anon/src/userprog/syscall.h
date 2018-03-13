#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);
int sys_write(int fd, char *s, unsigned int size); // Handles write syscall
#endif /* userprog/syscall.h */
