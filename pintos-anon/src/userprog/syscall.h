#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <list.h>
void syscall_init (void);
int sys_write(int fd, char *s, unsigned int size); // Handles write syscall
int sys_open(char *filename); // Handles open syscall
int sys_close(int fd);
int sys_read(int fd, char *s, unsigned int size);
int sys_seek(int fd, unsigned int pos);
int sys_tell(int fd);
int sys_filesize(int fd);
struct fd_struct *fd_item(int fd);

struct fd_struct {
  int fd;
  struct file *file;
  struct list_elem felem;
};
#endif /* userprog/syscall.h */
