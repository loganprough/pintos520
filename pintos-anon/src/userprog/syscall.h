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
int sys_wait(int pid);
// Checks to see if the virtual address is a valid pointer
// Reference: https://github.com/ryantimwilson/Pintos-Project-2/blob/master/src/userprog/syscall.c :298-304
void is_pointer_valid(const void *vaddr);
int user_kernel_conversion(const void *vaddr);
struct fd_struct *fd_item(int fd);

struct fd_struct {
  int fd;
  struct file *file;
  struct list_elem felem;
};
#endif /* userprog/syscall.h */
