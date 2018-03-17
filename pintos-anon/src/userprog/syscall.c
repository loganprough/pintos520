#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include <string.h>

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

// Write to file or stdout
int sys_write(int fd, char *s, unsigned int size) {
  if (!(fd)) return -1; // STDIN has file descriptor 0
  if (fd == 1) { // STDOUT has file descriptor 1
    putbuf(s, size);
    return (int)size;
  }
  // Otherwise, write out to the file
  struct fd_struct *fds;
  if ((fds = fd_item(fd)) == NULL) return -1;
  return file_write(fds->file, s, size);
}

int sys_open(char *filename) {
  //printf("\n\nopening: %s\n\n", filename);
  if (filename == NULL || filename[0] == 0) return -1;
  struct file *f = filesys_open(filename);
  if (f == NULL) return -1;
  //printf("\nfile is not null\n");
  struct fd_struct *fds = palloc_get_page(PAL_ZERO);
  memset(fds, 0, sizeof(*fds));
  struct list lfds = thread_current()->list_fds;
  if (list_empty(&lfds)) fds->fd = 3;
  else fds->fd = list_entry(list_front(&lfds), struct fd_struct, felem)->fd + 1;
  list_push_front(&lfds, &fds->felem);
  return fds->fd;
}

int sys_close(int fd) {
  struct fd_struct *fds;
  if ((fds = fd_item(fd)) == NULL) return -1;
  list_remove(&fds->felem);
  file_close(fds->file);
  return 0;
}

int sys_read(int fd, char *s, unsigned int size) {
  if (size <= 0) return 0;
  struct fd_struct *fds;
  if ((fds = fd_item(fd)) == NULL) return -1;
  return file_read(fds->file, s, size);
}

int sys_seek(int fd, unsigned int pos) {
  struct fd_struct *fds;
  if ((fds = fd_item(fd)) == NULL) return -1;
  file_seek(fds->file, pos);
  return 0;
}

int sys_tell(int fd) {
  struct fd_struct *fds;
  if ((fds = fd_item(fd)) == NULL) return -1;
  return file_tell(fds->file);
}

int sys_filesize(int fd) {
  struct fd_struct *fds;
  if ((fds = fd_item(fd)) == NULL) return -1;
  return file_length(fds->file);
}

int sys_create(char *filename, int size) {
  //printf("\n\nTrying to create \"%s\"\n\n", filename);
  if ((filename == NULL) || (size < 0) || (filename[0] == 0)) return -1;
  //printf("filename[0] is \"%d\"\n\n", filename[0]);
  if (strlen(filename) > 14) return 0;
  return filesys_create(filename, size);
}

struct fd_struct *fd_item(int fd) {
  struct list_elem *e;
  struct list *list_fds = &thread_current()->list_fds;
  struct fd_struct *fds = NULL;

  // Based on sample loop code from list library files
  for(e = list_begin(list_fds); e != list_end(list_fds); e = list_next(e)) {
    fds = list_entry(e, struct fd_struct, felem);
    if (fds->fd == fd) return fds;
  }

  // Return NULL if not found
  return NULL;
}

int sys_wait(tid_t pid) {
	return process_wait(pid);
}

// Both of the following two functions are derived from ryantimwilson's work
// Reference: https://github.com/ryantimwilson/Pintos-Project-2/blob/master/src/userprog/syscall.c :298
void is_pointer_valid(const void *vaddr) {
  //printf("\n\nChecking pointer %p\n\n", vaddr);
  if ((!(is_user_vaddr(vaddr))) || (!(is_user_vaddr(vaddr))) || ((unsigned int)vaddr < (unsigned int)0x08048000)) thread_exit(-1);
}

int user_kernel_conversion(const void *vaddr)
{
	is_pointer_valid(vaddr);
	void *ptr = pagedir_get_page(thread_current()->pagedir, vaddr);
	if (!ptr) thread_exit(-1);
	return (int)ptr;
}

char *verify_string(char *addr) {
  user_kernel_conversion(addr);
  return addr;
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  //printf ("system call!\n");
  int retval = 0;

  // find out which syscall and do it
  int *p = (int *)user_kernel_conversion(f->esp);
  int number = *p;
	// Call system functions with parameters. Referenced https://github.com/pindexis/pintos-project2/blob/master/userprog/syscall.c to get some of the typecasts to stop complaining
  switch (number) {
  case SYS_WRITE:
	  sys_write(*(int *)user_kernel_conversion(f->esp + 4), verify_string(*(char **)user_kernel_conversion(f->esp + 8)), *(unsigned int *)user_kernel_conversion(f->esp + 12)); break;
  case SYS_WAIT: process_wait(*(int *)user_kernel_conversion(f->esp + 4)); break; // TODO actually implement wait
  case SYS_HALT: shutdown(); break;
  case SYS_EXIT: thread_exit(*(int *)user_kernel_conversion(f->esp + 4)); break;
  case SYS_EXEC: retval = process_execute(verify_string(*(char **)user_kernel_conversion(f->esp + 4))); break;
  case SYS_CREATE: retval = sys_create(verify_string(*(char **)user_kernel_conversion(f->esp + 4)), *(int *)user_kernel_conversion(f->esp + 8)); break;
  case SYS_REMOVE: retval = filesys_remove(verify_string(*(char **)user_kernel_conversion(f->esp + 4))); break;
  case SYS_OPEN: retval = sys_open(verify_string(*(char **)user_kernel_conversion(f->esp + 4))); break;
  case SYS_CLOSE: retval = sys_close(*(int *)user_kernel_conversion(f->esp + 4)); break;
  case SYS_READ: retval = sys_read(*(int *)user_kernel_conversion(f->esp + 4), verify_string(*(char **)user_kernel_conversion(f->esp + 8)), *(unsigned int *)user_kernel_conversion(f->esp + 12)); break;
  case SYS_SEEK: retval = sys_seek(*(int *)user_kernel_conversion(f->esp + 4), *(unsigned int *)user_kernel_conversion(f->esp + 8)); break;
  case SYS_TELL: retval = sys_tell(*(int *)user_kernel_conversion(f->esp + 4)); break;
  case SYS_FILESIZE: retval = sys_filesize(*(int *)user_kernel_conversion(f->esp + 4)); break;
  default: thread_exit(0);
 }

  //printf("\n\nretval is %d, num is %d\n\n", retval, number);
  if (retval == -1 && number == SYS_CREATE) thread_exit(retval); // Create went wrong
  f->eax = retval;
}
