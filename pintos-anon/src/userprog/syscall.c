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
#include <string.h>

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

// Write to file or stdout
int sys_write(int fd, char *s, unsigned int size) {
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
  struct fd_struct *fds = palloc_get_page(PAL_ZERO);
  memset(fds, 0, sizeof(*fds));
  fds->file = filesys_open(filename);
  //TODO make sure filesys_open worked
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

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  //printf ("system call!\n");
  int retval = 0;

  // TODO check if stack pointer is valid

  // find out which syscall and do it
  int *p = f->esp;
  int number = *p;
  switch(number) {
    case SYS_WRITE:
      // Call sys_write with parameters. Referenced https://github.com/pindexis/pintos-project2/blob/master/userprog/syscall.c to get some of the typecasts to stop complaining
      sys_write(*(int *)(f->esp + 4), *(char **)(f->esp + 8), *(unsigned int *)(f->esp + 12)); break;
    case SYS_WAIT: while(1){}; break; // TODO actually implement wait
    case SYS_HALT: shutdown(); break;
    case SYS_EXIT: thread_exit(*((int *)f->esp + 1)); break; // TODO make sure pointer valid
    case SYS_EXEC: retval = process_execute(*(char **)(f->esp + 4)); break; // TODO make sure pointer valid
    case SYS_CREATE: retval = filesys_create(*(char **)(f->esp + 4), *(int *)(f->esp + 8)); break; // TODO ^^
    case SYS_REMOVE: retval = filesys_remove(*(char **)(f->esp + 4)); break; // TODO ^^
    case SYS_OPEN: sys_open(*(char **)(f->esp + 4)); break; // TODO ^^
    case SYS_CLOSE: sys_close(*(int *)(f->esp + 4)); break; // TODO ^^
    case SYS_READ: sys_read(*(int *)(f->esp + 4), *(char **)(f->esp + 8), *(unsigned int *)(f->esp + 12)); break; // TODO ^^
    case SYS_SEEK: sys_seek(*(int *)(f->esp + 4), *(unsigned int *)(f->esp + 8)); break; // TODO ^^
    case SYS_TELL: sys_tell(*(int *)(f->esp + 4)); break; // TODO ^^
    case SYS_FILESIZE: sys_filesize(*(int *)(f->esp + 4)); break; // TODO ^^
    default: thread_exit(0);
  }

  if (retval < 0) thread_exit(retval); // Syscall went wrong
}
