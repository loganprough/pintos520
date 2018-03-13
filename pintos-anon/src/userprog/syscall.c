#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

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
  return -1;
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  //printf ("system call!\n");

  // TODO check if stack pointer is valid

  // find out which syscall and do it
  int *p = f->esp;
  int number = *p;
  switch(number) {
    case SYS_WRITE:
      // Call sys_write with parameters. Referenced https://github.com/pindexis/pintos-project2/blob/master/userprog/syscall.c to get some of the typecasts to stop complaining
      sys_write(*(int *)(f->esp + 4), *(char **)(f->esp + 8), *(unsigned int *)(f->esp + 12)); break;
    default: thread_exit();
  }
}
