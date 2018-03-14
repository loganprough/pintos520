#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"

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
    //case SYS_OPEN: 
    default: thread_exit(0);
  }

  if (retval < 0) thread_exit(retval); // Syscall went wrong
}
