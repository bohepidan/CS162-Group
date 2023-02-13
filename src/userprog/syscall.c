#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "threads/malloc.h"

static void syscall_handler(struct intr_frame*);

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }
int open(const char* name);

/* Opens the file named file. Returns a nonnegative
 integer handle called a “file descriptor” (fd), or -1
  if the file could not be opened. */
int open(const char* name) {
  struct process* pcb = thread_current()->pcb;

  struct file* file = filesys_open(name);
  if (file == NULL) return -1;

  struct file_d* newfd = malloc(sizeof * newfd);
  if (newfd == NULL) return -1;

  if (list_empty(&pcb->file_table)) {

  }

}

static void syscall_handler(struct intr_frame* f UNUSED) {
  uint32_t* args = ((uint32_t*)f->esp);

  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

  printf("System call number: %d\n", args[0]);

  if (args[0] == SYS_EXIT) {
    f->eax = args[1];
    printf("%s: exit(%d)\n", thread_current()->pcb->process_name, args[1]);
    process_exit(args[1]);
  }
  else if (args[0] == SYS_PRACTICE) {
    f->eax = args[1] + 1;
  }
  else if (args[0] == SYS_HALT) {
    shutdown_power_off();
  }
  else if (args[0] == SYS_EXEC) {
    const char* cmd_line = (char*)args[1];
    f->eax = process_execute(cmd_line);
  }
  else if (args[0] == SYS_WAIT) {
    pid_t pid = args[1];
    f->eax = process_wait(pid);
  }
  else if (args[0] == SYS_CREATE) {
    const char* file = (char*)args[1];
    unsigned initial_size = args[2];
    f->eax = filesys_create(file, initial_size);
  }
  else if (args[0] == SYS_REMOVE) {
    const char* file = (char*)args[1];
    f->eax = filesys_remove(file);
  }
  else if (args[0] == SYS_OPEN) {
    const char* file = (char*)args[1];
    f->eax = open(file);
  }

}
