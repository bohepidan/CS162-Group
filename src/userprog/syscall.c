#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"

static void syscall_handler(struct intr_frame*);

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }

static void syscall_handler(struct intr_frame* f UNUSED) {
  uint32_t* args = ((uint32_t*)f->esp);

  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

  printf("System call number: %d\n", args[0]);

  switch(args[0]){
    case SYS_EXIT:
      f->eax = args[1];
      printf("%s: exit(%d)\n", thread_current()->pcb->process_name, args[1]);
      process_exit(args[1]);
      break;
    case SYS_PRACTICE:
      f->eax = args[1]+1;
      break;
    case SYS_HALT:
      shutdown_power_off();
      break;
    case SYS_EXEC: ;
      const char* cmd_line = (char*)args[1];
      f->eax = process_execute(cmd_line);
      break;
    case SYS_WAIT: ;
      pid_t pid = args[1];
      f->eax = process_wait(pid);
      break;
  }
  /*
  if (args[0] == SYS_EXIT) {
    f->eax = args[1];
    printf("%s: exit(%d)\n", thread_current()->pcb->process_name, args[1]);
    process_exit();
  }
  */
}
