#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "threads/malloc.h"
#include "filesys/inode.h"
#include "filesys/file.h"
#include "devices/input.h"
#include "kernel/console.h"
#include "devices/shutdown.h"

static void syscall_handler(struct intr_frame*);

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }

static struct file_d* get_file_d(int fd);
static struct file* get_file(int fd);

// Return the file_d structure of fd, or NULL if fd not exist.
static struct file_d* get_file_d(int fd){
  struct process* pcb = thread_current()->pcb;
  struct list_elem* e;
  struct file_d* file = NULL;
  lock_acquire(&pcb->ftlock);
  for(e = list_begin(&pcb->file_table); e != list_end(&pcb->file_table); e = list_next(e)){
    struct file_d* f = list_entry(e, struct file_d, elem);
    if(f->fd == fd){
      file = f;
      break;
    }
  }
  lock_release(&pcb->ftlock);
  return file;
}

// Return the file of fd, or NULL if fd not exist.
static struct file* get_file(int fd){
  struct file_d* f = get_file_d(fd);
  if(f == NULL) return NULL;
  return f->file;
}

/* Opens the file named file. Returns a nonnegative
 integer handle called a “file descriptor” (fd), or -1
  if the file could not be opened. */
int open(const char* name) {
  struct process* pcb = thread_current()->pcb;

  struct file* file = filesys_open(name);
  if (file == NULL) return -1;

  struct file_d* newfd = malloc(sizeof * newfd);
  if (newfd == NULL) return -1;

  newfd->file = file;
  if (list_empty(&pcb->file_table)) {
    newfd->fd = 2;
  }else{
    struct file_d* back = list_entry(list_back(&pcb->file_table), struct file_d, elem);
    newfd->fd = back->fd + 1;
  }
  lock_acquire(&pcb->ftlock);
  list_push_back(&pcb->file_table, &newfd->elem);
  lock_release(&pcb->ftlock);
  return newfd->fd;
}

/* Returns the size, in bytes, of the open file with file descriptor fd.
  or return -1 if fd not exist. */
int filesize(int fd){
  struct file* file = get_file(fd);
  if(file == NULL) return -1;

  return inode_length(file_get_inode(file));
}

/* Reads size bytes from the file open as fd into buffer.
  Returns the number of bytes actually read (0 at end of file), 
  or -1 if the file could not be read (due to a condition other than end of file).*/
int read(int fd, void* buffer, unsigned size){
  // Read from stdin.
  if(fd == STDIN_FILENO){
    for(uint8_t* c = buffer; c < (uint8_t*)buffer+size; c++){
      *c = input_getc();
    }
    return size;
  }

  struct file* file = get_file(fd);
  if(file == NULL) return -1;

  return file_read(file, buffer, size);
}

/* Writes size bytes from buffer to the open file with file descriptor fd.
  Returns the number of bytes actually written, or -1 if failed. */
int write(int fd, const void* buffer, unsigned size){
  if(fd == STDOUT_FILENO){
    putbuf(buffer, size);
    return size;
  }

  struct file* file = get_file(fd);
  if(file == NULL) return -1;

  return file_write(file, buffer, size);
}

/*Changes the next byte to be read or written in 
 open file fd to position, expressed in bytes from the beginning of the file. 
 Thus, a position of 0 is the file’s start. */
void seek(int fd, unsigned position){
  struct file* f = get_file(fd);
  if(f == NULL) return ;
  file_seek(f, position);
}

unsigned tell(int fd){
  struct file* f = get_file(fd);
  if(f == NULL) return 0;
  return file_tell(f);
}

void close(int fd){
  struct file_d* f = get_file_d(fd);
  struct process* pcb = thread_current()->pcb;
  if(f == NULL) return ;
  file_close(f->file);
  lock_acquire(&pcb->ftlock);
  list_remove(&f->elem);
  lock_release(&pcb->ftlock);
  free(f);
}

static void syscall_handler(struct intr_frame* f UNUSED) {
  uint32_t* args = ((uint32_t*)f->esp);

  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

  //printf("System call number: %d\n", args[0]);

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
  else if (args[0] == SYS_FILESIZE){
    int fd = args[1];
    f->eax = filesize(fd);
  }
  else if (args[0] == SYS_READ){
    int fd = args[1];
    void* buffer = (void*)args[2];
    unsigned size = args[3];
    f->eax = read(fd, buffer, size);
  }
  else if (args[0] == SYS_WRITE){
    int fd = args[1];
    const void* buffer = (void*)args[2];
    unsigned size = args[3];
    f->eax = write(fd, buffer, size);
  }
  else if (args[0] == SYS_SEEK){
    int fd = args[1];
    unsigned position = args[2];
    seek(fd, position);
  }
  else if (args[0] == SYS_TELL){
    int fd = args[1];
    f->eax = tell(fd);
  }
  else if (args[0] == SYS_CLOSE){
    int fd = args[1];
    close(fd);
  }

}
