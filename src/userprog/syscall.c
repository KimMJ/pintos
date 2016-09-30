#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"   // thread_exit()
#include "devices/shutdown.h" // shutdown_power_off()
#include "filesys/filesys.h"  // filesys_create(), filesys_remove()
#include "userprog/process.h" // process_execute(), process_wait()
#include "filesys/file.h"
#include "filesys/inode.h"

static void syscall_handler (struct intr_frame *f UNUSED);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&filesys_lock);
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
	void *esp = f->esp;
	int number = *(int *)(f->esp);
	int arg[4];						
	check_address(esp);
  switch(number){
	case SYS_HALT:
		halt();
		break;
	case SYS_EXIT:
		get_argument(f->esp,arg,1);
		exit(arg[0]);
		break;
  case SYS_CREATE :
		get_argument(f->esp, arg, 2);
		f->eax = create(arg[0],arg[1]);
		break;
 	case SYS_REMOVE :
		get_argument(f->esp, arg ,1);
		f->eax = remove(arg[0]);
		break;
	case SYS_EXEC:
		get_argument(f->esp,arg,1);
		f->eax = exec(arg[0]);
		break;
  case SYS_OPEN :
		get_argument(f->esp,arg,1);
		f->eax = open(arg[0]);
    break;
  case SYS_FILESIZE :
		get_argument(f->esp,arg,1);
		f->eax = filesize(arg[0]);
    break;
  case SYS_READ :
		get_argument(f->esp,arg,3);
		f->eax = read(arg[0],arg[1],arg[2]);
    break;
  case SYS_WRITE :
    get_argument(f->esp,arg,3);
		f->eax = write(arg[0],arg[1],arg[2]);
    break;
  case SYS_SEEK :
		get_argument(f->esp,arg,2);
		seek(arg[0],arg[1]);
    break;
  case SYS_TELL :
		get_argument(f->esp,arg,1);
		f->eax = tell(arg[0]);
    break;
  case SYS_CLOSE :
		get_argument(f->esp,arg,1);
		close(arg[0]);
    break;
  case SYS_WAIT : 
    get_argument(f->esp,arg,1);
    f->eax = wait(arg[0]);
    break;
	}

  //thread_exit ();
}

void check_address(void *addr){
  if (addr>=0xc0000000 || addr <=0x8048000)
		exit(-1);
}

void get_argument(void *esp, int *arg, int count){
	int i;
  ASSERT(count >= 1 && count <= 4);
	
  for (i = 0 ; i < count ; i ++){
    check_address(esp+4*i+4);
		arg[i] = *(int *)(esp + 4*i + 4);
	}

}

void halt(void){
  shutdown_power_off();
}

void exit(int status){
	thread_current()->exit_status = status;
  printf("%s: exit(%d)\n",thread_name(), status);
	thread_exit();
}

int wait(tid_t tid){
	return process_wait(tid);
}	

tid_t exec(const char *cmd_line){
	tid_t tid;
	struct thread *t;
	/*
		명령어의 해당하는 프로그램을 수행하는 프로세스 생성
		생성된 자식 프로세스의 프로세스 디스크립터를 검색
		자식 프로세스의 프로그램이 탑재될 때까지 대기
		프로그램 탑재 실패시 -1 리턴
		프로그램 탑재 성공 시 자식 프로세스의 pid리턴
	*/

  if (cmd_line == NULL) return -1;
  //printf("cmd_line = %s\n",cmd_line);
  tid = process_execute(cmd_line);
  if (tid == TID_ERROR){
    return -1;
  }
	
  t = get_child_process(tid);	
	ASSERT(t);
  sema_down(&t->load_sema);
  
  if (t->is_loaded)
		return t->tid;
	
  else return -1;
}

bool create (const char *file, unsigned initial_size){
	if (file == NULL) exit(-1);
  return filesys_create(file,initial_size);
}

bool remove (const char *file){
  if (file == NULL) return false;
	return filesys_remove(file);
}

int open (const char *file){
  struct file* f; 
  int result = -1;
  if (file == NULL) return -1;
  
  lock_acquire(&filesys_lock);
  f = filesys_open(file);
  result = process_add_file(f);
  lock_release(&filesys_lock);
  return result;
}

int filesize(int fd){
  struct file * f = process_get_file(fd);
  if (f == NULL) return -1;
  return file_length(f);
}

int read (int fd, void * buffer, unsigned size){
  struct file * f;
  off_t t = 0;
  int i = 0; 
  check_address(buffer);
  lock_acquire(&filesys_lock);
  if (fd == 1){
    lock_release(&filesys_lock);
    return -1;
  }else if (fd == 0){
    while (i < size){
      ((char*)buffer)[i++] = input_getc();
    }
    lock_release(&filesys_lock);
    return i;
  }else{
    f = process_get_file(fd);
    if (f == NULL){
      lock_release(&filesys_lock);
      return -1;
     }
    t =  file_read(f,buffer,(off_t)size);
  }
  lock_release(&filesys_lock);
  return t;
  
}
int write (int fd, void * buffer, unsigned size){
  struct file * f;
  off_t t = 0;
  check_address(buffer); 
  lock_acquire(&filesys_lock);
  
  if (fd == 0){
    lock_release(&filesys_lock);
    return -1;
  }else if (fd == 1){
    putbuf((char*)buffer,size);
    t = size;
    lock_release(&filesys_lock);
    return t;
  }else {
    f = process_get_file(fd);
    if (f == NULL){
      lock_release(&filesys_lock);
      return -1;
    }
    t = file_write(f,buffer,(off_t) size);
  }
  
  lock_release(&filesys_lock);
  return t;
}
void seek(int fd, unsigned position){
  struct file * f;
  off_t t = 0;
  f = process_get_file(fd);
  if (f != NULL) file_seek(f, position);
}
unsigned tell (int fd){
  struct file * f;

  f = process_get_file(fd);
  if (f != NULL) return file_tell(f);
  //exit(-1);
  return 0;
}
void close (int fd){
  process_close_file(fd);
}
