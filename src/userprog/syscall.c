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
		f->eax = exec((const char *) arg[0]);
		break;
  case SYS_OPEN :
		get_argument(f->esp,arg,1);
		f->eax = open((const char *) arg[0]);
    break;
  case SYS_FILESIZE :
		get_argument(f->esp,arg,1);
		f->eax = filesize((int) arg[0]);
    break;
  case SYS_READ :
		get_argument(f->esp,arg,3);
		f->eax = read((int) arg[0], (void *) arg[1], (unsigned) arg[2]);
    break;
  case SYS_WRITE :
    get_argument(f->esp,arg,3);
		f->eax = write((int)arg[0], (const void *) arg[1], (unsigned) arg[2]);
    break;
  case SYS_SEEK :
		get_argument(f->esp,arg,2);
		seek((int) arg[0], (unsigned) arg[1]);
    break;
  case SYS_TELL :
		get_argument(f->esp,arg,1);
		f->eax = tell((int) arg[0]);
    break;
  case SYS_CLOSE :
		get_argument(f->esp,arg,1);
		close((int) arg[0]);
    break;
	}

 // thread_exit ();
}

void check_address(void *addr){
  if ((int *)addr>=0xc0000000 || (int *)addr <=0x8048000)
		exit(-1);
}

void get_argument(void *esp, int *arg, int count){
	int i;
  ASSERT(count >= 1 && count <= 4)
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
  printf("%s :exit(%d)\n",thread_name(), status);
	thread_exit();
}

int wait(tid_t tid){
	return process_wait(tid);
}	

tid_t exec(const char *cmd_line){
	tid_t pid;
	struct thread *t;
	/*
		명령어의 해당하는 프로그램을 수행하는 프로세스 생성
		생성된 자식 프로세스의 프로세스 디스크립터를 검색
		자식 프로세스의 프로그램이 탑재될 때까지 대기
		프로그램 탑재 실패시 -1 리턴
		프로그램 탑재 성공 시 자식 프로세스의 pid리턴
	*/
	pid = process_execute(cmd_line);
  if (pid == TID_ERROR){
    return -1;
  }
	t = get_child_process(pid);	
  sema_down(&t->load_sema);
  if (t->is_loaded)
		return t->tid;
	
  else return -1;
}

bool create (const char *file, unsigned initial_size){
	return filesys_create(file,initial_size);
}

bool remove (const char *file){
	return filesys_remove(file);
}

int open (const char *file){
  struct file* f = filesys_open(file);  
  struct thread * t = thread_current();
  if (f == NULL){
    return -1;
  }
  t->fdt[t->next_fd] = f;
  t->next_fd ++;
  return t->next_fd - 1;

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
  lock_acquire(&filesys_lock);

  if (fd == 0){
    while (i < size){
      ((char*)buffer)[i++] = input_getc();
    }
    return i;
  }
  
  f = process_get_file(fd);
  if (f == 0){
    return -1;
  }
  
  t =  file_read(f,buffer,size);

  lock_release(&filesys_lock);
  return t;
}
int write (int fd, void * buffer, unsigned size){
  struct file * f;
  off_t t = 0;
  
  lock_acquire(&filesys_lock);
  if (fd == 1){
    putbuf(buffer,size);
  }

  f = process_get_file(fd);
  if (f == 0){
    return -1;
  }

  t = file_write(fd, buffer, size);

  lock_release(&filesys_lock);
  return t;
}
void seek(int fd, unsigned position){
  struct file * f;
  off_t t = 0;
  ASSERT(fd > 1 && fd < 64);

  f = process_get_file(fd);
  if (f == 0){
    return -1;
  }

  file_seek(f, position);
}
unsigned tell (int fd){
  struct file * f;
  ASSERT(fd > 1 && fd < 64);

  f = process_get_file(fd);
  if (f == 0) return -1;

  return file_tell(f);
}
void close (int fd){
  process_close_file(fd);
}
