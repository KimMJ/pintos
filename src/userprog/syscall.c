#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"   // thread_exit()
#include "devices/shutdown.h" // shutdown_power_off()
#include "filesys/filesys.h"  // filesys_create(), filesys_remove()
#include "userprog/process.h" // process_execute(), process_wait()


static void syscall_handler (struct intr_frame *f UNUSED);

void
syscall_init (void) 
{

  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
	void *esp = f->esp;
	int number = *(int *)(f->esp);
	int arg[4];						
	check_address(esp);
	printf("number is %d\n",number);
	switch(number){
	case SYS_HALT:
		printf("1\n");
		halt();
		break;
	case SYS_EXIT:
		get_argument(f->esp,arg,1);
		printf("2\n");
		exit(arg[0]);
		break;
  case SYS_CREATE :
		get_argument(f->esp, arg, 2);
		printf("3\n");
		f->eax = create(arg[0],arg[1]);
		break;
 	case SYS_REMOVE :
		get_argument(f->esp, arg ,1);
		printf("4\n");
		f->eax = remove(arg[0]);
		break;
	case SYS_EXEC:
		get_argument(f->esp,arg,1);
		printf("5\n");
		check_address((void*)arg[0]);
		f->eax = exec((const char *) arg[0]);
		break;	
	}	
  printf ("system call!\n");
  thread_exit ();
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
	printf("%s :exit(%d)",thread_name(), status);
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
  printf("exec\n");
  if (pid == TID_ERROR){
    return -1;
  }
  printf("exec1\n");
	t = get_child_process(pid);	
  sema_down(&t->load_sema);
  printf("exec2\n");
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
