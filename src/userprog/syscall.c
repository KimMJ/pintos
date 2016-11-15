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
#include "devices/input.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "vm/page.h"

static void syscall_handler (struct intr_frame *f UNUSED);
static struct lock mapid_lock;

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
//  printf("hry\n");
  //printf("number = %d, esp = %x\n",number,esp);
  check_address(esp, esp);
  switch(number){
	case SYS_HALT:
    halt();
    break;
	case SYS_EXIT:
    get_argument(f->esp,arg,1);
    //printf("%d\n",arg[0]);
    exit(arg[0]);
    break;
  case SYS_CREATE :
    get_argument(f->esp, arg, 2);
    check_valid_string((void *)arg[0],esp);
		f->eax = create((const char *)arg[0], (unsigned int) arg[1]);
    break;
 	case SYS_REMOVE :
    get_argument(f->esp, arg ,1);
    f->eax = remove((const char *)arg[0]);
    break;
	case SYS_EXEC:
    get_argument(f->esp,arg,1);
    check_valid_string((void *)arg[0], esp);
    f->eax = exec((const char *)arg[0]);
    break;
  case SYS_OPEN :
    get_argument(f->esp,arg,1);
    check_valid_string((void *)arg[0], esp);
    f->eax = open((const char *)arg[0]);
    break;
  case SYS_FILESIZE :
    get_argument(f->esp,arg,1);
    f->eax = filesize((int) arg[0]);
    break;
  case SYS_READ :
		get_argument(f->esp,arg,3);
    check_valid_buffer((void *)arg[1], (unsigned) arg[2], esp, true);
		f->eax = read((int) arg[0], (void *)arg[1], (unsigned) arg[2]);
    break;
  case SYS_WRITE :
    get_argument(f->esp,arg,3);
    check_valid_buffer((void *)arg[1], (unsigned) arg[2], esp, false);

		f->eax = write((int) arg[0], (void *)arg[1], (unsigned) arg[2]);
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
  case SYS_WAIT : 
    get_argument(f->esp,arg,1);
    f->eax = wait((tid_t) arg[0]);
    break;
  case SYS_MMAP :
    get_argument(f->esp, arg, 2);
    f->eax = mmap((int)arg[0], (void*) arg[1]);
    break;
  case SYS_MUNMAP : 
    get_argument(f->esp, arg, 2);
    munmap((int)arg[0]);
    break;
  default :
    printf("what the fuck\n");
    break;
	}
}

void check_user_stack(void *addr){
  if (addr >= (void *)0xc0000000 || addr <= (void *)0x08048000){
		exit(-1);
  }
}

struct vm_entry *check_address(void *addr, void *esp UNUSED){
  //printf("addr = %x,thread_name = %s\n",addr,thread_name());
  if (addr >= (void *)0xc0000000 || addr <= (void *)0x08048000){
    //printf("fucking pintos %x\n",addr);
		exit(-1);
  }
  struct vm_entry *e = find_vme(addr);
  
  if (e == NULL){
    //printf("null\n");
    exit(-1);
  }
  //printf("normal\n");
  return e;
}

void check_valid_buffer(void *buffer, unsigned size, void *esp UNUSED, bool to_write){
  int tmp_size = size;
  while (tmp_size >= 0) {
    //printf("buffer = %x\n",buffer);
    struct vm_entry *e = check_address(buffer + tmp_size,0);
    //printf("5\n");
    if (e == NULL) {
      exit(-1);
    }

    if (to_write && !e->writable){
      exit(-1);
    }
    tmp_size -= PGSIZE;
  }
}

void check_valid_string(const void *str, void *esp UNUSED){
  struct vm_entry *e = check_address((void *)str,0);
  //printf("1\n");
  if (e == NULL){
    exit(-1);
  }
}

void get_argument(void *esp, int *arg, int count){
	int i;
  ASSERT(count >= 1 && count <= 3);
  //count는 1~3까지 가질 수 있습니다.
	
  for (i = 0 ; i < count ; i ++){
    //check_address(esp+4*i+4);
    check_address(esp+4*i+4,0);
    //printf("2\n");
		arg[i] = *(int *)(esp + 4*i + 4);
	}

}

void halt(void){
  shutdown_power_off();
}

void exit(int status){
	thread_current()->exit_status = status;
  //종료상태를 저장합니다.
  printf("%s: exit(%d)\n",thread_name(), status);
	thread_exit();
}

int wait(tid_t tid){
	return process_wait(tid);
}	

tid_t exec(const char *cmd_line){
	tid_t tid;
	struct thread *t;

  if (cmd_line == NULL) return -1;
  //유효하지 않은 입력이 오면 종료합니다.
  tid = process_execute(cmd_line);
  //명령을 실행합니다.
  if (tid == TID_ERROR){
    return -1;
  }
	
  t = get_child_process(tid);
  //생성된 자식 프로세스의 포인터를 얻습니다.
	ASSERT(t);
  sema_down(&t->load_sema);
  //자식이 로드가 다 될때까지 기다립니다.

  if (t->is_loaded)
		return t->tid;
	
  else return -1;
}

bool create (const char *file, unsigned initial_size){
  if (file == NULL) exit(-1);
  //유효하지 않은 값이 들어오면 종료합니다.
  return filesys_create(file,initial_size);
}

bool remove (const char *file){
  if (file == NULL) return false;
  //유효하지 않은 값이 들어오면 종료합니다.
	return filesys_remove(file);
}

int open (const char *file){
  struct file* f; 
  int result = -1;
  if (file == NULL) return -1;
  //유요하지 않은 값이 들어오면 종료합니다.
  
  lock_acquire(&filesys_lock);
  //open중에 다른 프로세스에서의 접근을 막습니다.
  f = filesys_open(file);
  result = process_add_file(f);
  //프로세스의 fdt에 파일을 넣어줍니다.
  lock_release(&filesys_lock);
  //open이 끝나면 lock을 해제합니다.
  return result;
}

int filesize(int fd){
  struct file * f = process_get_file(fd);
  if (f == NULL) return -1;
  //fd에 대한 파일이 없으면 종료합니다.
  return file_length(f);
}

int read (int fd, void * buffer, unsigned size){
  struct file * f;
  off_t t = 0;
  unsigned int i = 0; 
  struct vm_entry *e = check_address(buffer,0);
  //printf("6\n");
  if (e == NULL){
    exit(-1);
  }
  //버퍼가 유효한 값인지 검사합니다.
  lock_acquire(&filesys_lock);
  //read중에 다른 프로세서에서 접근을 막습니다.
  /*
  if (fd == 1){
    lock_release(&filesys_lock);
    return -1;
  }else*/ 
    if (fd == 0){//stdin을 읽을 경우
    while (i < size){
      ((char*)buffer)[i++] = input_getc();
    }
    lock_release(&filesys_lock);
    return i;
  }else{//나머지의 경우
    f = process_get_file(fd);
    //fd가 유효하지 않으면 null을 반환합니다.
    if (f == NULL){
      lock_release(&filesys_lock);
      return -1;
     }
    t =  file_read(f,buffer,(off_t)size);
    //fd가 유효하면 버퍼로 읽어들입니다.
  }
  lock_release(&filesys_lock);
  return t;
  
}
int write (int fd, void * buffer, unsigned size){
  struct file * f;
  off_t t = 0;
  struct vm_entry *e = check_address(buffer,0); 
  //버퍼가 유효한지 검사합니다.
  if (e == NULL){
    exit(-1);
  }
  //printf("e->vaddr = %x\n",e->vaddr); 
  lock_acquire(&filesys_lock);
  /*
  if (fd == 0){
    lock_release(&filesys_lock);
    return -1;
  }else */
    if (fd == 1){//stdout에 쓸 경우
    putbuf((char*)buffer,size);
    t = size;
    lock_release(&filesys_lock);
    return t;
  }else {//나머지의 경우
    f = process_get_file(fd);
    //fd가 유효하지 않으면 null을 반환합니다.
    if (f == NULL){
      lock_release(&filesys_lock);
      return -1;
    }
    t = file_write(f,buffer,(off_t) size);
    //fd가 유효하면 버퍼로 기록합니다.
  }
  lock_release(&filesys_lock);
  return t;
}
void seek(int fd, unsigned position){
  struct file * f;
  f = process_get_file(fd);
  //유효하지 않은 fd는 null을 리턴합니다.
  if (f != NULL) file_seek(f, position);
}
unsigned tell (int fd){
  struct file * f;
  f = process_get_file(fd);
  //유효하지 않은 fd는 null을 리턴합니다.
  if (f != NULL) return file_tell(f);
  return 0;
}
void close (int fd){
  process_close_file(fd);
  //fd가 유효하지 않으면 아무일도 하지 않습니다.
}


//Memory Mapped File
static mapid_t allocate_mapid (void) {
  //printf("int allocate_mapid\n");
  static mapid_t next_mapid = 1;
  mapid_t mapid;

  //printf("here4\n");
  //lock_acquire (&mapid_lock);
  mapid = next_mapid++;
  //lock_release (&mapid_lock);
  

  return mapid;
}

mapid_t mmap(int fd, void *addr){
  //printf("mmap\n");
  //이미 한 addr에 대해 mmap할 때, over-code, over-data, over-stk 
  //printf("")
  if (pg_ofs(addr) != 0 || addr == NULL) return -1;
  mapid_t mapid=0;


  struct file *file = file_reopen(process_get_file(fd));


  if (file != NULL){
    //allocate mapid
    int read_bytes = 0, zero_bytes =0;
    off_t ofs = 0;
    //file 에 대한 정보들 읽자.
    int total_size = file_length(file);

    read_bytes = (uint32_t)total_size;
    mapid = allocate_mapid();
    
    //make mmap_file and initialize
    //해당 파일에 대한 mmap_file구조체 생성
    struct mmap_file *m = malloc(sizeof(struct mmap_file)); 
    if (m == NULL){
      return -1;
    }
    memset(m, 0, sizeof *m);

    m->mapid = mapid;
    m->file = file;
    list_init(&m->vme_list);
    list_push_back(&thread_current()->mmap_list, &m->elem);
    
    //make vm_entry and initialize
    //파일에 대한 vm_entry들 생성하여 vme_list에 넣을 것.
    while (read_bytes > 0 || zero_bytes > 0){
      if (find_vme(addr)) return -1;
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      struct vm_entry * e = malloc(sizeof(struct vm_entry));
    
      memset(e, 0, sizeof(struct vm_entry));

      if (e == NULL){
        return -1;
      }
      //file에 대한 정보는???
      e->type = VM_FILE;
      e->offset = ofs;
      e->writable = true;
      e->read_bytes = page_read_bytes;
      e->zero_bytes = page_zero_bytes;
      e->file = file;
      e->vaddr = addr;

      list_push_back(&m->vme_list, &e->mmap_elem);
      insert_vme(&thread_current()->vm, e);

      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      addr += PGSIZE;
      ofs += page_read_bytes;
    }
    return mapid;
  }
  return -1;
}

void munmap(mapid_t mapping){  
//  printf("munmap\n");
  //mmap_list에서 mapping에 해당하는 모든 vm_entry를 해제
  struct thread *cur = thread_current();
  struct list_elem *e, *tmp;
  for (e = list_begin(&cur->mmap_list) ;
       e != list_end(&cur->mmap_list) ; ){
    //tmp = list_next(e);
    struct mmap_file *m = list_entry(e, struct mmap_file, elem);
    ASSERT(m != NULL);
    if (m->mapid == mapping || mapping == CLOSE_ALL ){
      e = list_remove(e);
      //printf("go to munmap\n");
      do_munmap(m);
    }else {
      e = list_next(e);
    }
    //e = tmp;
  }
}

void do_munmap(struct mmap_file *mmap_file){
//  printf("do_munmap\n");
  //mmap_file의 vme_list를 삭제하는 과정.
  //vme_list의 vme들은 thread와 공유중
  
  struct list_elem *e, *tmp;
  //ASSERT(!list_empty(&mmap_file->vme_list));
  for (e = list_begin(&mmap_file->vme_list) ;
       e != list_end(&mmap_file->vme_list) ; ){
    tmp = list_next(e);
    void *pd = thread_current()->pagedir;
    struct vm_entry *vme = list_entry(e, struct vm_entry, mmap_elem);

    if (vme->is_loaded && pagedir_is_dirty(pd,vme->vaddr)){//if dirty
      file_write_at(mmap_file->file, vme->vaddr, vme->read_bytes, vme->offset);
      //vme->vaddr을 가지고 page를 얻어서 free_page할 것.
      struct page* page;
      //page = find_page_with_kaddr(pagedir_get_page(thread_current()->pagedir, vme->vaddr));
      
      //free_page(page);
      free_page(pagedir_get_page(thread_current()->pagedir, vme->vaddr));
      pagedir_clear_page(pd, vme->vaddr);
    }
    vme->is_loaded = false;
    e = tmp;
    delete_vme(&thread_current()->vm,vme);
  }
  //file_close(mmap_file->file);
  //list_remove(&mmap_file->elem);//for thread
  free(mmap_file);
}
