#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/syscall.h"
#include "vm/page.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t process_execute (const char *file_name) 
{
  char *fn_copy;
	char *save_ptr,*real_file_name;
  tid_t tid;
  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  
  fn_copy = palloc_get_page (PAL_ZERO);
  //fn_copy는 이 함수에서 해재되지 않고 start_process에서 해제합니다.
  if (fn_copy == NULL)
    return TID_ERROR;

  real_file_name = palloc_get_page(PAL_ZERO);
  //real_file_name은 파일 이름을 저장하기 위해 사용한 포인터입니다.
  if (real_file_name == NULL)
    return TID_ERROR;

  strlcpy (fn_copy, file_name, PGSIZE);
  strlcpy (real_file_name, file_name, PGSIZE);


	real_file_name = strtok_r(real_file_name," ",&save_ptr);
  //real_file_name은 실행될 함수의 이름

  /* Create a new thread to execute FILE_NAME. */
	tid = thread_create(real_file_name, PRI_DEFAULT, start_process, fn_copy);
  //쓰레드 이름은 real_file_name, start_process(fn_copy);
  if (tid == TID_ERROR) 
    palloc_free_page (fn_copy);
  //tid가 error이면 start_process가 실행되지 않으므로 fn_copy를 해제해 주어야 합니다.
  palloc_free_page(real_file_name);
  
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)//k->aux
{
  char *file_name=file_name_;
	char *token, *save_ptr;//parsing을 위한 포인터
	int count = 0;//argc를 위한 변수
  struct intr_frame if_;
  bool success; 
  char *parsed[strlen(file_name_)/2+1];
  /*파싱해서 로드 함수의 첫번째 인자로는 함수의 이름을 전달*/
  
  for (token = strtok_r(file_name, " ", &save_ptr); 
       token != NULL ; 
       token = strtok_r(NULL, " ", &save_ptr)){//while token != NULL
    parsed[count ++] = token;
	}//count는 argument의 갯수

  vm_init(&(thread_current()->vm));

  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;

  success =	load (file_name, &if_.eip, &if_.esp);
  //function call
  thread_current()->is_loaded = success;
  sema_up(&thread_current()->load_sema);
  //로드 완료했으니 부모는 일해도 좋습니다.
  
  /* If load failed, quit. */
  if (!success){
    palloc_free_page(file_name);
    thread_exit ();
  } 
  argument_stack(parsed, count, &if_.esp);
  //parsing된 문자를 넘기고 총 argument의 갯수, 스택포인터를 넘깁니다. 
  palloc_free_page(file_name);
  //prcoess_execute에서 선언하였던 fn_copy를 해제합니다.
  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
	//hex_dump(if_.esp, if_.esp, PHYS_BASE - if_.esp, true);//메모리 확인을 위한 함수
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}




/*스택에 데이터를 넣어주는 함수*/
void argument_stack(char **parse, int count, void **esp){
	int i,j;
  void * argv_position[count];
  //argv_position은 argument들의 포인터를 저장합니다.

  for (i = count-1 ; i >= 0 ; i --){
    for (j = strlen(parse[i]) ; j >= 0 ; j --){
      *esp -= 1;
      **(char**)esp = parse[i][j];
    }//parsing된 데이터를 스택에 넣어줍니다.
    argv_position[i] = *esp;//한 argument가 끝날 때마다 스택포인터를 저장합니다.
  }

	//스택 포인터 4로 나눠서 확인 후 word-align을 해줍니다.
	if ((int)*esp % 4 !=0){
		*esp -= ((int)*esp % 4)+4;
	}

	//argument들과 포인터 사이에 NULL을 넣는 부분
	*esp -= 4;
	*(int*)(*esp) = 0;
  
  //argument들의 포인터를 넣는 부분
  for (i = count ; i > 0 ; i -- ){
    *esp -= 4;
    *(char***)*esp = argv_position[i-1];
  }

	//(char**)argv를 넣는 부분.
	*esp -= 4;
	*(char****)(*esp) = (*esp + 4);
  //현재 스택포인터에서 4바이트 윗 부분이 argument[0]의 포인터입니다.

	//argc를 넣는 부분
	*esp -= 4;
	*(int*)(*esp) = count;

	//fake address를 넣습니다.(0)
	*esp -=4;
	*(int*)(*esp) = 0;
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */


int process_add_file (struct file *f){
  struct thread * t = thread_current(); 
  if (f == NULL){
    //NULL포인터가 들어오면 -1을 리턴합니다.
    return -1;
  }
  (t->fdt)[t->next_fd] = f;
  t->next_fd ++;
  //file descriptor table에 file을 추가시켜주고 next_fd를 늘려줍니다.
  return t->next_fd - 1;
}

struct file *process_get_file (int fd){
  struct thread *t = thread_current();
  if (fd >= t->next_fd || fd < 2){
    //유효하지 않은 값이 들어오면 null을 리턴합니다.
    return NULL;
  }
  return t->fdt[fd]; 
}

void process_close_file (int fd){
  struct thread * t = thread_current();
  if (fd <= 1 || t->next_fd <= fd) return;
  //유효하지 않은 값에 대해서는 아무 일도 하지 않습니다.
  if(t->fdt[fd] != NULL){
    //파일이 열려있을 경우 닫아주고 포인터를 null로 바꿉니다.
    file_close(t->fdt[fd]);
    t->fdt[fd] = NULL;
  }
}

struct thread *get_child_process(int pid){
  struct list_elem *elem;
  struct thread *t;
  for (elem = list_begin(&thread_current()->child_list) ; 
				elem != list_end(&thread_current()->child_list) ; 
				elem = list_next(elem)){
    if ((t=list_entry(elem,struct thread, child_elem))->tid == pid){
      //주어진 pid와 같은 쓰레드를 찾았을 경우 그 포인터를 넘겨줍니다.
      return t;
    }
  }	
  return NULL;//찾지 못하면 null을 넘겨줍니다.
}

void remove_child_process(struct thread *cp){
  //쓰레드를 제거합니다.
  list_remove(&cp->child_elem);
	palloc_free_page(cp);
}

int
process_wait (tid_t child_tid UNUSED) 
{
	struct thread* child_thread= get_child_process(child_tid);
	int status;
  
  if (child_thread == NULL){
    //tid를 가진 쓰레드가 없으면 -1를 리턴합니다.
    return -1;
  }

  sema_down(&child_thread->wait_sema);
  //자식 프로세스가 죽을때까지 기다립니다.
  //list_remove(&child_thread->child_elem);
  status = child_thread->exit_status;
  //자식 프로세스가 죽고 나면 상태를 기록합니다.
  remove_child_process(child_thread);	  
  //자식 프로세스를 제거합니다.
  return status;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  //printf("in process_exit tid is %d\n", thread_current()->tid);
  struct thread *cur = thread_current ();
  uint32_t *pd;
                                                                                                                  

  while (cur->next_fd > 2){
    process_close_file(cur->next_fd-1);
    cur->next_fd --;
  }

  palloc_free_page(cur->fdt);

  file_close(cur->run_file);
  
  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  //vm_entry를 해제하는 함수 삽입

  //destory vm_entry;
  munmap(CLOSE_ALL);
  //free_all_pages(cur->tid);
  //printf("??\n");
  /*
  int i = 0;
  for (i = 0 ; i < cur->next_mapid ; i ++){
    struct list_elem *e, *tmp;
    for (e = list_begin(&cur->mmap_list) ; 
         e != list_end(&cur->mmap_list ) ; ){
      struct mmap_file *m = list_entry(e, struct mmap_file, elem);
        printf("before\n");
      if (m->mapid == i){
        e = list_remove(e);
        do_munmap(m);
      }
    }
  }
*/
  vm_destroy(&cur->vm);

  pd = cur->pagedir;

  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
  
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;
  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();
  /* Open executable file. */
  lock_acquire(&filesys_lock); 
  //load중에 다른 프로세스에서 파일에 접근하지 못하도록 합니다.
  file = filesys_open (file_name);
  
  if (file == NULL) 
    {
      lock_release(&filesys_lock);
      //파일이 열리지 않았으면 lock을 해제합니다.
			printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  t->run_file = file; 
  file_deny_write(file);
  //불러들인 파일에 대해 쓰기를 거부합니다. 
  lock_release(&filesys_lock);
  //로드가 끝났으니 락을 풀어줍니다.

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  //printf("t->pagedir = %x, t->name = %s, t->tid = %d\n",t->pagedir,t->name,t->tid);
  /* We arrive here whether the //load is successful or not. */
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);
  //printf("filename =, ofs = %d, upage = %x, writable = %d\n", ofs, upage, writable);
  //file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
//      uint8_t *kpage = palloc_get_page (PAL_USER);
//      if (kpage == NULL)
//        return false;

      /* Load this page. */
//      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
//        {
//          palloc_free_page (kpage);
//          return false; 
//        }
//      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
//      if (!install_page (upage, kpage, writable)) 
//        {
//          palloc_free_page (kpage);
//          return false; 
//        }


      /*make vm_entry*/
      struct vm_entry * e = malloc(sizeof(struct vm_entry));

      if (e == NULL){
        return false;
      }
      
      memset(e, 0x00, sizeof(struct vm_entry));
      
      e->type = VM_BIN;
      e->offset = ofs;
      e->writable = writable;
      e->read_bytes = page_read_bytes;
      e->zero_bytes = page_zero_bytes;
      e->file = file;
      e->vaddr = upage;
      
      //printf("in load vaddr = %x, wrtable = %d\n",e->vaddr,writable);

      if (!insert_vme(&thread_current()->vm, e)){
        return false;
      }
      

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
      ofs += page_read_bytes;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  uint8_t *kpage;
  bool success = false;

  struct vm_entry *e = (struct vm_entry *)malloc(sizeof(struct vm_entry));
  if (e == NULL){
    return false;
  } 
  
  struct page *page = alloc_page(PAL_USER | PAL_ZERO);
  //kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  kpage = page->kaddr;

  if (kpage != NULL || page != NULL) 
    {
      page->vme = e;
      //printf("in setup_stack add_page = %x\n",page);
      //add_page_to_lru_list(page);
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;
      else{
        //palloc_free_page (kpage);
        free_page(page);
        free(e);
        return false;
      }
    }
  else {
    free_page(page);
  }

  memset(e,0x00, sizeof(struct vm_entry));
  e->type = VM_ANON;
  e->vaddr = (((uint8_t *)PHYS_BASE) - PGSIZE);
  e->writable = true;
  e->is_loaded = true;
  
  success = insert_vme(&thread_current()->vm, e);
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}

bool handle_mm_fault(struct vm_entry *vme){
  //printf("handle_mm_fault\n");
  struct page* page = alloc_page(PAL_USER | PAL_ZERO);
  //void *kaddr = palloc_get_page(PAL_USER | PAL_ZERO);
  void *kaddr = page->kaddr;
  //printf("mmfault = %x\n",vme->vaddr);
/*
  if (kaddr == NULL) {
    //palloc_free_page(kaddr);
    free_page(page);
    return false;
  }
*/
  page->vme = vme;
/*
  if (vme->is_loaded){
    return false;
  }
*/
  switch (vme->type){
    case VM_BIN :
      load_file(kaddr, vme);//load on physical memory
      if (install_page(vme->vaddr,kaddr, vme->writable)){
        vme->is_loaded = true;  
      }//mapping
      return vme->is_loaded;
    case VM_FILE : 
      load_file(kaddr, vme);
      if (install_page(vme->vaddr, kaddr, vme->writable)){
        vme->is_loaded = true;
      }
      return vme->is_loaded;
      //데이터 로드할 수 있도록 수정
    case VM_ANON:
      //printf("VM_ANON\n");
//      printf("swap_in vaddr = %x, tid = %d\n",vme->vaddr,thread_current()->tid);
      swap_in(vme->swap_slot, kaddr);
      install_page(vme->vaddr, kaddr, vme->writable);
      vme->is_loaded = true;
      return vme->is_loaded;
  }

  return false;
}

