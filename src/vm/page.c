#include "vm/page.h"
#include "lib/kernel/hash.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "filesys/file.h"
#include "userprog/syscall.h"

static unsigned vm_hash_func(const struct hash_elem *e, void *aux UNUSED){
  struct vm_entry *v = hash_entry(e, struct vm_entry, elem);
  return (unsigned)hash_int((int)v->vaddr); 
}

static bool vm_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED){
  struct vm_entry *v1 = hash_entry(a, struct vm_entry, elem);
  struct vm_entry *v2 = hash_entry(b, struct vm_entry, elem);

  if (v1->vaddr < v2->vaddr){
    return true;
  }

  return false;
}

static void vm_destory_func (struct hash_elem *hash_elem,void *aux UNUSED){
  //deallocate
  struct vm_entry *e = hash_entry(hash_elem, struct vm_entry, elem);
  if (e->is_loaded){
    palloc_free_page(pagedir_get_page(thread_current()->pagedir, e->vaddr));
    pagedir_clear_page(thread_current()->pagedir, e->vaddr);
  }
  free(e);
}

void vm_init(struct hash *vm){
  hash_init(vm, &vm_hash_func, &vm_less_func,0);
}

bool insert_vme(struct hash *vm, struct vm_entry *vme){
  if (hash_insert(vm, &vme->elem) == NULL){
    return true;
  }
  return false;
}

bool delete_vme(struct hash *vm, struct vm_entry *vme){
  if (hash_delete(vm, &vme->elem) == NULL){
    return false;
  }

  return true;
}

struct vm_entry *find_vme(void *vaddr){
  struct vm_entry e;
  e.vaddr = pg_round_down(vaddr);
  struct hash_elem * h;
  h =  hash_find(&thread_current()->vm, &e.elem);
  //printf("hello vaddr = %x\n",vaddr);
  if (h == NULL) {
    //printf("hi! \n");
    return NULL;
  }

  struct vm_entry *r = hash_entry(h, struct vm_entry, elem);

  return r;
}

void vm_destroy(struct hash *vm){
  //printf("destoryed!\n");
  // make destroy func
  hash_destroy(vm, vm_destory_func);
}

bool load_file (void *kaddr, struct vm_entry *vme){
  //locking
  //intr_disable();
  if(file_read_at(vme->file, kaddr, vme->read_bytes, vme->offset) != vme->read_bytes){
    return false;
  }
  
  if (vme->zero_bytes > 0){
    memset(vme->read_bytes + kaddr, 0x00, vme->zero_bytes);
  }
  //intr_enable();
  return true;
}
