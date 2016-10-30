#ifndef _PAGE_H_

#define _PAGE_H_


#define VM_BIN 0
#define VM_FILE 1
#define VM_ANON 2

#include "lib/kernel/hash.h"

struct vm_entry{
  uint8_t type;// VM_BIN, VM_FILE, VM_ANON
  void *vaddr;//page number of vm_entry
  bool writable;//write is allowed if true
  
  bool is_loaded;//is loaded on physical memory
  struct file *file;
  
  /*in Memory Mapped File*/
  struct list_elem mmap_elem;//mmap list element

  size_t offset;//offset of file
  size_t read_bytes;//data size of virtual memory
  size_t zero_bytes;//rest size of virtual memory

  /*in Swapping*/
  size_t swap_slot;//swap slot

  /*in vm_entry*/
  struct hash_elem elem;//hash table element
};

void vm_init(struct hash *vm);

//static unsigned vm_hash_func(const struct hash_elem *e, void *aux);
//static bool vm_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux);


bool insert_vme(struct hash *vm, struct vm_entry *vme);
bool delete_vme(struct hash *vm, struct vm_entry *vme);

struct vm_entry *find_vme(void *vaddr);
void vm_destroy(struct hash *vm);
bool load_file(void *kaddr, struct vm_entry *vme);

#endif
