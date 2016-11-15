#include "vm/frame.h"
#include "threads/synch.h"
#include "lib/kernel/list.h"
#include "threads/thread.h"

struct list lru_list;
struct list_elem *lru_clock;
struct lock lru_list_lock;


void lru_list_init(void){
  list_init(&lru_list);
  lru_clock = NULL;
  lock_init(&lru_list_lock);
}

void add_page_to_lru_list(struct page* page){//used lock
  //printf("add_page_to_lru_list\n");
  lock_acquire(&lru_list_lock);
  ASSERT(page);
  list_push_back(&lru_list, &page->lru);//lru_list에 page추가
  lock_release(&lru_list_lock);
}

void del_page_from_lru_list(struct page* page){//used lock
  //printf("del_page_from_lru_list\n");
  lock_acquire(&lru_list_lock);
  if (&page->lru == lru_clock){
    lru_clock = list_remove(lru_clock);//if it's lru_clock
  }else {
    list_remove(&page->lru);
  }
  lock_release(&lru_list_lock);
}

struct page* alloc_page(enum palloc_flags flags){
  void *kaddr = palloc_get_page(flags);//allocate page(virtual memory)
  while (kaddr == NULL){
    kaddr = try_to_free_pages(flags);
  }
  
  struct page *page = malloc(sizeof(struct page));
  if (page == NULL){
    return NULL;
  }
  ASSERT(page);
  //initalize struct page
  memset(page, 0, sizeof(struct page));
  page->kaddr = kaddr;//for kaddr
  //page->vme = find_vme(kaddr);//for vme
  page->thread = thread_current();//for thread
  //for lru?
  //add to lru_list
  add_page_to_lru_list(page);

  return page;
}

void free_page(void *kaddr){
  //printf("free_page\n");
  struct page *page;
  struct list_elem *elem,*tmp;
  lock_acquire(&lru_list_lock);


  for (elem = list_begin(&lru_list) ; 
       elem != list_end(&lru_list) ; ){
    tmp = list_next(elem);
    page = list_entry(elem, struct page, lru);
    if (page->kaddr == kaddr){
      //printf("page in find_page = %x\n",page);
      break;
    }
    elem = tmp;
  }

  if (page != NULL){
    __free_page(page);
  }
  lock_release(&lru_list_lock);
}

void __free_page(struct page* page){
  //printf("__free_page\n");
  del_page_from_lru_list(page);//delete from lru_list (for lru)
  //memory deallocate
  palloc_free_page(page->kaddr);//for kaddr
  pagedir_clear_page(page->thread->pagedir, page->vme->vaddr);

  //delete_vme(&page->thread->vm, page->vme);//for vme
  
  free(page);//for page itself
}

struct page* find_page_with_kaddr(void *kaddr){
  //printf("find_page_with_kaddr, lru_list %d\n", list_size(&lru_list));
  struct list_elem *elem;
  struct page *page;

  for (elem = list_begin(&lru_list) ; 
       elem != list_end(&lru_list) ; 
       elem = list_next(elem)){
    page = list_entry(elem, struct page, lru);
    if (page->kaddr == kaddr){
//    printf("page in find_page = %x\n",page);
//      printf("returned\n");
      return page;
    }
  }
//  printf("return null\n");
  return NULL;
}

struct list_elem* get_next_lru_clock(void){//get_next_victim_elem
  //printf("get_next_lru_clock, list size is %d\n",list_size(&lru_list));
  /*
  printf("get_next_lru_clock\n");
  //when lru_clock is deleted,(in try_to_get_page) it changed to next elem
  if (lru_clock == list_end(&lru_list)){
    lru_clock = NULL;
    return get_next_lru_clock();
  }else if (lru_clock != NULL){//if it is alright
    return lru_clock;
  }else if (list_empty(&lru_list)){//if lru_list is empty
    return NULL;
  }else {//lru_list is not empty but lru_clock is NULL
    lru_clock = list_begin(&lru_list);//go to first node
    return lru_clock;
  }
  */
  if (lru_clock == NULL || lru_clock == list_end(&lru_list)){
    if(list_empty(&lru_list)){
      //printf("hello1\n");
      return NULL;
    }else {
      //printf("hello2\n");
      return (lru_clock = list_begin(&lru_list));
    }
  }
  lru_clock = list_next(lru_clock);
  if(lru_clock == list_end(&lru_list)){
    //printf("hello3\n");
    return get_next_lru_clock();
  }else {
    //printf("hello4\n");
    return lru_clock;
  }
}

void* try_to_free_pages(enum palloc_flags flags){
  lock_acquire(&lru_list_lock);
  //printf("try_to_free_pages\n");
  //when lack of physical memory, handle_mm_fault call this function
  struct list_elem *elem = get_next_lru_clock();
  //find next victim elem
  if (elem == NULL) printf("what the fuck!\n");//not reached

  struct page *victim = list_entry(elem, struct page, lru);
  //find victim page with elem
  while(pagedir_is_accessed(victim->thread->pagedir, victim->vme->vaddr)){
    pagedir_set_accessed(victim->thread->pagedir, victim->vme->vaddr, false);
    elem = get_next_lru_clock();
    victim = list_entry(elem, struct page, lru);
  }

  bool dirty = pagedir_is_dirty(victim->thread->pagedir, victim->vme->vaddr);
  //printf("dirty? %d\n",dirty);
  //release from physical memory
  switch (victim->vme->type){
    case VM_BIN:
      //printf("swap out VM_BIN\n");
      if (dirty){
        victim->vme->swap_slot = swap_out(victim->kaddr);
        victim->vme->type = VM_ANON;
        //record in swap partition
        //pagedir_clear_page(victim->thread->pagedir, victim->vme->vaddr);
        //page deallocate
      }
      //for demand paging
      break;
    case VM_FILE:
      //printf("swap out VM_FILE\n");
      if (dirty){
        file_write_at(victim->vme->file, victim->kaddr, victim->vme->read_bytes, victim->vme->offset);
      }
      //pagedir_clear_page(victim->thread->pagedir, victim->vme->vaddr);

      //page deallocate
      break;
    case VM_ANON:
      //printf("swap out VM_ANON\n");
      victim->vme->swap_slot = swap_out(victim->kaddr);
      break;
    default:
      exit(-1234);//don't reach here
  }
  //pagedir_clear_page(victim->thread->pagedir, victim->vme->vaddr);
  victim->vme->is_loaded = false;

  lock_release(&lru_list_lock);
  __free_page(victim);
  return palloc_get_page(flags);
}
