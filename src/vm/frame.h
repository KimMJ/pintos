#ifndef _FRAME_H_
#define _FRAME_H_

#include "vm/page.h"
#include "threads/palloc.h"
#include "threads/thread.h"

void lru_list_init(void);
void add_page_to_lru_list(struct page* page);
void del_page_from_lru_list(struct page* page);

struct page* alloc_page(enum palloc_flags flags);
void free_page(void *kaddr);
void __free_page(struct page* page);

void* try_to_free_pages(enum palloc_flags flags);
struct page* find_page_with_kaddr(void *kaddr);
struct list_elem* get_next_lru_clock(void);
void free_all_pages(tid_t tid);

#endif
