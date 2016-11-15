#include "vm/swap.h"
#include "devices/block.h"
#include "lib/kernel/bitmap.h"
#include "vm/page.h"
#include "vm/frame.h"

//struct block *swap_block;
struct bitmap *swap_bitmap;
struct lock swap_lock;
//bitmap is one bit that handles one page

void swap_init (int count){
  swap_bitmap = bitmap_create(count); 
  lock_init(&swap_lock);
}

void swap_in (size_t used_index, void *kaddr){
  //printf("swap_in kaddr = %x\n",kaddr);
  struct block *swap_block = block_get_role(BLOCK_SWAP);
  lock_acquire(&swap_lock);
  

  int i = 0;
  for (i = 0  ; i < 8 ; i ++){
    //sector to block
    block_read(swap_block, used_index*8 + i, kaddr + i*BLOCK_SECTOR_SIZE);
  }

  bitmap_set_multiple(swap_bitmap, used_index, 1, false);
  //swap in from bitmap
  lock_release(&swap_lock);
}

size_t swap_out (void *kaddr){
  //printf("swap_out kaddr = %x\n",kaddr);
  struct block *swap_block = block_get_role(BLOCK_SWAP);
  lock_acquire(&swap_lock); 

  size_t index = bitmap_scan_and_flip(swap_bitmap, 0, 1, false);
  //used first fit

  int i = 0;
  for (i = 0 ; i < 8 ; i ++){
    //recording in swap partition 512 bytes
    //page size is 4096 bytes
    //buffer to sector
    //1 sector handles 512bytes
    block_write(swap_block, index * 8 + i, kaddr + i*BLOCK_SECTOR_SIZE);
  }
  lock_release(&swap_lock);
  //printf("index = %d\n",index);
  return index;//?
}
