#ifndef _SWAP_H_
#define _SWAP_H_

#include "userprog/process.h"

void swap_init (int count);
void swap_in (size_t used_index, void *kaddr);
size_t swap_out (void *kaddr);

#endif
