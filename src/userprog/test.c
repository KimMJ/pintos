#include <stdlib.h>
#include <stdio.h>
#include <string.h>


int main(void){
  void ** a;
  void * b;
  int **a;
  *(int*)a=1;
  *(char *******)(*a) = b;
  *(void **)(*a) = b;
	return 0;
}
