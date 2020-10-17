/*  Calling single pointer on bss  */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

void win1()
{
    puts("win1");
}

void (*func_ptr1)() = &win1;

int main(){
    puts("Hey");
    int a;
    scanf("%d",&a);
    (*func_ptr1)();
    return 0;
}
