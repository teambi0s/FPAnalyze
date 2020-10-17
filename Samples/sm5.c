/*  Calling pointer in a struct  */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

typedef struct{
    void (*fun_ptr)();
    int size;
}name;

void win1()
{
    puts("win1");
}

name sample={&win1,20};

int main(){
    puts("Hey");
    int a;
    scanf("%d",&a);
    sample.fun_ptr();
    return 0;
}
