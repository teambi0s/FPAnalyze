/*  Calling multiple pointers on bss  */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

void win1()
{
    puts("win1");
}

void win2()
{
    puts("win2");
}
void win3()
{
    puts("win3");
}

void win4()
{
    puts("win4");
}

void win5()
{
    puts("win5");
}

void win6()
{
    puts("win6");
}
void win7()
{
    puts("win7");
}

void win8()
{
    puts("win8");
}

void win9()
{
    puts("win9");
}

void win10()
{
    puts("win10");
}


void (*func_ptr1)() = &win1;
void (*func_ptr2)() = &win2;
void (*func_ptr3)() = &win3;
void (*func_ptr4)() = &win4;
void (*func_ptr5)() = &win5;

int main(){
    puts("Hey");
    int a;
    scanf("%d",&a);
    (*func_ptr1)();
    (*func_ptr2)();
    (*func_ptr3)();
    (*func_ptr4)();
    (*func_ptr5)();
    return 0;
}
