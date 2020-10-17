/*  Calling some pointers in an array  */

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


void (*func_arr[10])()={&win1,&win2,&win3,&win4,&win5,&win6,&win7,&win8,&win9,&win10};

int main(){
    puts("Hey");
    int a;
    scanf("%d",&a);
    for(int i=0;i<10;i++)
    {
        if(i%2==0)
            (*func_arr[i])();
    }
    return 0;
}
