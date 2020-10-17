/* FPAnalyze
  
 * Created By - 3agl3 and Cyb0rG
 
 * The tool is currently a very basic implementation of a function pointer finder utility.
 
 * Finding valid function pointers in the binary can be useful in the final stages of exploitation 
   where we have a write-what-where primitive.
 
 * The tool works on the method of tainting memory regions containing function pointers.
 
 * Segmentation faults hence triggered are handled and function pointers are printed as well 
   as replaced back to ensure smooth execution thereafter.
 */


/* 
 * Including all necessary header files
 */

#define _GNU_SOURCE
# define REG REG_RIP
#include <stdio.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <distorm3/distorm.h> 
#include <stdlib.h>
#include <stdbool.h>
#include <getopt.h>
#include <dlfcn.h>
#include "colors.h"

/* Defining common datatypes being used */

typedef unsigned long long ull;
typedef long long ll;
typedef unsigned long ul;


#define MAX_INSTRUCTIONS 64

/* Using a foreign disassembler API to handle segmentation fault in various linux environments */

_DecodeResult res;
_OffsetType offset = 0;
_DecodedInst decodedInstructions[MAX_INSTRUCTIONS];
unsigned int decodedInstructionsCount = 0;
_DecodeType dt = Decode64Bits;




/* Maintaining separate arrays to store the function ,function pointer and an array to store 
 * names of all functions being triggered
 */

ull pointer_arr[800];
ull * addr_arr[800];
ull *arr_pointer = pointer_arr;
ull *arr_addr = (ull *)addr_arr;
unsigned int idx = 0;
ll strtoll(const char *nptr, char **endptr, int base);
int pagesize = 0;

/* Logical flags to detect rw and rx regions */

int isfirstrw=1;
int isfirstrx=1;
int isfirstlibc=1;
int isfirstbinary=1;

/* addresses of binary and libc */

ull binary_rostart=0;
ull binary_roend=0;
ull  binary_rxstart=0;
ull  binary_rxend=0;
ull *binary_rwstart=0;
ull *binary_rwend=0;

ull libc_rxstart=0;
ull libc_rxend=0;
ull *libc_rwstart=0;
ull *libc_rwend=0;
ull libc_rostart=0;
ull libc_roend=0;


ull stack_start=0;
ull stack_end=0;

/* Function to convert int to string , implementation of itoa  */

char *reverse(char *buffer, int i, int j);
void swap(char *x, char *y);

void swap(char *x, char *y) {
    char t = *x; *x = *y; *y = t;
}

char* reverse(char *buffer, int i, int j)
{
    while (i < j)
        swap(&buffer[i++], &buffer[j--]);

    return buffer;
}

char* itoa(int value, char* buffer, int base)
{
    if (base < 2 || base > 32)
        return buffer;
    int n =value;
    if(value < 0)
        n = value * -1;
    int i = 0;
    while (n)
    {
        int r = n % base;
        if (r >= 10)
            buffer[i++] = 65 + (r - 10);
        else
            buffer[i++] = 48 + r;

        n = n / base;
    }
    if (i == 0)
        buffer[i++] = '0';
    if (value < 0 && base == 10)
        buffer[i++] = '-';

    buffer[i] = '\0'; // null terminate string

    return reverse(buffer, 0, i - 1);
}

// End of int to str conversion functions

/* Function to tokenize instruction pointer to get the required register for handling 
 * segmentation fault 
 * Initializing a 2D array to store the parsed tokens
 */

char arr[10][20]={0};

char * splitter(char * op, char position){
    int j=0;
    int k=0;
    int ret=0;
    for(int i=0;i<strlen(op);i++){
        if(op[i]==' '){
            if(op[i+1]==' '){
                continue;
            }
            else{
                arr[j][k]='\0';
                k=0;
                j++;
            }
        }
        if((op[i] >= 'A' && op[i]<= 'Z') || (op[i]>='a' && op[i]<='z') || op[i]=='+' || op[i]=='['){
            if(op[i]=='+')
                arr[j][k]=' ';
            else if(op[i]=='['){
                k--;
                ret=j;
            }
            else
                arr[j][k]=op[i];
            k++;
        }
    }
    if(position=='l')
        return arr[ret];
    return arr[0];
}

/* Function to compare registers to handle segfaults in various environments
 *
 */ 

bool regcmp(char * reg, char* reg2,int n){
    for(int i=0;i<n;i++){
        if(reg[i]!=reg2[i])
            return false;
    }
    return true;
}

/* 
 * Function to parse and simultaenously taint bss to detect function pointers
 * 
 */

void parse_bss(ull * rw_start, ull * rw_end, ull rx_start, ull rx_end)
{
    unsigned  int offset = 0;
    while( (offset) < (rw_end - rw_start) )
    {
        ull value = *(rw_start+offset);
        ull* address = (ull*)rw_start+offset;
        if((value <= (ul)(rx_end)) && (value >= (ul)rx_start))
        {
            *arr_pointer = value;
            *arr_addr = (ull)address;
            arr_pointer = arr_pointer + 1;
            arr_addr = arr_addr + 1;
            *address = idx;
            idx++;
        }
        offset++;
    }
}

/* Handle segfault
 
 * This function is responsible for handling segfaults and printing function pointers.

 * The current version of this tool implements function addresss from base address of the
   memory region where it belongs to.

 * After printing function pointers , it replaces the addresses with their respective 
   original values.

 * The function needs additional check for running on foreign ubuntu environments , which is
   the basis for implementing the outer if else statements.

 * The appropriate register values are calculated for properly handling segfaults in the else
   part.

 * The else part also implements printing caller function names using dladdr function

 * The if part needs to be updated to print function names. 

 */

void handle_segfault(int signo, siginfo_t *Info, ucontext_t* context)
{
    ull index;
    ull offset = (ull)context->uc_mcontext.gregs[REG];
    ll* RIP = (ll *)offset;
    write(0,"\x1B[31m* \x1B[0m",strlen("\x1B[31m* \x1B[0m"));
    if(offset < idx ){
        ull *local_stack = (ull*)__builtin_frame_address(1);
        local_stack = local_stack-1;
        ull func_ptr = (ull)addr_arr[offset];
        ull local_ret=0;
        ull* real_ret=0;
        unsigned int i=0;
        while(1){
            /* Checking if return value of __builtin_frame_address(1) is a stack address */
            if((ull)local_stack >= stack_start && (ull)local_stack<= stack_end){
                /* If so , store the value at the stack address into local_ret */
                local_ret = *local_stack;
                /* If local_ret is a libc executable address or binary executable address */
                if((local_ret >= libc_rxstart && local_ret <= libc_rxend ) ||
                    (local_ret >= binary_rxstart && local_ret <= binary_rxend)){
                    /* We have found the actual return address , hence copy to an appropriate variable 
                       and break out 
                     */
                    real_ret = (ull*)local_ret;
                    break;
                }
                /* Decrement the local_stack var by 8 and keep running in the loop to check for valid 
                   return address 
                 */
                local_stack = local_stack-1;
                i++;
            }
            else{
                break;
            }
        }
        /* If function pointer is in code segment */
        int bin_func_ptr=0;
        if(func_ptr < (ull)(binary_rwend) && func_ptr >= (ull)binary_rwstart){
            index = (ull)(func_ptr-(binary_rostart));
            bin_func_ptr=1;
        }
        /* If function pointer is in libc segment */
        else{
            index = (ull)(func_ptr-(libc_rostart));
        }
        write(0,"0x",2);
        char buffer[50]={0};
        itoa(index,buffer,16);
        write(0,buffer,strlen(buffer));
        if(bin_func_ptr)
            write(0," (binary) ",strlen(" (binary) "));
        else
            write(0," (libc) ",strlen(" (libc) "));
        ull local_off=0;
        char b[50];
        /* Calculate offset of instruction from libc base and binary base respectively */
        uint32_t bin_instruction = 0;
        if(real_ret){
            if((ull)real_ret >= libc_rxstart && (ull)real_ret <= libc_rxend ){
                local_off = (ull)(real_ret - (libc_rostart/8));
            }
            else{
                local_off = (ull)(real_ret -  (binary_rostart/8));
                bin_instruction = 1;
            }
            if(bin_instruction)
                write(0,": Instruction Offset 0x",strlen(": Instruction Offset 0x"));
            else
                write(0,": Instruction Offset 0x",strlen(": Instruction Offset 0x"));
            char buf[50]={0};
            itoa(local_off,buf,16);
            write(0,buf,strlen(buf));
        }
        if(bin_instruction && real_ret){
            write(0," (binary) ",strlen("   (binary) "));
        }
        else if(real_ret){
            write(0," (libc) ",8);
        }
        write(0,"\n",1);
        context->uc_mcontext.gregs[REG]= pointer_arr[offset];
        *addr_arr[offset] = pointer_arr[offset];
    }
    else 
    {
        if(RIP > (ll *)binary_rxstart)
        {
            char* buf = (char *)RIP;
            // Decode the buffer at given offset (virtual address).
            res = distorm_decode(offset, (const unsigned char*)buf, sizeof(buf), dt, decodedInstructions, MAX_INSTRUCTIONS,&decodedInstructionsCount);
            if (res == DECRES_INPUTERR)
            {
                return;
            }
            char* parsed = (char *)decodedInstructions[0].operands.p;
            char * first = splitter(parsed,'l');
            char * reg = splitter(first,'f');
            if(regcmp(reg,"rax",strlen(reg)) || regcmp(reg,"RAX",strlen(reg)))
            {
                offset = context->uc_mcontext.gregs[REG_RAX];
                if(offset <= idx){
                    context->uc_mcontext.gregs[REG_RAX] = pointer_arr[offset];
                }
            }
            if(regcmp(reg,"rbx",strlen(reg)) || regcmp(reg,"RBX",strlen(reg)))
            {
                offset = context->uc_mcontext.gregs[REG_RBX];
                if(offset <= idx){
                    context->uc_mcontext.gregs[REG_RBX] = pointer_arr[offset];
                }
            }
            if(regcmp(reg,"rcx",strlen(reg)) || regcmp(reg,"RCX",strlen(reg)))
            {
                offset = context->uc_mcontext.gregs[REG_RCX];
                if(offset <= idx){
                    context->uc_mcontext.gregs[REG_RCX] = pointer_arr[offset];
                }
            }
            if(regcmp(reg,"rsi",strlen(reg)) || regcmp(reg,"RSI",strlen(reg)))
            {
                offset = context->uc_mcontext.gregs[REG_RSI];
                if(offset <= idx){
                    context->uc_mcontext.gregs[REG_RSI] = pointer_arr[offset];
                }
            }
            if(regcmp(reg,"rdi",strlen(reg)) || regcmp(reg,"RDI",strlen(reg)))
            {
                offset = context->uc_mcontext.gregs[REG_RDI];
                if(offset <= idx){
                    context->uc_mcontext.gregs[REG_RDI] = pointer_arr[offset];
                }
            }
            if(regcmp(reg,"rdx",strlen(reg)) || regcmp(reg,"RDX",strlen(reg)))
            {
                offset = context->uc_mcontext.gregs[REG_RDX];
                if(offset <= idx){
                    context->uc_mcontext.gregs[REG_RDX] = pointer_arr[offset];
                }
            }
            if(regcmp(reg,"rbp",strlen(reg)) || regcmp(reg,"RBP",strlen(reg)))
            {
                offset = context->uc_mcontext.gregs[REG_RBP];
                if(offset <= idx){
                    context->uc_mcontext.gregs[REG_RBP] = pointer_arr[offset];
                }
            }
            if(regcmp(reg,"rsp",strlen(reg)) || regcmp(reg,"RSP",strlen(reg)))
            {
                offset = context->uc_mcontext.gregs[REG_RSP];
                if(offset <= idx){
                    context->uc_mcontext.gregs[REG_RSP] = pointer_arr[offset];
                }
            }
            if(regcmp(reg,"r8",strlen(reg)) || regcmp(reg,"R8",strlen(reg)))
            {
                offset = context->uc_mcontext.gregs[REG_R8];
                if(offset <= idx){
                    context->uc_mcontext.gregs[REG_R8] = pointer_arr[offset];
                }
            }
            if(regcmp(reg,"r9",strlen(reg)) || regcmp(reg,"R9",strlen(reg)))
            {
                offset = context->uc_mcontext.gregs[REG_R9];
                if(offset <= idx){
                    context->uc_mcontext.gregs[REG_R9] = pointer_arr[offset];
                }
            }
            if(regcmp(reg,"r10",strlen(reg)) || regcmp(reg,"R10",strlen(reg)))               
            {
                offset = context->uc_mcontext.gregs[REG_R10];
                if(offset <= idx){
                    context->uc_mcontext.gregs[REG_R10] = pointer_arr[offset];
                }
            }
            if(regcmp(reg,"r11",strlen(reg)) || regcmp(reg,"R11",strlen(reg)))
            {
                offset = context->uc_mcontext.gregs[REG_R11];
                if(offset <= idx){
                    context->uc_mcontext.gregs[REG_R11] = pointer_arr[offset];
                }
            }
            if(regcmp(reg,"r12",strlen(reg)) || regcmp(reg,"R12",strlen(reg)))
            {
                offset = context->uc_mcontext.gregs[REG_R12];
                if(offset <= idx){
                    context->uc_mcontext.gregs[REG_R12] = pointer_arr[offset];
                }
            }
            if(regcmp(reg,"r13",strlen(reg)) || regcmp(reg,"R13",strlen(reg)))
            {
                offset = context->uc_mcontext.gregs[REG_R13];
                if(offset <= idx){
                    context->uc_mcontext.gregs[REG_R13] = pointer_arr[offset];
                }
            }
            if(regcmp(reg,"r14",strlen(reg)) || regcmp(reg,"R14",strlen(reg)))
            {
                offset = context->uc_mcontext.gregs[REG_R14];
                if(offset <= idx){
                    context->uc_mcontext.gregs[REG_R14] = pointer_arr[offset];
                }
            }
            if(regcmp(reg,"r15",strlen(reg)) || regcmp(reg,"R15",strlen(reg)))               
            {
                offset = context->uc_mcontext.gregs[REG_R15];
                if(offset <= idx){
                    context->uc_mcontext.gregs[REG_R15] = pointer_arr[offset];
                }
            }
            long unsigned int func_ptr = (ul)addr_arr[offset];
            int bin_func_ptr=0;
            if(func_ptr < (ull)(binary_rwend) && func_ptr >= (ull)binary_rwstart){
                bin_func_ptr=1;
                index = (ull)(func_ptr-(binary_rostart));
            }
            else{
                index = (ull)(func_ptr-(libc_rostart));
            }
            write(0,"0x",2);
            char buffer[50];
            itoa(index,buffer,16);
            write(0,buffer,strlen(buffer));
            if(bin_func_ptr)
                write(0," (binary) ",strlen(" (binary) "));
            else
                write(0," (libc) ",strlen(" (libc) "));
            ull local_off=0; 
            unsigned int bin_instruction = 0;
            if(RIP){
                if((ull)RIP >= libc_rxstart && (ull)RIP <= libc_rxend ){
                    local_off = (ull)(RIP - (libc_rostart/8));
                }
                else{
                    local_off = (ull)(RIP - (binary_rostart/8));
                    bin_instruction = 1;
                }
                if(bin_instruction)
                    write(0,"   : Instruction Offset 0x",strlen(" : Instruction Offset 0x"));
                else
                    write(0,": Instruction Offset 0x",strlen(" : Instruction Offset 0x"));
                char buf[50];
                itoa(local_off,buf,16);
                write(0,buf,strlen(buf));
            }
            if(bin_instruction && RIP){
                write(0," (binary) ",10);
            }
            else if(RIP){
                write(0," (libc) ",8);
            }
            write(0,"\n",1);
            *addr_arr[offset] = pointer_arr[offset];
        }
    }
    return;
}

/* Hooking _init function to run the tool

 * This function parses memory maps to identify memory addresses for validating function pointers.

 * Parsing happens in both libc and the binary bss segments.

*/
void _init()
{
    char FPAnalyze[] = "FPAnalyze                                 \n\n";
    printf(BBLU);
    printf(FPAnalyze);
    printf(BYEL);
    char banner[]=
        "The offsets are printed according to the following: \n\n";
    printf(banner);
    char instructions[] = 
        " ->   Only offsets from Base are printed in case tool is not able to find the instruction.\n\n"
        " ->   If instruction is also found, then it's offset from base and the offset of function \n"
        "      pointer are printed together separated by a ':' .\n\n"
        " ->   The paranthesis specify if the detected function pointer was from libc/binary base  \n\n\n";
    printf(BGRN);
    printf(instructions);
    printf(reset);
    signal(SIGSEGV,(void *)handle_segfault);
    pagesize = getpagesize();
    int i=0;

    char* filename = "/proc/self/maps";
    char data[50][400] = {0};
    FILE* map = fopen(filename,"r");
    if(map==NULL)
    {
        printf("\n fopen() Error!!!\n");
        return;
    }
    while(fscanf(map,"%200[^\n]",data[i]) != EOF)
    {
        i++;
        fgetc(map);
    }
    char str[400];
    char * array[6];
    int index=0;

    for(int k=0;k<i;k++)
    {
        memset(str,'\x00',400);
        strcpy(str,data[k]);
        char *ptr = strtok(str," ");
        index = 0;
        char ** endptr;
        while(ptr != NULL)
        {
            array[index++]= ptr;
            ptr = strtok(NULL, " ");
        }
        char addrs[50] ={0};
        strcpy(addrs,array[0]);
        strncat(addrs," ",2);
        char addrs_cpy[50];
        char addrs_cpy2[50];
        strncpy(addrs_cpy,addrs,50);
        strncpy(addrs_cpy2,addrs,50);

        /* 

         * Capture the base address of binary with the help of isfirstbinary flag.

         * Set the flag to 0 and get the base addresses.
         
         * Similarly , check for "libc" in the memory maps and get the base address of 
           libc with the isfirstlibc flag.
         
         * To get addresses of writeable memory segments , check for "rw-p" in the memory maps 
           and appropriately get the required base addresses of libc and binary bss.
         
         * We also store the base address of stack for later determining the offset of the instruction
           of the caller function
		 
		 */ 
        if(isfirstbinary)
        {
            isfirstbinary=0;
            binary_rostart = (ull)strtoll(strtok(addrs_cpy,"-"),endptr,16);
            binary_roend = (ull)strtoll(strtok(NULL," "),endptr,16);
        }
        if(isfirstlibc && strstr(array[5],"libc")){
            isfirstlibc=0;
            libc_rostart= (ull)strtoll(strtok(addrs_cpy2,"-"),endptr,16);
            libc_roend= (ull)strtoll(strtok(NULL," "),endptr,16);
        }
        if(strncmp(array[1],"rw-p",4) == 0){
            if(isfirstrw){
                isfirstrw=0;
                binary_rwstart= (ull *)strtoll(strtok(addrs,"-"),endptr,16);
                binary_rwend= (ull *)strtoll(strtok(NULL," "),endptr,16);
            }
            else{
                if(strstr(array[5],"libc")){
                    libc_rwstart = (ull*)strtoll(strtok(addrs,"-"),endptr,16);
                    libc_rwend = (ull*)strtoll(strtok(NULL," "),endptr,16);
                }
            }
        }
        if(strncmp(array[1],"r-xp",4) == 0){
            if(isfirstrx && isfirstbinary){
                isfirstrx=0;
                isfirstbinary=0;
                binary_rxstart= (ull)strtoll(strtok(addrs,"-"),endptr,16);
                binary_rxend= (ull)strtoll(strtok(NULL," "),endptr,16);
                binary_rostart = binary_rxstart;
                binary_roend= binary_rxend;
            }
            else if(isfirstrx && !isfirstbinary)
            {
                isfirstrx=0;
                binary_rxstart= (ull)strtoll(strtok(addrs,"-"),endptr,16);
                binary_rxend= (ull)strtoll(strtok(NULL," "),endptr,16);
            }
            else{
                if(strstr(array[5],"libc")){
                    libc_rxstart = (ull)strtoll(strtok(addrs,"-"),endptr,16);
                    libc_rxend = (ull)strtoll(strtok(NULL," "),endptr,16);
                }
            }
        }
        if(strstr(array[5],"stack"))
        {
            stack_start = (ull)strtoll(strtok(addrs,"-"),endptr,16);
            stack_end = (ull)strtoll(strtok(NULL," "),endptr,16);
        }
    }
    // Finding the pointers on binary bss
    parse_bss(binary_rwstart,binary_rwend,binary_rxstart,binary_rxend);

    // Finding the pointers on libc bss
    parse_bss(libc_rwstart,libc_rwend,libc_rxstart,libc_rxend);
}
