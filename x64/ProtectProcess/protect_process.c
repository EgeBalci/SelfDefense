/*
 
# Win32 - Protect Process Shellcode
# Date: [17.02.2017]
# Author: [Ege Balcı]
# Tested on: [Win 7/8/8.1/10]
 
This shellcode sets the SE_DACL_PROTECTED flag inside security descriptor structure, 
this will prevent the process being terminated by non administrative users.
 
-----------------------------------------------------------------
*/
 
 
#include <windows.h>
#include <stdio.h>
#include "shellcode.h" 

 
int main(int argc, char const *argv[])
{
    char* BUFFER = (char*)VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(BUFFER, shellcode, sizeof(shellcode));
    (*(void(*)())BUFFER)(); 
 
    printf("This process is protected !");
    getchar();
 
    return 0;
}
