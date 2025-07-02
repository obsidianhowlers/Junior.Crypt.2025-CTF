#!/usr/bin/env python3
from pwn import *
import struct

# --- Configuration ---
HOST = 'ctf.mf.grsu.by'
PORT = 9074

# --- Analysis ---
# The program checks for two 16-bit (word) values.
# 1. The lower 16 bits of the input must be 0xfde9
# 2. The upper 16 bits of the input must be 0xbee0

# On a little-endian system (like x86-64), these are combined
# with the upper bits first to form the 32-bit number.
winning_number_hex = 0xbee0fde9

# The program reads the input as a signed 32-bit decimal integer ("%d").
# We need to convert our hex value to its signed decimal representation.
# The `struct` module is perfect for this.
# '<' denotes little-endian byte order.
# 'I' packs the number as a 4-byte unsigned integer.
# 'i' unpacks those same bytes as a 4-byte signed integer.
packed_bytes = struct.pack('<I', winning_number_hex)
signed_decimal_value = struct.unpack('<i', packed_bytes)[0]

# This is the correct number to send.
print(f"[*] Winning number in hex: {hex(winning_number_hex)}")
print(f"[*] Correct signed decimal to send: {signed_decimal_value}")

# --- Pwn ---
# Connect to the server
p = remote(HOST, PORT)

# Receive the prompt
prompt = p.recvuntil(b'number: > ')
print(prompt.decode())

# Create the payload (the number as a string) and send it
payload = str(signed_decimal_value).encode()
p.sendline(payload)
print(f"[*] Sent payload: {payload.decode()}")

# Print the rest of the response, which should contain the flag
print(p.recvall().decode())
