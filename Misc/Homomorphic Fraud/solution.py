#!/usr/bin/env python3
from pwn import *
import re
import random

# We copy the server's encryption function. We have the public key,
# so we can encrypt any message we want.
def encrypt(m, pub_key):
    n, g = pub_key
    n_squared = n * n
    # Any r such that gcd(r, n) == 1 is valid. We can pick a small one.
    r = random.randint(1, n - 1) 
    c = (pow(g, m, n_squared) * pow(r, n, n_squared)) % n_squared
    return c

# Connect to the server
# context.log_level = 'debug' # Uncomment for verbose output
io = remote('ctf.mf.grsu.by', 9054)

# --- Step 1: Receive and parse the server's initial data ---
io.recvuntil(b"[*] Public Key (n, g) = ")
pub_key_str = io.recvline().decode().strip()
io.recvuntil(b"[*] Encrypted Balance = ")
enc_balance_str = io.recvline().decode().strip()

# Extract numbers using regex
n = int(re.search(r'\((\d+),', pub_key_str).group(1))
g = int(re.search(r', (\d+)\)', pub_key_str).group(1))
enc_balance = int(enc_balance_str)

pub_key = (n, g)
n_squared = n * n

log.info(f"Received n = {n}")
log.info(f"Received g = {g}")
log.info(f"Received Enc(Balance) = {enc_balance}")

# --- Step 2: Craft the malicious transaction ---

# Our target plaintext balance
target_balance = 1000000

# We need to compute Enc(target_balance - current_balance).
# Using homomorphic properties:
# Enc(T - B) = Enc(T) * Enc(-B) mod n^2
#            = Enc(T) * [Enc(B)]^(-1) mod n^2

# 1. Encrypt the target balance (T) ourselves
log.info(f"Encrypting target balance: {target_balance}")
enc_target = encrypt(target_balance, pub_key)
log.success(f"Calculated Enc({target_balance}) = {enc_target}")

# 2. Compute the modular inverse of the current encrypted balance (Enc(B))
# This is equivalent to Enc(-B)
log.info("Calculating modular inverse of the current encrypted balance...")
inv_enc_balance = pow(enc_balance, -1, n_squared)
log.success(f"Calculated [Enc(Balance)]^(-1) = {inv_enc_balance}")

# 3. Multiply them together to get Enc(T - B)
log.info("Calculating the final encrypted amount to send...")
enc_amount_to_send = (enc_target * inv_enc_balance) % n_squared
log.success(f"Transaction amount Enc({target_balance} - Balance) = {enc_amount_to_send}")

# --- Step 3: Send the transaction and get the flag ---
io.recvuntil(b">> Enc(amount) = ")
io.sendline(str(enc_amount_to_send).encode())

# The server will multiply our Enc(T-B) with the current Enc(B), resulting in:
# Enc(B) * Enc(T-B) = Enc(B + T - B) = Enc(T)
# This new encrypted balance will decrypt to 1,000,000 and we get the flag.

response = io.recvall().decode()
print(response)

# Example output with flag:
# [+] New Encrypted Balance = ...
# Flag is: grodno{...}
