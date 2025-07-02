#!/usr/bin/env python3
from pwn import *
import re
import random

# --- Connection Details ---
HOST = 'ctf.mf.grsu.by'
PORT = 9049
ROUNDS = 3

# --- Function to solve the discrete logarithm for a small prime ---
def solve_dlog(g, y, p):
    """
    Solves g^x mod p = y for x, by brute-force since p is small.
    """
    log.info(f"Solving for x in {g}^x mod {p} = {y}")
    for x_candidate in range(1, p):
        if pow(g, x_candidate, p) == y:
            log.success(f"Found secret x = {x_candidate}")
            return x_candidate
    log.error("Could not find x. Is g a generator?")
    return None

# --- Main execution ---
io = remote(HOST, PORT)

# Receive the initial banner and parse parameters
# Wait for the part of the banner just before the parameters are printed.
initial_data = io.recvuntil(b"Parameters: ").decode()
# Read the rest of that line to get the parameters
param_line = io.recvline().decode()
initial_data += param_line # Combine for parsing

log.info("Received initial parameters from server.")

# Use regex to find p, g, and y in the server output
params = re.search(r"p=(\d+), g=(\d+), y=(\d+)", initial_data)
if not params:
    log.error("Could not parse parameters from server output!")
    log.info(f"Received: {initial_data}")
    exit(1)

p = int(params.group(1))
g = int(params.group(2))
y = int(params.group(3))

log.info(f"Parsed parameters: p={p}, g={g}, y={y}")

# The vulnerability: p is small, so we can find x
x = solve_dlog(g, y, p)
if x is None:
    log.error("Could not solve discrete logarithm. Exiting.")
    exit(1)

# Now that we know x, we can act as an honest prover for all rounds
for i in range(ROUNDS):
    log.info(f"--- Starting Round {i+1}/{ROUNDS} ---")
    
    # 1. Prover's commitment: Send C = g^r mod p
    # CHANGED: Wait for the generic prompt ending
    io.recvuntil(b': ')
    
    # Choose a random r. 
    r = random.randint(1, p - 2) 
    C = pow(g, r, p)
    log.info(f"Chose r={r}, sending C={C}")
    io.sendline(str(C).encode())

    # 2. Verifier's challenge: Receive e
    # CHANGED: Wait for the "e = " part to robustly get the challenge
    io.recvuntil(b'e = ')
    e = int(io.recvline().strip())
    log.info(f"Received challenge e={e}")
    
    # 3. Prover's response: Send s = r + e*x mod (p-1)
    # CHANGED: Wait for the generic prompt ending
    io.recvuntil(b': ')
    
    # The exponent arithmetic is mod (p-1) due to Fermat's Little Theorem
    s = (r + e * x) % (p - 1) 
    log.info(f"Calculated s={s}, sending...")
    io.sendline(str(s).encode())

log.success("All rounds passed! Waiting for flag...")

# Let the script print the rest of the output, which should include the flag
io.interactive()