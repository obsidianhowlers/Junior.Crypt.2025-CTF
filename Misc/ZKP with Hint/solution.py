#!/usr/bin/env python3
from pwn import *
from math import gcd, isqrt

# Baby-Step Giant-Step algorithm
def bsgs(g, h, p, N):
    m = isqrt(N) + 1
    baby_steps = {}
    val = 1
    for j in range(m):
        if val not in baby_steps:
            baby_steps[val] = j
        val = (val * g) % p
    g_inv_m = pow(g, -m, p)
    giant_step = h
    for i in range(m):
        if giant_step in baby_steps:
            j = baby_steps[giant_step]
            x = i * m + j
            if x < N:
                return x
        giant_step = (giant_step * g_inv_m) % p
    return None

# Modular inverse for solving linear congruence
def modInverse(a, n):
    return pow(a, -1, n)

# --- Script Configuration ---
HOST = "ctf.mf.grsu.by"
PORT = 9052
n_leak = 464
unknown_bits = 512 - n_leak
r_high_bound = 2**unknown_bits

# --- Connect once and perform the entire exploit ---
log.info("Starting single-connection exploit...")
r = remote(HOST, PORT)

# --- Parse initial parameters ---
r.recvuntil(b"p=")
p = int(r.recvline().strip())
r.recvuntil(b"g=")
g = int(r.recvline().strip())
r.recvuntil(b"y=")
y = int(r.recvline().strip())
log.info(f"p={p}\ng={g}\ny={y}")

# Pre-calculate the BSGS base, as it's constant for the session
bsgs_base = pow(g, 2**n_leak, p)

# =========================================================================
# ROUND 1: Fail intentionally to learn the secret 'x'
# =========================================================================
log.info("\n--- Round 1: Reconnaissance ---")
r.recvuntil(b"C = g^r mod p: ")
C1 = int(r.recvline().strip())
r.recvuntil(b"leak(r): ")
leak1 = int(r.recvline().strip())

log.info("Solving for r1 using BSGS...")
target1 = (C1 * modInverse(pow(g, leak1, p), p)) % p
r1_high = bsgs(bsgs_base, target1, p, r_high_bound)
r1 = r1_high * (2**n_leak) + leak1
log.success(f"Found r1: {r1}")
assert pow(g, r1, p) == C1

r.recvuntil(b"e = ")
e1 = int(r.recvline().strip())

# Send bogus 's' to get the correct one
r.sendlineafter(b"s = (r + e*x) mod (p-1):", b"0")
r.recvuntil(b"Correct s is: ")
s1_correct = int(r.recvline().strip())
log.success(f"Received correct s1: {s1_correct}")

# Now calculate the secret x for this session
x_num = (s1_correct - r1) % (p-1)
x_den_inv = modInverse(e1, p-1)
secret_x = (x_num * x_den_inv) % (p-1)
log.success(f"!!! Recovered session secret x: {secret_x} !!!")

# Verify our calculated x
assert pow(g, secret_x, p) == y, "Verification of x failed! The 'corrupted y' theory might be true."
log.info("Secret x verified against public y successfully.")

# =========================================================================
# ROUND 2: Use the secret 'x' to win
# =========================================================================
log.info("\n--- Round 2: Forging Proof ---")
r.recvuntil(b"C = g^r mod p: ")
C2 = int(r.recvline().strip())
r.recvuntil(b"leak(r): ")
leak2 = int(r.recvline().strip())

log.info("Solving for r2 using BSGS...")
target2 = (C2 * modInverse(pow(g, leak2, p), p)) % p
r2_high = bsgs(bsgs_base, target2, p, r_high_bound)
r2 = r2_high * (2**n_leak) + leak2
log.success(f"Found r2: {r2}")
assert pow(g, r2, p) == C2

r.recvuntil(b"e = ")
e2 = int(r.recvline().strip())

# Calculate the correct 's' for round 2
s2_correct = (r2 + e2 * secret_x) % (p-1)
log.info(f"Calculated correct s2: {s2_correct}")

# Send the correct 's'
r.sendlineafter(b"s = (r + e*x) mod (p-1):", str(s2_correct).encode())

# --- Get the flag ---
r.recvuntil(b"Success! Flag: ")
flag = r.recvline().strip().decode()
log.success(f"FLAG: {flag}")

r.close()