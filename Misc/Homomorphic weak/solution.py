import math
from Crypto.Util.number import long_to_bytes

# --- Values from the challenge ---
n = 10433089223103613540146127745958651165434229588914563487547767981399976732589274164426005294552849394931736652417586392379143724319911739072592115363183681
g = 10433089223103613540146127745958651165434229588914563487547767981399976732589274164426005294552849394931736652417586392379143724319911739072592115363183682
c = 76150346902050652474319505199132975171458915729410819702757805296345125747769503730890106052714968081256956538551585782887412764982436794040087385988019766749649745942838684429268976442252303534078731878450861754910871631279786840963200974278673378169157524278687731374460533999459100063574961874386074053757

# --- Step 1: Factor n using Fermat's Factorization ---

print("[*] Starting Fermat's factorization for n...")
# Start searching for 'a' from the ceiling of sqrt(n)
a = math.isqrt(n) + 1

# Calculate b_squared = a^2 - n. If it's a perfect square, we're done.
b_squared = a * a - n
b = math.isqrt(b_squared)

# The search will be very fast because p and q are close
while b * b != b_squared:
    a += 1
    b_squared = a * a - n
    b = math.isqrt(b_squared)

p = a - b
q = a + b

print(f"[+] Found factors!")
print(f"p = {p}")
print(f"q = {q}")

# Sanity check
assert p * q == n
print("[+] Sanity check passed: p * q == n")

# --- Step 2: Decrypt the message using Paillier's formula ---

print("\n[*] Decrypting the ciphertext...")
# For the simplified Paillier variant (g = n+1), phi is used for decryption
phi = (p - 1) * (q - 1)
n_squared = n * n

# L(x) = (x - 1) // n
def L(x, n_val):
    return (x - 1) // n_val

# m = L(c^phi mod n^2) * (phi^-1 mod n) mod n
c_pow_phi = pow(c, phi, n_squared)
l_val = L(c_pow_phi, n)
phi_inv = pow(phi, -1, n)
m = (l_val * phi_inv) % n

print("[+] Decryption successful.")
print(f"m = {m}")

# --- Step 3: Convert the decrypted number to the flag ---

flag = long_to_bytes(m)
print("\n[!] The flag is:")
print(flag.decode())
