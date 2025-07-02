import base64

def lfsr(state, mask):
    """The LFSR function provided in the challenge."""
    feedback = (state & 1)
    state >>= 1
    if feedback:
        state ^= mask
    return state, feedback

def berlekamp_massey(s):
    """A robust implementation of the Berlekamp-Massey algorithm."""
    n = len(s)
    c, b, L, m = [1], [1], 0, -1
    for N in range(n):
        d = s[N]
        for i in range(1, L + 1): d ^= c[i] & s[N - i]
        if d == 1:
            T = list(c)
            # Pad c with zeros if needed for the XOR operation
            if len(c) < len(b) + N - m: c.extend([0] * (len(b) + N - m - len(c)))
            for i in range(len(b)): c[i + (N - m)] ^= b[i]
            if L <= N / 2: L, m, b = N + 1 - L, N, T
    return c[1:L+1], L

# The encrypted data from the challenge
b64_Enc_XOR_text = "rKcUtOpHHO6ZXNzB3IwyLXPzQX9pkAYLNfrolB191POUEJoz3xQANLSTm1inSV3jh88w15d5jcaQttzpNyewT7mPufbvtVf+xMTS7Zeeai4u6/TyeFHGLPH9cHnCNg=="
ciphertext = base64.b64decode(b64_Enc_XOR_text)
known_plaintext = b"grodno{"

print(f"[+] Assuming plaintext prefix: '{known_plaintext.decode()}'")

# Keystream = Plaintext XOR Ciphertext
known_keystream_bytes = bytes([p ^ c for p, c in zip(known_plaintext, ciphertext)])

# Convert keystream bytes to a bit sequence (MSB-first)
keystream_bits = []
for byte in known_keystream_bytes:
    for i in range(7, -1, -1):
        keystream_bits.append((byte >> i) & 1)

print(f"[+] Recovered {len(keystream_bits)} keystream bits.")

# Use Berlekamp-Massey to find the mask
poly_coeffs, degree = berlekamp_massey(keystream_bits)
print(f"[+] Berlekamp-Massey found a polynomial of degree {degree}.")

if degree != 16:
    print("[-] Degree is not 16. Aborting.")
    exit()

# --- THE FINAL FIX: Correct polynomial-to-mask conversion ---
# The i-th coefficient corresponds directly to the i-th bit of the mask.
mask = 0
for i, bit in enumerate(poly_coeffs):
    if bit == 1:
        mask |= (1 << i)
print(f"[+] Found LFSR mask: {hex(mask)}")

# Brute-force the 16-bit initial state
print("[+] Brute-forcing 16-bit initial state...")
correct_initial_state = -1
for state_candidate in range(2**16):
    temp_state = state_candidate
    generated_bits = []
    for _ in range(len(keystream_bits)):
        temp_state, feedback = lfsr(temp_state, mask)
        generated_bits.append(feedback)
    
    if generated_bits == keystream_bits:
        correct_initial_state = state_candidate
        print(f"[+] Success! Found initial state: {hex(correct_initial_state)}")
        break

if correct_initial_state == -1:
    print("[-] Failed to find the initial state.")
    exit()

# Decrypt the full flag
print("[+] Decrypting the flag...")
state = correct_initial_state
keystream = b""
bits = []
for _ in range(len(ciphertext) * 8):
    state, feedback = lfsr(state, mask)
    bits.append(feedback)
    if len(bits) == 8:
        byte = 0
        for bit in bits:
            byte = (byte << 1) | bit
        keystream += bytes([byte])
        bits = []

flag = bytes([c ^ k for c, k in zip(ciphertext, keystream)])

print("\n" + "="*50)
print(f"  Flag: {flag.decode()}")
print("="*50)