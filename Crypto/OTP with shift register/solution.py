import base64

# Provided LFSR function
def lfsr(state, mask):
    bit = state & 1
    state >>= 1
    if bit:
        state ^= mask
    return state, bit

# Convert keystream bits into bytes
def bits_to_bytes(bits):
    return bytes(int(''.join(str(b) for b in bits[i:i+8]), 2) for i in range(0, len(bits), 8))

# Load and decode ciphertext
with open("OTP_LFSR_b64.bin", "rb") as f:
    b64_data = f.read().strip()

ciphertext = base64.b64decode(b64_data)

# Convert ciphertext to bitstream
cipher_bits = []
for byte in ciphertext:
    cipher_bits.extend([(byte >> i) & 1 for i in reversed(range(8))])  # MSB first

# LFSR setup
state = 0b1100101011110001
mask  = 0b1011010000000001

# Generate keystream bits
keystream = []
for _ in range(len(cipher_bits)):
    state, bit = lfsr(state, mask)
    keystream.append(bit)

# XOR to get plaintext bits
plain_bits = [c ^ k for c, k in zip(cipher_bits, keystream)]

# Convert bits back to bytes
plaintext = bits_to_bytes(plain_bits)

# Try decoding as UTF-8 (CTF flags are usually ASCII/UTF-8)
try:
    print("[+] Decrypted Flag:", plaintext.decode())
except:
    print("[*] Raw bytes:", plaintext)
