from ecdsa import SECP256k1
from hashlib import sha256

# Curve and parameters
curve = SECP256k1
n = curve.order

# Provided values
r = int("e37ce11f44951a60da61977e3aadb42c5705d31363d42b5988a8b0141cb2f50d", 16)
s1 = int("df88df0b8b3cc27eedddc4f3a1ecfb55e63c94739e003c1a56397ba261ba381d", 16)
s2 = int("2291d4ab9e8b0c412d74fb4918f57580b5165f8732fd278e65c802ff8be86f61", 16)
h1 = int("315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3", 16)
h2 = int("a6ab91893bbd50903679eb6f0d5364dba7ec12cd3ccc6b06dfb04c044e43d300", 16)

# Step 1: Recover k
k = ((h1 - h2) * pow(s1 - s2, -1, n)) % n

# Step 2: Recover d (private key)
d = ((s1 * k - h1) * pow(r, -1, n)) % n

print(f"Recovered private key (d): {hex(d)}")
