import numpy as np

# This is the de-obfuscated modular inverse function from the challenge script
def modular_inverse(matrix, modulus):
    """Calculates the modular inverse of a matrix."""
    det = int(round(np.linalg.det(matrix)))
    det_inv = pow(det, -1, modulus)
    adjugate = np.round(det * np.linalg.inv(matrix)).astype(int)
    mod_inv_matrix = (det_inv * adjugate) % modulus
    return mod_inv_matrix.astype(int)

# --- Values from the challenge ---

# The key matrix 'A' from data.txt
key_matrix = np.array([[193, 243, 218], [240, 186, 172], [62, 118, 70]])

# The encrypted data from data.txt
encrypted_matrix = np.array(
    [[76, 252, 109], [67, 73, 222], [227, 49, 104], [199, 230, 167], 
     [118, 74, 4], [253, 70, 40], [78, 123, 230], [16, 240, 85], 
     [62, 184, 34], [87, 50, 233], [224, 188, 40]]
)

# The modulus from the script (__ = 257)
MODULUS = 257

# --- Decryption ---

# 1. Calculate the modular inverse of the key matrix
key_matrix_inv = modular_inverse(key_matrix, MODULUS)

# 2. The decryption key is the transpose of the inverse key matrix
#    because encryption used the transpose of the original key (A.T)
decryption_key = key_matrix_inv.T

# 3. Decrypt by multiplying the ciphertext matrix by the decryption key
#    Formula: P = C @ (A_inv).T % modulus
decrypted_matrix = (encrypted_matrix @ decryption_key) % MODULUS

# 4. Convert the resulting matrix of numbers back to bytes
decrypted_bytes = decrypted_matrix.flatten().tobytes()

# 5. The original message was padded with null bytes, so we remove them
flag = decrypted_bytes.rstrip(b'\x00')

# 6. Print the flag
print(f"Decrypted flag: {flag.decode()}")