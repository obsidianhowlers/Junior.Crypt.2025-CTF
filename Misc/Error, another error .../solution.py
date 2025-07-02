#!/usr/bin/env python3
from pwn import *

# Connection details from the challenge
HOST = 'ctf.mf.grsu.by'
PORT = 9057
# The server output shows 20 rounds are required
ROUNDS = 20

# Connect to the remote server
conn = remote(HOST, PORT)

# The server runs for multiple rounds
for i in range(ROUNDS):
    log.info(f"--- Round {i + 1}/{ROUNDS} ---")

    # --- PARSING FIX ---
    # Receive all data up to the prompt ' >>'. This will include the banner on the first round.
    full_output = conn.recvuntil(b' >>', drop=True).decode()
    
    # The line with the code is the last non-empty line in the output.
    # We find it by splitting all output by newline and taking the last element.
    last_line = full_output.strip().split('\n')[-1]
    
    # The code is the part of the line before the comma.
    received_code = last_line.split(',')[0].strip()
    # --- END FIX ---

    log.info(f"Parsed code: {received_code}")

    # Convert the string of bits to a list of integers
    bits = [int(b) for b in received_code]

    # --- The Hamming Code logic remains the same ---
    # Calculate the syndrome bits
    s1 = bits[0] ^ bits[2] ^ bits[4] ^ bits[6]
    s2 = bits[1] ^ bits[2] ^ bits[5] ^ bits[6]
    s3 = bits[3] ^ bits[4] ^ bits[5] ^ bits[6]

    # The syndrome s3s2s1 gives the binary position of the error (1-indexed)
    error_pos_1_indexed = int(f"{s3}{s2}{s1}", 2)
    
    if error_pos_1_indexed == 0:
        log.success("No error detected.")
        corrected_code = received_code
        error_pos_0_indexed = 0
    else:
        error_pos_0_indexed = error_pos_1_indexed - 1
        log.warning(f"Error at 1-indexed pos: {error_pos_1_indexed} (0-indexed: {error_pos_0_indexed})")
        
        # Correct the code by flipping the error bit
        corrected_bits = list(bits)
        corrected_bits[error_pos_0_indexed] = 1 - corrected_bits[error_pos_0_indexed]
        corrected_code = "".join(map(str, corrected_bits))
        log.info(f"Corrected code: {corrected_code}")

    # Extract original data bits (at 0-indexed positions 2, 4, 5, 6)
    original_data = f"{corrected_code[2]}{corrected_code[4]}{corrected_code[5]}{corrected_code[6]}"
    log.success(f"Extracted data: {original_data}")
    
    # Format and send the answer
    answer = f"{error_pos_0_indexed}:{original_data}"
    log.info(f"Sending answer: {answer}")
    conn.sendline(answer.encode())

# After all successful rounds, the server will print the flag
flag = conn.recvall().decode()
log.success(f"FLAG: {flag.strip()}")