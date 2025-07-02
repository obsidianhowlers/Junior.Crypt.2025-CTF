#!/usr/bin/env python3

import time
import random
import math
from pwn import *

# Disable pwntools' verbose logging to keep output clean
context.log_level = 'error'

def find_seed(conn, n1, n2, time_window_start, time_window_end):
    """Brute-forces the seed within the given time window."""
    # Add a small margin to account for network latency and clock differences
    margin = 2 # seconds
    
    start_m = math.ceil((time_window_start - margin) * 1000000)
    end_m = math.ceil((time_window_end + margin) * 1000000)

    print(f"[*] Searching for seed in time window of {end_m - start_m} possibilities...")

    for m_guess in range(start_m, end_m):
        if m_guess % 200000 == 0:
            print(f"[*] Progress: {((m_guess - start_m) / (end_m - start_m)) * 100:.2f}%")
            
        # Create a local PRNG instance and seed it
        local_rng = random.Random()
        local_rng.seed(m_guess)
        
        # Check if the first two generated numbers match
        if local_rng.getrandbits(31) == n1:
            if local_rng.getrandbits(31) == n2:
                print(f"\n[+] Seed found: {m_guess}")
                return m_guess, local_rng

    return None, None

def solve():
    """Main solver function."""
    conn = remote('ctf.mf.grsu.by', 9045)
    try:
        # ---- Step 1: Record time and get first two numbers ----
        time_start = time.time()
        
        conn.sendlineafter(b'> ', b'1')
        line1 = conn.recvline()
        n1 = int(line1.split(b': ')[1])

        conn.sendlineafter(b'> ', b'1')
        line2 = conn.recvline()
        n2 = int(line2.split(b': ')[1])

        time_end = time.time()
        
        print(f"[*] Received first two numbers: {n1}, {n2}")
        
        # ---- Step 2: Brute-force the seed ----
        seed, cloned_rng = find_seed(conn, n1, n2, time_start, time_end)

        if not seed:
            print("[-] Seed not found. The time window might be too small or latency too high.")
            return

        # ---- Step 3: Synchronize state ----
        print("[*] Synchronizing state with server...")
        # We already requested two numbers, so we need to ask for 622 more to make a total of 624.
        # This is not strictly necessary for prediction since we have the seed,
        # but it confirms our generator is in lock-step and moves the server's index forward.
        for i in range(2, 624):
            conn.sendlineafter(b'> ', b'1')
            server_num_str = conn.recvline().split(b': ')[1]
            server_num = int(server_num_str)
            
            # Verify our local generator matches
            local_num = cloned_rng.getrandbits(31)
            if local_num != server_num:
                print(f"[-] Synchronization failed at number {i+1}! Aborting.")
                return

        print("[+] State synchronized successfully!")

        # ---- Step 4: Predict and submit ----
        predicted_num = cloned_rng.getrandbits(31)
        print(f"[+] Predicted next number: {predicted_num}")

        conn.sendlineafter(b'> ', b'2')
        conn.sendlineafter(b': ', str(predicted_num).encode())

        # ---- Step 5: Get the flag ----
        response1 = conn.recvline().strip().decode(errors='ignore')
        response2 = conn.recvline().strip().decode(errors='ignore')

        print("\n[*] Server response:")
        print(response1)
        print(response2)

    finally:
        conn.close()
        print("\n[*] Connection closed.")

if __name__ == "__main__":
    solve()