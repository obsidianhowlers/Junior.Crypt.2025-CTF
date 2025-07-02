import socket
import re

# --- Server Details ---
HOST = 'ctf.mf.grsu.by'
PORT = 9042

# --- LCG Parameters from source code ---
A = 2**15 - 1
B = 2**51 - 1

def get_number_from_response(response_bytes):
    """Extracts the number from the server's response string."""
    text = response_bytes.decode('utf-8', errors='ignore')
    # The number is on a line like "Следующее число: 1678..." or "Here is your number: 1678..."
    match = re.search(r':\s*(\d+)', text)
    if match:
        return int(match.group(1))
    return None

def solve():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        print(f"[*] Connecting to {HOST}:{PORT}...")
        s.connect((HOST, PORT))

        # 1. Read the initial banner
        initial_banner = s.recv(4096)
        print("[+] Received banner.")
        # print(initial_banner.decode())

        # 2. Ask for the first number (which is M)
        print("[*] Sending '1' to get the first number (M)...")
        s.sendall(b'1\n')

        # 3. Read the response and extract X0, which is M
        response = s.recv(4096)
        x0 = get_number_from_response(response)
        
        if x0 is None:
            print("[-] Failed to extract the first number. Aborting.")
            # print("Full response:", response.decode())
            return
            
        m = x0
        print(f"[+] Got the first number (X0): {x0}")
        print(f"[+] This is our modulus (M): {m}")

        # 4. Calculate the next number, X1
        x1 = (A * x0 + B) % m
        print(f"[+] Calculated the next number (X1): {x1}")

        # 5. Send '2' to enter guessing mode
        print("[*] Sending '2' to switch to guessing mode...")
        s.sendall(b'2\n')
        
        # Read the prompt for the answer
        s.recv(1024) 

        # 6. Send our calculated X1 as the guess
        print(f"[*] Sending our guess: {x1}")
        s.sendall(f"{x1}\n".encode())

        # 7. Read the flag
        flag_response = s.recv(4096).decode('utf-8', errors='ignore')
        print("\n[+] Server response:")
        print(flag_response)

if __name__ == '__main__':
    solve()
