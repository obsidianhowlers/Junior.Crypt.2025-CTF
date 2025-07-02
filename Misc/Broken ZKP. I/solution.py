import math

def solve_linear_congruence(a, b, m):
    """
    Solves the modular equation a*x ≡ b (mod m).
    This is the core function to find the secret x.
    """
    g = math.gcd(a, m)
    if b % g != 0:
        return None  # No solutions
    
    a_prime = a // g
    b_prime = b // g
    m_prime = m // g
    
    inv_a_prime = pow(a_prime, -1, m_prime)
    x0 = (b_prime * inv_a_prime) % m_prime
    
    solutions = [x0 + k * m_prime for k in range(g)]
    return solutions

def main():
    print("--- ZKP Challenge Manual Solver ---")
    print("This script will guide you through solving the challenge step-by-step.\n")
    
    # --- Part 1: Gather Initial Parameters ---
    print("--- Part 1: Gather Initial Parameters ---")
    print("Copy the values from the server prompt.")
    
    p = int(input("[?] Enter the value for p: "))
    g = int(input("[?] Enter the value for g: "))
    y = int(input("[?] Enter the value for y: "))
    r = int(input("[?] Enter the value for r: "))
    
    print("\nParameters received. Ready for Round 1.")
    print("-" * 40)
    
    # --- Part 2: Find the Secret x ---
    print("--- Part 2: Find the Secret x ---")
    e1 = int(input("[?] Enter the Challenge 'e' for Round 1: "))
    
    print("\n[ACTION] Now, send a FAKE value for 's' to the server.")
    print("[ACTION] For example, just send the number 1.")
    print("[ACTION] The server will reply with 'Verification failed!' and the CORRECT value of 's'.")
    
    s_correct = int(input("\n[?] Enter the CORRECT 's' value that the server leaked: "))
    
    print("\n[INFO] Calculating the secret 'x' using the leaked 's'...")
    
    m = p - 1
    a = e1
    b = (s_correct - r) % m
    
    possible_solutions = solve_linear_congruence(a, b, m)
    
    if not possible_solutions:
        print("[ERROR] Could not find any solutions for x. Something went wrong.")
        return

    secret_x = -1
    for x_candidate in possible_solutions:
        if pow(g, x_candidate, p) == y:
            secret_x = x_candidate
            break
            
    if secret_x == -1:
        print("[ERROR] Could not find the correct x among the candidates. Please double-check your inputs.")
        return
        
    print("\n" + "="*40)
    print(f"[SUCCESS] The secret 'x' has been found!")
    print(f"[SUCCESS] x = {secret_x}")
    print("="*40 + "\n")
    
    # --- Part 3: Pass the Remaining Rounds ---
    print("--- Part 3: Pass the Remaining Rounds ---")
    print("Now we will use the secret 'x' to pass rounds 2, 3, 4, and 5.\n")
    
    for i in range(2, 6):
        print(f"--- Round {i} ---")
        e_current = int(input(f"[?] Enter the Challenge 'e' for Round {i}: "))
        
        # Calculate the correct 's' to send
        s_to_send = (r + e_current * secret_x) % m
        
        print(f"\n[=>] For Round {i}, SEND THIS VALUE FOR s: {s_to_send}\n")
        print("-" * 20)
        
    # --- Part 4: Final Submission ---
    print("\n" + "="*40)
    print("--- Part 4: Final Submission ---")
    print("[SUCCESS] You have passed all the rounds!")
    print("[ACTION] The server will now ask for 'x'.")
    print(f"[=>] SUBMIT THIS SECRET VALUE FOR x: {secret_x}")
    print("="*40)
    print("\nAfter submitting 'x', you will receive the flag. Good luck!")

if __name__ == "__main__":
    main()