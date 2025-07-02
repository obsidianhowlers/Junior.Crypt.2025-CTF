import re

# --- 1. Parse the data ---

# The dream sum from Homo_RSA.py
dream_sum = 51999884711298256279139483764500625524555947558324683565293215223860861439365869245016556808946069376210234208051889905473428307099335266198556660549084421948376963868131939751733713217547145342061587754812000747394877170239958534615968079443224197703107182407137345808430083378360519257003496366898745432749

signatures = {}
n = 0

# Read the provided text file
with open('Homo_RSA_print.txt', 'r') as f:
    content = f.read()

# Extract n using regex
n_match = re.search(r'n = (\d+)', content)
if n_match:
    n = int(n_match.group(1))

# Extract all (message, signature) pairs
sign_matches = re.findall(r'Sign\((\d+)\) = (\d+)', content)
for m_str, s_str in sign_matches:
    signatures[int(m_str)] = int(s_str)

print(f"[*] Found n and {len(signatures)} signatures.")

# --- 2. Factor the target message ---

def prime_factorize(num, available_primes):
    """Factors 'num' using only the primes from 'available_primes'."""
    factors = {}
    temp_num = num
    for p in sorted(list(available_primes)):
        if p <= 1: continue
        while temp_num % p == 0:
            factors[p] = factors.get(p, 0) + 1
            temp_num //= p
        if temp_num == 1:
            break
    if temp_num == 1:
        return factors
    else:
        return None # Failed to factor completely

signed_messages = signatures.keys()
factors = prime_factorize(dream_sum, signed_messages)

if not factors:
    print("[!] Failed to factor dream_sum using the provided signed messages.")
    exit()

print(f"[*] Successfully factored dream_sum: {factors}")

# --- 3. Combine signatures ---

# Calculate the signature of the dream_sum using the homomorphic property
dream_signature = 1
for prime_factor, exponent in factors.items():
    sig_of_factor = signatures[prime_factor]
    # In this case, all exponents are 1, but this handles cases with repeated factors
    term = pow(sig_of_factor, exponent, n)
    dream_signature = (dream_signature * term) % n

print(f"[*] Calculated signature for dream_sum: {dream_signature}")

# --- 4. Construct the flag ---
flag = f"grodno{{{dream_signature}}}"
print(f"\n[+] Flag: {flag}")
