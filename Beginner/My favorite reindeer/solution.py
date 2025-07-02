import base64
import reedsolo

# The corrupted data from 2Reindeers.txt
b64_data = "TXkgZmF2b3JpdGUgcmVpbmQE/v9NMC7EPgT+fVKtYX1uAP1zYW1iaQT+ZXNpjl6WWlMZ+F06cKpDoSF7cIQ2Ug9OxlQ2VQ58otSA6jm+xjhwUFcr02pIxVfyY85y84/QFG8T94M="

# 1. Base64 decode the data
corrupted_data1 = base64.b64decode(b64_data)

print("[*] Starting brute-force search for n1 and n0...")

# 2. Brute-force n1 to perform the first level of decoding
for n1 in range(1, 51):
    try:
        rs1 = reedsolo.RSCodec(n1)
        # The decode function returns (message, ecc, errata_positions)
        # We only need the message part.
        corrupted_data0, _, _ = rs1.decode(corrupted_data1)
    except reedsolo.ReedSolomonError:
        # This n1 was not able to correct the errors, try the next one
        continue

    # If we got here, rs1.decode succeeded. Now try decoding with n0.
    for n0 in range(1, 51):
        try:
            rs0 = reedsolo.RSCodec(n0)
            original_text_bytes, _, _ = rs0.decode(corrupted_data0)
        except reedsolo.ReedSolomonError:
            # This n0 was not able to correct the errors, try the next one
            continue
        
        # If we got here, both decodes succeeded.
        # NOW, we must check if the result is valid text.
        try:
            original_text = original_text_bytes.decode('utf-8')
            
            # --- SUCCESS! ---
            # This is the correct combination of n1 and n0.
            print(f"\n[+] Success! Found correct combination: n1 = {n1}, n0 = {n0}")
            
            print("\n--- Decoded Text ---")
            print(original_text)
            
            # Extract the names to create the flag
            # The expected format is "My favorite reindeer: Name1 and Name2"
            parts = original_text.split(': ')
            if len(parts) > 1:
                names = parts[1].split(' and ')
                if len(names) == 2:
                    flag = f"grodno{{{names[0]};{names[1]}}}"
                    print("\n--- Flag ---")
                    print(flag)
                else:
                    print("[!] Could not parse names from the decoded text.")
            else:
                print("[!] Decoded text is not in the expected format.")
            
            # Exit the script since we found the solution
            exit()
            
        except UnicodeDecodeError:
            # This (n1, n0) pair was a false positive, it produced invalid bytes.
            # Continue the inner loop to try the next n0.
            continue

print("\n[-] Brute-force failed. No valid solution found in the given range.")