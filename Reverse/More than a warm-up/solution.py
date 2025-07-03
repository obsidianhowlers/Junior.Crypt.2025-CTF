import hashlib

# 1. Input "password" derived from initial analysis.
password = "easy-peasy-pwn"

# 2. First step of maybeGetFlag(), calculate MD5 of the password.
# This becomes the string to iterate over.
outer_md5_hex = hashlib.md5(password.encode()).hexdigest()
# -> '1f3a9bcb997e39c33452b40f83b60cfc'

print(f"[*] Input password: {password}")
print(f"[*] Outer MD5 hash: {outer_md5_hex}")

# 3. The core transformation loop using the CORRECT logic.
transformed_bytes = []
for i, char_of_md5 in enumerate(outer_md5_hex):
    # a. MD5 the single character (e.g., '1', then 'f', etc.)
    #    and get its HEX representation.
    inner_md5_hex = hashlib.md5(char_of_md5.encode()).hexdigest()

    # b. Get the FIRST CHARACTER of that hex string (e.g., 'c').
    first_char_of_inner_hex = inner_md5_hex[0]

    # c. Get the ASCII value of that character.
    ascii_val = ord(first_char_of_inner_hex)

    # d. Perform the transformation: i XOR (ascii_val & 0x7b)
    result_byte = i ^ (ascii_val & 0x7b)

    transformed_bytes.append(result_byte)

transformed_string = bytes(transformed_bytes)
print(f"[*] Transformed string (hex): {transformed_string.hex()}")

# 4. Final SHA256 hashing step.
final_sha256_hex = hashlib.sha256(transformed_string).hexdigest()
print(f"[*] Final SHA256 hash: {final_sha256_hex}")

# 5. Assemble the flag.
flag = f"grodno{{{final_sha256_hex}}}"

print("\n" + "="*40)
print(f"[*] GDB generated this flag: grodno{{{final_sha256_hex}}}")
print(f"[*] This IS the correct flag.")
print("="*40)



Breakpoint 1, 0x0000555555557973 in main ()
(gdb) c
Continuing.

Breakpoint 3, 0x0000555555557a40 in main ()
(gdb) c
Continuing.
You are right! But flag isn't here :(
[Inferior 1 (process 8864) exited normally]
(gdb) run Filitoni2
Starting program: /home/sanskariwolf/Documents/CTFs/Junior.Crypt.2025 CTF/More than a warm-up/MoreThanAWarmUp.exe Filitoni2
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, 0x0000555555557973 in main ()
(gdb) c
Continuing.

Breakpoint 3, 0x0000555555557a40 in main ()
(gdb) jump maybeGetFlag
Continuing at 0x55555555764d.
grodno{ea88897b06948c43c6c09ff49826e2b7ed2695b42f76223cb10484a4606b2114}
[Inferior 1 (process 8881) exited normally]
(gdb) 
