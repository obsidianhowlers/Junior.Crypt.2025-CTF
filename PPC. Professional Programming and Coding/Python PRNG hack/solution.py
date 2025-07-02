from pwn import *
from randcrack import RandCrack

rc = RandCrack()

# Connect to server
p = remote('ctf.mf.grsu.by', 9043)

# Skip banner
for _ in range(14):
    p.recvline()

# Step 1: Collect 624 outputs
for _ in range(624):
    p.sendline('1')  # Option 1: Get next number
    line = p.recvline().decode()
    num = int(line.strip().split(': ')[-1])
    rc.submit(num)

# Step 2: Predict next output
predicted = rc.predict_getrandbits(32)

# Step 3: Submit guess
p.sendline('2')  # Option 2: Guess
p.recvuntil(': ')  # Wait for prompt
p.sendline(str(predicted))

# See the result (flag or wrong)
print(p.recvall().decode())
