import base64

encoded = "np2Z3p2c3s6YmZ3ezs2ZmM/Tnc7NmJmdz5yYm96cz8+Ym53Z3w=="
decoded = base64.b64decode(encoded)
decrypted = ''.join(chr(b ^ 0xAA) for b in decoded)
flag = f"grodno{{{decrypted}}}"
print("Flag:", flag)
