expected = b'\x74\xab\x9a\x62\x95\x6b\x9f\x81\x6b\x87\xbd\x99\x81\xb9\x93\x98\xb5\x80\x8d\xa9\x5b\x4a\xb1\x8e\xac\xa7\x9c\xb9\xa9\xa4\xa8\xb1\x39\xdc\xd7\x26\xd5\xea\xee\xdb\xc8\xc7\xca\xf5\x39\xc8\xc0\xcb'

def decrypt(enc, key):
    result = []
    for i, byte in enumerate(enc):
        val = (byte ^ (i * 2)) - key
        if 32 <= val <= 126:  # printable ASCII
            result.append(chr(val))
        else:
            return None
    return ''.join(result)

for key in range(0x80):  # 0-127
    middle = decrypt(expected, key)
    if middle:
        flag = f"grodno{{{middle}}}"
        print(f"[+] Key: {key} -> {flag}")
