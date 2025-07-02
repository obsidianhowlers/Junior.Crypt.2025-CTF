def unpuzzle(s: str) -> str:
    half = (len(s) + 1) // 2  # Length of even-indexed part
    even = s[:half]
    odd = s[half:]
    original = [''] * len(s)
    original[::2] = even
    original[1::2] = odd
    return ''.join(original)

s = '789603251257384214725442633'
for _ in range(5):
    s = unpuzzle(s)

print(f"Recovered flag: grodno{{{s}}}")
