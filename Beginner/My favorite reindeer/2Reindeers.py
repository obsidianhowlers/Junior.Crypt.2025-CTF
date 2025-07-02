import reedsolo
import base64
from random import randint
from secret import n0, n1, m0, m1, original_text

def put_error(m, message):
    lst = [(randint(0, len(message)-1), randint(0,255).to_bytes(1, 'big')) for i in range(0, m)]
    for x in lst:
        message[x[0]:x[0]+1] =  x[1]
    return message

# Initializing the Reed-Solomon coder
rs0 = reedsolo.RSCodec(n0)

# 1. Text encoding
encoded_data0 = rs0.encode(original_text.encode('utf-8'))

# 2. Simulating errors
corrupted_data0 = bytearray(put_error(m0, encoded_data0))

# 3. Text encoding
rs1 = reedsolo.RSCodec(n1)
encoded_data1 = rs1.encode(corrupted_data0)

# 4. Simulating errors
corrupted_data1 = bytearray(put_error(m1, encoded_data1))

cd_b64 = base64.b64encode(corrupted_data1)
print(f"Corrupted data (base64):\n{cd_b64}")
