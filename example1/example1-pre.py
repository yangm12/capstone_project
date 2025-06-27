import struct
from hashlib import sha256

def concatHash(name: str, ver:str):
    text = name+ver
    return sha256(text.encode('utf-8')).digest()
    
text = concatHash("flask", "3.1.1")

array = list()
for i in range(0,8):
    array.append(text[i*4:(i+1)*4])

args = ' '.join(str(int.from_bytes(b, byteorder='big')) for b in array)
print(args)