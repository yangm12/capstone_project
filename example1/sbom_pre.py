import json
from hashlib import sha256

def sha256_u32x8(text: str):
    digest = sha256(text.encode('utf-8')).digest()
    return [int.from_bytes(digest[i*4:(i+1)*4], 'big') for i in range(8)]

with open("testsbom.json", "r") as f:
    sbom = json.load(f)

for comp in sbom["components"]:
    name = comp.get("name", "").strip().lower()
    ver = comp.get("version", "").strip()
    if name and ver:
        h = sha256_u32x8(name + ver)
        print(" ".join(map(str, h)))
