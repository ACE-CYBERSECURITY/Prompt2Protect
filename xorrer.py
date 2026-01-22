# gen_flag_hex.py
import binascii

FLAG_SECRET = "ACE".encode()
plaintext_base = "T3ST_CH4LL4N83_II".encode()

def xor_bytes(data, key):
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

print(xor_bytes(plaintext_base, FLAG_SECRET).hex())
