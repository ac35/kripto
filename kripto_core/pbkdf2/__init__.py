import os
import hashlib
import binascii


def pbkdf2(base_key, n=32, rounds=10000):
    if not type(base_key) == bytes:
        if type(base_key) == str:
            base_key = base_key.encode() 
    # dk = hashlib.pbkdf2_hmac('sha256', base_key, os.urandom(n), rounds, dklen=16)
    dk = hashlib.pbkdf2_hmac('sha256', base_key, os.urandom(n), rounds) # hasilnya random bytes berukuran 32.

    # return binascii.hexlify(dk).decode()
    return dk
