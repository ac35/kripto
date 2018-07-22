import random
import sys
import os
from kripto_core.rsa.prime_number import generate_large_prime
from kripto_core.rsa.rsa_math import gcd, find_mod_inverse


def generate_key(keysize=1024):
    ''' Membuat sepasang kunci RSA dengan ukuran kunci mengikuti
        nilai pada keysize (nilai default adalah 1024-bit).

        Langkah pertama: Membuat dua bilangan prima, p dan q.
        Kemudan,hitung n = p * q.
    '''
    p = generate_large_prime(keysize)
    q = generate_large_prime(keysize)
    n = p * q

    # Langkah kedua: Buat e yang relatif prima dengan (p-1)*(q-1).
    while True:
        # Terus mencari bilangan acak untuk e sampai e valid
        e = random.randrange(2 ** (keysize - 1), 2 ** keysize)
        if gcd(e, (p - 1) * (q - 1)) == 1:
            break

    # Langkah ketiga: Hitung d
    d = find_mod_inverse(e, (p - 1) * (q - 1))

    public_key = (n, e)
    private_key = (n, d)

    return public_key, private_key

##############################################################################
# buat se generik mungkin
def make_string_keys(keysize=1024):
    ''' Mengembalikan sebuah tuple yang berisi kunci publik dan kunci privat.
        Kedua kunci tersebut adalah string.
    '''
    pub, priv = generate_key(keysize)
    # ubah kunci ke dalam format string
    # simbol ',' berfungsi sebagai pembatas (berguna pada saat membaca key)
    public_key = '{},{},{}'.format(keysize, pub[0], pub[1])
    private_key = '{},{},{}'.format(keysize, priv[0], priv[1])

    return public_key, private_key
##############################################################################
