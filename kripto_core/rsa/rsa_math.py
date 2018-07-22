def gcd(a, b):
    '''Mengembalikan faktor pembagi bersama terbesar (gcd) dari dua
    bilangan integer a dan b dgn menggunakan algoritma Euclidean
    '''
    while a != 0:
        a, b = b % a, a
    return b


def find_mod_inverse(a, m):
    # Mengembalikan inversi dari a modulo m, yaitu bilangan bulat      # x sedemikian sehingga a*x % m = 1
    if gcd(a, m) != 1:
        return None  # a dan b relatif prima

    # Hitung menggunakan algoritma Extended Euclidean
    u1, u2, u3 = 1, 0, a
    v1, v2, v3 = 0, 1, m
    while v3 != 0:
        q = u3 // v3
        v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
    return u1 % m
