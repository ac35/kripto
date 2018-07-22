import math
import random


def prime_sieve(sieve_size):
    # Returns a list of prime numbers calculated using
    # the Sieve of Eratosthenes algorithmthe Sieve of Eratosthenes algorithm.

    sieve = [True] * sieve_size
    sieve[0] = False  # Zero and one are not prime numbers.
    sieve[1] = False

    # Create the sieve:
    for i in range(2, int(math.sqrt(sieve_size)) + 1):
        pointer = i * 2
        while pointer < sieve_size:
            sieve[pointer] = False
            pointer += i

    # Compile the list of primes:
    primes = []
    for i in range(sieve_size):
        if sieve[i]:
            primes.append(i)

    return primes


def rabin_miller(num):
    # Returns True if num is a prime number.

    s = num - 1
    t = 0
    while s % 2 == 0:
        # keep halving s while it is even (and use t
        # to count how many times we halve s)
        s = s // 2
        t += 1

    for trials in range(5):  # try to falsify num's primality 5 times
        a = random.randrange(2, num - 1)
        v = pow(a, s, num)
        if v != 1:  # this test does not apply if v is 1.
            i = 0
            while v != (num - 1):
                if i == t - 1:
                    return False
                else:
                    i = i + 1
                    v = (v ** 2) % num
    return True


def is_prime(num):
    # Mengembalikan nilai True jika num adalah sebuah bil prima.
    if num < 2:
        return False  # bilangan < 2 bukan bilangan prima

    # About 1/3 of the time we can quickly determine if num is not prime
    # by dividing by the first few dozen prime numbers. This is quicker
    # than rabinMiller(), but unlike rabinMiller() is not guaranteed to
    # prove that a number is prime.

    low_primes = prime_sieve(1000)  # bil prima antara 2 sd 1000

    if num in low_primes:
        return True

    # lakukan tes pembagian dengan low_primes
    for prime in low_primes:
        if num % prime == 0:
            return False  # num habis dibagi bil di low_prime

    # lakukan pengujian terakhir dengan pengujian Rabin Miller
    return rabin_miller(num)


def generate_large_prime(keysize=1024):
    # mengembalikan sebuah bilangan prima acak
    while True:
        num = random.randrange(2**(keysize - 1), 2**keysize)
        if is_prime(num):
            return num
