#!/usr/bin/env python3

import hashlib
import gmpy2
import math

from pwn import process, remote, sys
from typing import Any, Generator, List, Tuple


def _primes_yield_gmpy(n: int) -> Generator[int, Any, Any]:
    p = i = 1
    while i <= n:
        p = gmpy2.next_prime(p)
        yield p
        i += 1


def primes(n: int) -> List[int]:
    return list(_primes_yield_gmpy(n))


def pollard_p_1(n: int, num_primes: int = 10000) -> Tuple[int, int]:
    z = []
    logn = math.log(int(gmpy2.isqrt(n)))
    prime = primes(num_primes)

    for j in range(len(prime)):
        primej = prime[j]
        logp = math.log(primej)
        for _ in range(int(logn / logp)):
            z.append(primej)

    try:
        for pp in prime:
            i = 0
            x = pp
            while 1:
                x = gmpy2.powmod(x, z[i], n)
                i += 1
                y = gmpy2.gcd(n, x - 1)
                if y != 1:
                    p = y
                    q = n // y
                    return p, q
                if i >= len(z):
                    return 0, None
    except TypeError:
        return 0, None


def get_process():
    if len(sys.argv) == 1:
        return process(['python3', 'ursaminor.py'])

    host, port = sys.argv[1], 443
    return remote(host, port, ssl=True, sni=host)


def encrypt(r, number: int) -> List[int]:
    r.sendlineafter(b'|  > ', b'e')
    r.sendlineafter(b'|  > (int) ', str(number).encode())
    r.recvuntil(b'|  ~ Encryption ::\n')
    res = r.recvuntil(b'|\n')[:-2]
    return list(map(int, res.decode().split('|    ')[1:]))


def main():
    r = get_process()

    r.recv()
    r.sendline()

    r.recvuntil(b'|    id = ')
    n_id_hex = r.recvline().decode().strip()
    n = 0

    r.recvuntil(b'|    e  = ')
    e = int(r.recvline().decode())

    r.recvuntil(b'|    ')
    flag_enc = int(r.recvline().decode())

    a, b = 2 ** 256, 2 ** 512

    while a + 1 != b:
        test_n = (a + b) // 2

        if len(encrypt(r, test_n)) > 1:
            b = test_n
        else:
            a = test_n

    n = a if a % 2 else b
    assert hashlib.sha256(str(n).encode()).hexdigest() == n_id_hex

    p, q = pollard_p_1(n)
    assert n == p * q

    phi_n = (p - 1) * (q - 1)
    d = pow(e, -1, phi_n)
    m = pow(flag_enc, d, n)
    print(bytes.fromhex(hex(m)[2:]))

    r.close()


if __name__ == '__main__':
    main()
