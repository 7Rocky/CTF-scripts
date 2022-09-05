#!/usr/bin/env python3

from math import gcd
from pwn import remote


def main():
    r = remote('puzzler7.imaginaryctf.org', 3000)

    r.sendlineafter(b'Would you like an encrypted flag (y/n)? ', b'y')
    r.recvuntil(b'Public key: ')
    n1, e = eval(r.recvline().decode())
    r.recvuntil(b'Your encrypted flag: ')
    c = int(r.recvline().decode())

    r.sendlineafter(b'Would you like an encrypted flag (y/n)? ', b'y')
    r.recvuntil(b'Public key: ')
    n2, _ = eval(r.recvline().decode())
    r.close()

    p = gcd(n1, n2)
    q = n1 // p

    phi_n = (p - 1) * (q - 1)
    d = pow(e, -1, phi_n)
    m = pow(c, d, n1)

    print(bytes.fromhex(hex(m)[2:]).decode())


if __name__ == '__main__':
    main()
