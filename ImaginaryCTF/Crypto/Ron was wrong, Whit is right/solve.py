#!/usr/bin/env python3

from math import gcd


def main():
    e = 65537
    ns, cs = [], []

    with open('messages.txt') as f:
        while (line := f.readline()):
            n, c = map(int, line.split(','))
            ns.append(n)
            cs.append(c)

    found = False

    for i in range(len(ns)):
        for j in range(i + 1, len(ns)):
            if gcd(ns[i], ns[j]) != 1:
                n, c = ns[i], cs[i]
                p = gcd(ns[i], ns[j])
                found = True
                break

    if not found:
        return print('Not found')

    q = n // p
    phi_n = (p - 1) * (q - 1)
    d = pow(e, -1, phi_n)
    m = pow(c, d, n)
    print(bytes.fromhex(hex(m)[2:]).decode())


if __name__ == '__main__':
    main()
