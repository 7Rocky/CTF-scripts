#!/usr/bin/env python3

from gmpy2 import iroot
from pwn import context, log, remote, sys
from random import getrandbits, seed
from sage.all import CRT


def main():
    if len(sys.argv) != 3:
        log.warning(f'Usage: python3 {sys.argv[0]} <host> <port>')
        exit(1)

    host, port = sys.argv[1], sys.argv[2]

    seeds = log.progress('Seed')

    for i in range(10000000):
        seeds.status(str(i))
        seed(i)

        if getrandbits(32) < 50:
            nice_seed = i
            break

    if nice_seed is None:
        log.warning('Could not find nice seed')
        exit(1)

    seeds.success(str(nice_seed))

    name = bytes.fromhex(hex(nice_seed)[2:])
    seed(nice_seed)
    e = 2 * getrandbits(32) + 1

    log.info(f'{e = }')

    ns, cs = [], []

    connections = log.progress('Connections')

    for i in range(1000):
        connections.status(str(i))

        with context.local(log_level='CRITICAL'):
            r = remote(host, int(port))
            r.sendlineafter(b'>>> ', name)

            r.recvuntil(b'n = ')
            ns.append(int(r.recvline().strip().decode()))
            r.recvuntil(b'c = ')
            cs.append(int(r.recvline().strip().decode()))
            r.close()

    connections.success(str(i))

    m_e = CRT(cs, ns)
    m = iroot(m_e, e)

    log.success(f'Flag: {bytes.fromhex(hex(m[0])[2:]).decode()}')


if __name__ == '__main__':
    main()
