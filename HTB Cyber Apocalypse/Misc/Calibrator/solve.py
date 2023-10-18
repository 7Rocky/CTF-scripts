#!/usr/bin/env python3

from pwn import *

ITERATIONS = 47
SIDE_LENGTH = 2 * 10 ** 9
ATTEMPTS = 300

HI = SIDE_LENGTH // 2
LO = -SIDE_LENGTH // 2


def get_process():
    if len(sys.argv) == 1:
        return process(['python3', 'src/server.py'])

    host, port = sys.argv[1].split(':')
    return remote(host, port)


def binary_seach(io, a: int, b: int, fmt_string: str, reverse: bool) -> int:
    while a < b - 1:
        m = (a + b) // 2
        io.sendlineafter(b'> ', (fmt_string % m).encode())

        data = io.recvline()

        if b'UNDETECTED' in data:
            if reverse:
                a = m
            else:
                b = m
        elif b'DETECTED' in data:
            if reverse:
                b = m
            else:
                a = m

    return m


def main():
    io = get_process()
    prog = log.progress('Round')

    for r in range(ITERATIONS):
        prog.status(str(r + 1))

        x1 = binary_seach(io, 0, HI, '%d 0', False)
        x2 = binary_seach(io, LO, 0, '%d 0', True)
        y1 = binary_seach(io, 0, HI, '0 %d', False)
        y2 = binary_seach(io, LO, 0, '0 %d', True)

        X = (x1 ** 2 - x2 ** 2) // (2 * (x1 - x2))
        Y = (y1 ** 2 - y2 ** 2) // (2 * (y1 - y2))

        while True:
            io.sendlineafter(b'> ', f'{X} {Y}'.encode())
            data = io.recvline()

            if b'REFERENCE' in data:
                break
            else:
                X -= 1

    prog.success()
    io.success(io.recv().decode())


if __name__ == '__main__':
    main()

