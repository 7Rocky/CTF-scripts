#!/usr/bin/env python3

from itertools import product
from pwn import process, remote, sys

from Crypto.Cipher import AES


def get_process():
    if len(sys.argv) == 1:
        return process(['python3', 'two-wrongs.py'])

    host, port = sys.argv[1], sys.argv[2]
    io = remote(host, port)
    io.recvline()
    cmd = io.recvlineS().strip()
    p = process(['bash', '-c', cmd])
    solution = p.recvline().strip()
    p.close()
    io.sendlineafter(b'solution: ', solution)
    return io


io = get_process()

io.sendlineafter(b'Select a sensor index to remove from each bit: ', b'0 -6 -12 -18 -24 -30 -36 -42')
io.recvuntil(b"Here's your flag: b'")
enc_flag = bytes.fromhex(io.recvuntil(b"'", drop=True))

rands = {
    '000000': [],
    '001000': ['x 0'],
    '000010': ['z 1'],
    '011000': ['x 3'],
    '000101': ['z 4'],
    '110000': ['x 6'],
    '000001': ['z 0'],
    '100000': ['x 2'],
    '000011': ['z 3'],
    '111000': ['x 5'],
    '000110': ['z 6'],
    '010000': ['x 1'],
    '000100': ['z 2'],
    '101000': ['x 4'],
    '000111': ['z 5'],
}

rev_insts = [
    'cx 2 6',
    'cx 2 5',
    'cx 2 4',
    'cx 1 6',
    'cx 1 5',
    'cx 1 3',
    'cx 0 5',
    'cx 0 4',
    'cx 0 3',
    'cx 6 4',
    'cx 6 3',
    'h 2',
    'h 1',
    'h 0',
    'cx 6 r',
]

key = bytearray()
prog = io.progress('Bytes')

for b in range(16):
    prog.status(f'{b + 1} / 16')
    io.recvuntil(b'Sensor measurements: ')
    all_sensors = io.recvlineS().strip().replace('?', '0')
    sensors = [all_sensors[i : i + 6] for i in range(0, 8 * 6, 6)]
    io.recvuntil(b'You can only touch main or res. Use an integer to index main, or r for res.\n')

    for i in range(8):
        insts = ';'.join(rands[sensors[i]] + rev_insts).encode()
        io.sendline(insts)

    io.recvuntil(b'Your byte: ')
    key.append(int(io.recvlineS(), 2))

prog.success(f'16 / 16')
io.info(f'Almost {key = }')

for p in product(range(2), repeat=16):
    for i, b in enumerate(p):
        key[i] = (b << 7) | (key[i] & 0x7f)

    if b'corctf{' in (flag := AES.new(key, AES.MODE_ECB).decrypt(enc_flag)):
        io.success(f'{key = }')
        io.success(f'Flag: {flag.decode()}')
        break
