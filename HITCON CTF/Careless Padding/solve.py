#!/usr/bin/env python3

from pwn import process, remote, sys


def get_process():
    if len(sys.argv) < 3:
        return process(['python3', 'chal.py'], level='CRITICAL')

    host, port = sys.argv[1], sys.argv[2]
    return remote(host, port, level='CRITICAL')


def prepare():
    io = get_process()
    io.recvuntil(b"Anyway, here's your encrypted key: ")
    enc_data = bytes.fromhex(io.recvline().decode())
    io.recv()

    iv, ct = enc_data[:16], enc_data[16:]

    if len(sys.argv) < 3:
        pt = sys.argv[1].encode()
    else:
        pt = sys.argv[3].encode()

    assert len(pt) % 16 == 0

    if len(pt) > 32:
        iv = ct[(len(pt) // 16 - 3) * 16: (len(pt) // 16 - 2) * 16]
        ct = ct[(len(pt) // 16 - 2) * 16:]
        pt = pt[(len(pt) // 16 - 2) * 16:]

    known = pt[::-1].index(b'.')

    return io, iv, ct, pt, known


N = 16

io, iv, ct, pt, known = prepare()

if known == 0:
    for i in range(16):
        payload = ''

        for b in range(256):
            _iv = iv[:i] + bytes([b]) + iv[i + 1:]
            _ct = ct[:16] + ct[16:32]

            payload += _iv.hex() + _ct.hex() + '\n'

        io.send(payload.encode())

        for b in range(256):
            if b'weirdo' not in io.recvline():
                print(chr(iv[i] ^ b ^ pt[i]))

        io.recv()

    exit()

for k in range(1, known + 1):
    padding = pt[-k]
    print('Force padding to', chr(padding) * known)

    for i in range(16):
        payload = ''

        for b in range(256):
            _iv = iv[:i] + bytes([b]) + iv[i + 1:]
            _ct = ct[:16 - known] + \
                bytes([ct[j] ^ pt[16:32][j] ^ padding for j in range(16 - known, 16)]) + \
                ct[16:32]

            payload += _iv.hex() + _ct.hex() + '\n'

        io.send(payload.encode())

        for b in range(256):
            if b'weirdo' not in io.recvline():
                print([chr(x) for x in range(0x20, 0x7f) if x % N == i])

        io.recv()

        io.close()
        io, iv, ct, pt, _ = prepare()
