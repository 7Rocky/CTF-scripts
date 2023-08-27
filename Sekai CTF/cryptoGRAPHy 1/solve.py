#!/usr/bin/env python3

from pwn import process, remote, sys

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


def get_process():
    if len(sys.argv) == 1:
        return process(['python3', 'server.py'], level='DEBUG')

    host, port = sys.argv[1], sys.argv[2]
    return remote(host, port)


io = get_process()

io.recvuntil(b'[*] Key: ')
key = bytes.fromhex(io.recvline().decode())
SKE, DES = key[:16], key[16:]

round_prog = io.progress('Round')

for r in range(50):
    round_prog.status(f'{r + 1} / 50')
    io.recvuntil(b'/50: ')
    start = io.recvuntil(b' ')
    io.recvuntil(b'[*] Response: ')
    res = bytes.fromhex(io.recvline().decode())

    ct_iv = [(res[i:i+16], res[i+16:i+32]) for i in range(0, len(res), 32)]
    shortest_path = []

    for ct, iv in ct_iv:
        cipher = AES.new(SKE, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        shortest_path.append(pt.split(b',')[0])

    io.sendlineafter(b'> Original query: ', start + b' '.join(shortest_path))

round_prog.success('50 / 50')
print(io.recv().decode().strip())
# SEKAI{GES_15_34sy_2_br34k_kn@w1ng_th3_k3y}
