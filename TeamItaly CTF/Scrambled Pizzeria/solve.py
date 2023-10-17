#!/usr/bin/env python3

import numpy as np

from collections import Counter
from PIL import Image
from pwn import log, remote


flag = np.ones((400, 400), np.uint8)
prog = log.progress('Row/Col')

for ii in range(2):
    for jj in range(400):
        prog.status(f'{ii}/{jj}')
        io = remote('scrambledpizzeria.challs.teamitaly.eu', 29002, level='CRITICAL')
        my_img = np.zeros((400, 400), np.uint8)
        my_img[200 * ii : 200 * (ii + 1), jj] = np.arange(1, 200 + 1)

        io.sendlineafter(b"What's the height of the image? ", b'400')
        io.sendlineafter(b"What's the width of the image? ", b'400')
        io.sendlineafter(b"Now send me the image and I'll do the rest!\n", my_img.tobytes().hex().encode())

        io.recvline()
        enc_my_img = np.array(Image.frombytes('L', (400, 400), bytes.fromhex(io.recvline().decode().strip())))

        io.recvline()
        enc_flag = np.array(Image.frombytes('L', (400, 400), bytes.fromhex(io.recvline().decode().strip())))
        io.close()

        c = Counter(tuple(enc_my_img[r, :]) for r in range(400))
        xor_keys = np.array([c.most_common(1)[0][0] for _ in range(400)])

        shuffled_my_img = enc_my_img ^ xor_keys
        shuffled_flag = enc_flag ^ xor_keys

        for ix, jx in zip(*shuffled_my_img.nonzero()):
            flag[shuffled_my_img[ix, jx] - 1 + 200 * ii, jj] = shuffled_flag[ix, jx]

data = Image.fromarray(flag)
data.save('flag.jpg')
