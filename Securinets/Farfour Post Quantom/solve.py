#!/usr/bin/env python3

import json

from hashlib import sha256
from pwn import log, process, remote, sys
from sage.all import GF, Matrix, vector

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


F = GF(257)
g_prog = log.progress('g')
Pub_matrix_prog = log.progress('Pub_matrix')


def get_process():
    if len(sys.argv) == 1:
        return process(['python3', 'Farfour_post_quantom.py'])

    host, port = sys.argv[1], sys.argv[2]
    return remote(host, port)


def get_hint(vec):
    io.sendlineafter(b'Choose an option\n', json.dumps({'option': 'get_hint', 'vector': vec}).encode())
    return json.loads(io.recvline().decode()).get('hint')


def get_data():
    g = 0

    while g != 256:
        io.sendlineafter(b'Choose an option\n', b'{"option":"reset_connection"}')
        g = json.loads(io.recvline().decode()).get('G')
        g_prog.status(str(g))

    Pub_matrix_prog.status('Querying...')

    hint10 = get_hint([1, 0] + [0] * 14)
    hint01 = get_hint([0, 1] + [0] * 14)
    hint11 = get_hint([1, 1] + [0] * 14)
    hint1_1 = get_hint([1, -1] + [0] * 14)

    rows = [[] for _ in range(16)]
    i = 0

    for a in hint10:
        for b in hint01:
            if (a + b) % 257 in hint11 and (a - b) % 257 in hint1_1:
                rows[i].append(a)
                rows[i].append(b)
                i += 1
                break

    if not all(len(row) == 2 for row in rows):
        Pub_matrix_prog.status('Error')
        return [], []

    hint001 = get_hint([0, 0, 1] + [0] * 13)
    hint111 = get_hint([1, 1, 1] + [0] * 13)
    hint011 = get_hint([0, 1, 1] + [0] * 13)

    for row in rows:
        for b in hint001:
            if (sum(row) + b) % 257 in hint111 and \
                    (sum(row[1:]) + b) % 257 in hint011:

                row.append(b)
                break

    if not all(len(row) == 3 for row in rows):
        Pub_matrix_prog.status('Error')
        return [], []

    hint0001 = get_hint([0, 0, 0, 1] + [0] * 12)
    hint1111 = get_hint([1, 1, 1, 1] + [0] * 12)
    hint0111 = get_hint([0, 1, 1, 1] + [0] * 12)
    hint0011 = get_hint([0, 0, 1, 1] + [0] * 12)

    for row in rows:
        for b in hint0001:
            if (sum(row) + b) % 257 in hint1111 and \
                (sum(row[1:]) + b) % 257 in hint0111 and \
                    (sum(row[2:]) + b) % 257 in hint0011:

                row.append(b)
                break

    if not all(len(row) == 4 for row in rows):
        Pub_matrix_prog.status('Error')
        return [], []

    hint00001 = get_hint([0, 0, 0, 0, 1] + [0] * 11)
    hint11111 = get_hint([1, 1, 1, 1, 1] + [0] * 11)
    hint01111 = get_hint([0, 1, 1, 1, 1] + [0] * 11)
    hint00111 = get_hint([0, 0, 1, 1, 1] + [0] * 11)
    hint00011 = get_hint([0, 0, 0, 1, 1] + [0] * 11)

    for row in rows:
        for b in hint00001:
            if (sum(row) + b) % 257 in hint11111 and \
                (sum(row[1:]) + b) % 257 in hint01111 and \
                (sum(row[2:]) + b) % 257 in hint00111 and \
                    (sum(row[3:]) + b) % 257 in hint00011:

                row.append(b)
                break

    if not all(len(row) == 5 for row in rows):
        Pub_matrix_prog.status('Error')
        return [], []

    hint000001 = get_hint([0, 0, 0, 0, 0, 1] + [0] * 10)
    hint111111 = get_hint([1, 1, 1, 1, 1, 1] + [0] * 10)
    hint011111 = get_hint([0, 1, 1, 1, 1, 1] + [0] * 10)
    hint001111 = get_hint([0, 0, 1, 1, 1, 1] + [0] * 10)
    hint000111 = get_hint([0, 0, 0, 1, 1, 1] + [0] * 10)
    hint000011 = get_hint([0, 0, 0, 0, 1, 1] + [0] * 10)

    for row in rows:
        for b in hint000001:
            if (sum(row) + b) % 257 in hint111111 and \
                (sum(row[1:]) + b) % 257 in hint011111 and \
                (sum(row[2:]) + b) % 257 in hint001111 and \
                (sum(row[3:]) + b) % 257 in hint000111 and \
                    (sum(row[4:]) + b) % 257 in hint000011:

                row.append(b)
                break

    if not all(len(row) == 6 for row in rows):
        Pub_matrix_prog.status('Error')
        return [], []

    hint0000001 = get_hint([0, 0, 0, 0, 0, 0, 1] + [0] * 9)
    hint1111111 = get_hint([1, 1, 1, 1, 1, 1, 1] + [0] * 9)
    hint0111111 = get_hint([0, 1, 1, 1, 1, 1, 1] + [0] * 9)
    hint0011111 = get_hint([0, 0, 1, 1, 1, 1, 1] + [0] * 9)
    hint0001111 = get_hint([0, 0, 0, 1, 1, 1, 1] + [0] * 9)
    hint0000111 = get_hint([0, 0, 0, 0, 1, 1, 1] + [0] * 9)
    hint0000011 = get_hint([0, 0, 0, 0, 0, 1, 1] + [0] * 9)

    for row in rows:
        for b in hint0000001:
            if (sum(row) + b) % 257 in hint1111111 and \
                (sum(row[1:]) + b) % 257 in hint0111111 and \
                (sum(row[2:]) + b) % 257 in hint0011111 and \
                (sum(row[3:]) + b) % 257 in hint0001111 and \
                (sum(row[4:]) + b) % 257 in hint0000111 and \
                    (sum(row[5:]) + b) % 257 in hint0000011:

                row.append(b)
                break

    if not all(len(row) == 7 for row in rows):
        Pub_matrix_prog.status('Error')
        return [], []

    hint00000001 = get_hint([0, 0, 0, 0, 0, 0, 0, 1] + [0] * 8)
    hint11111111 = get_hint([1, 1, 1, 1, 1, 1, 1, 1] + [0] * 8)
    hint01111111 = get_hint([0, 1, 1, 1, 1, 1, 1, 1] + [0] * 8)
    hint00111111 = get_hint([0, 0, 1, 1, 1, 1, 1, 1] + [0] * 8)
    hint00011111 = get_hint([0, 0, 0, 1, 1, 1, 1, 1] + [0] * 8)
    hint00001111 = get_hint([0, 0, 0, 0, 1, 1, 1, 1] + [0] * 8)
    hint00000111 = get_hint([0, 0, 0, 0, 0, 1, 1, 1] + [0] * 8)
    hint00000011 = get_hint([0, 0, 0, 0, 0, 0, 1, 1] + [0] * 8)

    for row in rows:
        for b in hint00000001:
            if (sum(row) + b) % 257 in hint11111111 and \
                (sum(row[1:]) + b) % 257 in hint01111111 and \
                (sum(row[2:]) + b) % 257 in hint00111111 and \
                (sum(row[3:]) + b) % 257 in hint00011111 and \
                (sum(row[4:]) + b) % 257 in hint00001111 and \
                (sum(row[5:]) + b) % 257 in hint00000111 and \
                    (sum(row[6:]) + b) % 257 in hint00000011:

                row.append(b)
                break

    if not all(len(row) == 8 for row in rows):
        Pub_matrix_prog.status('Error')
        return [], []

    hint000000001 = get_hint([0, 0, 0, 0, 0, 0, 0, 0, 1] + [0] * 7)
    hint111111111 = get_hint([1, 1, 1, 1, 1, 1, 1, 1, 1] + [0] * 7)
    hint011111111 = get_hint([0, 1, 1, 1, 1, 1, 1, 1, 1] + [0] * 7)
    hint001111111 = get_hint([0, 0, 1, 1, 1, 1, 1, 1, 1] + [0] * 7)
    hint000111111 = get_hint([0, 0, 0, 1, 1, 1, 1, 1, 1] + [0] * 7)
    hint000011111 = get_hint([0, 0, 0, 0, 1, 1, 1, 1, 1] + [0] * 7)
    hint000001111 = get_hint([0, 0, 0, 0, 0, 1, 1, 1, 1] + [0] * 7)
    hint000000111 = get_hint([0, 0, 0, 0, 0, 0, 1, 1, 1] + [0] * 7)
    hint000000011 = get_hint([0, 0, 0, 0, 0, 0, 0, 1, 1] + [0] * 7)

    for row in rows:
        for b in hint000000001:
            if (sum(row) + b) % 257 in hint111111111 and \
                (sum(row[1:]) + b) % 257 in hint011111111 and \
                (sum(row[2:]) + b) % 257 in hint001111111 and \
                (sum(row[3:]) + b) % 257 in hint000111111 and \
                (sum(row[4:]) + b) % 257 in hint000011111 and \
                (sum(row[5:]) + b) % 257 in hint000001111 and \
                (sum(row[6:]) + b) % 257 in hint000000111 and \
                    (sum(row[7:]) + b) % 257 in hint000000011:

                row.append(b)
                break

    if not all(len(row) == 9 for row in rows):
        Pub_matrix_prog.status('Error')
        return [], []

    hint0000000001 = get_hint([0, 0, 0, 0, 0, 0, 0, 0, 0, 1] + [0] * 6)
    hint1111111111 = get_hint([1, 1, 1, 1, 1, 1, 1, 1, 1, 1] + [0] * 6)
    hint0111111111 = get_hint([0, 1, 1, 1, 1, 1, 1, 1, 1, 1] + [0] * 6)
    hint0011111111 = get_hint([0, 0, 1, 1, 1, 1, 1, 1, 1, 1] + [0] * 6)
    hint0001111111 = get_hint([0, 0, 0, 1, 1, 1, 1, 1, 1, 1] + [0] * 6)
    hint0000111111 = get_hint([0, 0, 0, 0, 1, 1, 1, 1, 1, 1] + [0] * 6)
    hint0000011111 = get_hint([0, 0, 0, 0, 0, 1, 1, 1, 1, 1] + [0] * 6)
    hint0000001111 = get_hint([0, 0, 0, 0, 0, 0, 1, 1, 1, 1] + [0] * 6)
    hint0000000111 = get_hint([0, 0, 0, 0, 0, 0, 0, 1, 1, 1] + [0] * 6)
    hint0000000011 = get_hint([0, 0, 0, 0, 0, 0, 0, 0, 1, 1] + [0] * 6)

    for row in rows:
        for b in hint0000000001:
            if (sum(row) + b) % 257 in hint1111111111 and \
                (sum(row[1:]) + b) % 257 in hint0111111111 and \
                (sum(row[2:]) + b) % 257 in hint0011111111 and \
                (sum(row[3:]) + b) % 257 in hint0001111111 and \
                (sum(row[4:]) + b) % 257 in hint0000111111 and \
                (sum(row[5:]) + b) % 257 in hint0000011111 and \
                (sum(row[6:]) + b) % 257 in hint0000001111 and \
                (sum(row[7:]) + b) % 257 in hint0000000111 and \
                    (sum(row[8:]) + b) % 257 in hint0000000011:

                row.append(b)
                break

    if not all(len(row) == 10 for row in rows):
        Pub_matrix_prog.status('Error')
        return [], []

    hint00000000001 = get_hint([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1] + [0] * 5)
    hint11111111111 = get_hint([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1] + [0] * 5)
    hint01111111111 = get_hint([0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1] + [0] * 5)
    hint00111111111 = get_hint([0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1] + [0] * 5)
    hint00011111111 = get_hint([0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1] + [0] * 5)
    hint00001111111 = get_hint([0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1] + [0] * 5)
    hint00000111111 = get_hint([0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1] + [0] * 5)
    hint00000011111 = get_hint([0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1] + [0] * 5)
    hint00000001111 = get_hint([0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1] + [0] * 5)
    hint00000000111 = get_hint([0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1] + [0] * 5)
    hint00000000011 = get_hint([0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1] + [0] * 5)

    for row in rows:
        for b in hint00000000001:
            if (sum(row) + b) % 257 in hint11111111111 and \
                (sum(row[1:]) + b) % 257 in hint01111111111 and \
                (sum(row[2:]) + b) % 257 in hint00111111111 and \
                (sum(row[3:]) + b) % 257 in hint00011111111 and \
                (sum(row[4:]) + b) % 257 in hint00001111111 and \
                (sum(row[5:]) + b) % 257 in hint00000111111 and \
                (sum(row[6:]) + b) % 257 in hint00000011111 and \
                (sum(row[7:]) + b) % 257 in hint00000001111 and \
                (sum(row[8:]) + b) % 257 in hint00000000111 and \
                    (sum(row[9:]) + b) % 257 in hint00000000011:

                row.append(b)
                break

    if not all(len(row) == 11 for row in rows):
        Pub_matrix_prog.status('Error')
        return [], []

    hint000000000001 = get_hint([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1] + [0] * 4)
    hint111111111111 = get_hint([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1] + [0] * 4)
    hint011111111111 = get_hint([0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1] + [0] * 4)
    hint001111111111 = get_hint([0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1] + [0] * 4)
    hint000111111111 = get_hint([0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1] + [0] * 4)
    hint000011111111 = get_hint([0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1] + [0] * 4)
    hint000001111111 = get_hint([0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1] + [0] * 4)
    hint000000111111 = get_hint([0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1] + [0] * 4)
    hint000000011111 = get_hint([0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1] + [0] * 4)
    hint000000001111 = get_hint([0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1] + [0] * 4)
    hint000000000111 = get_hint([0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1] + [0] * 4)
    hint000000000011 = get_hint([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1] + [0] * 4)

    for row in rows:
        for b in hint000000000001:
            if (sum(row) + b) % 257 in hint111111111111 and \
                (sum(row[1:]) + b) % 257 in hint011111111111 and \
                (sum(row[2:]) + b) % 257 in hint001111111111 and \
                (sum(row[3:]) + b) % 257 in hint000111111111 and \
                (sum(row[4:]) + b) % 257 in hint000011111111 and \
                (sum(row[5:]) + b) % 257 in hint000001111111 and \
                (sum(row[6:]) + b) % 257 in hint000000111111 and \
                (sum(row[7:]) + b) % 257 in hint000000011111 and \
                (sum(row[8:]) + b) % 257 in hint000000001111 and \
                (sum(row[9:]) + b) % 257 in hint000000000111 and \
                    (sum(row[10:]) + b) % 257 in hint000000000011:

                row.append(b)
                break

    if not all(len(row) == 12 for row in rows):
        Pub_matrix_prog.status('Error')
        return [], []

    hint0000000000001 = get_hint([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1] + [0] * 3)
    hint1111111111111 = get_hint([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1] + [0] * 3)
    hint0111111111111 = get_hint([0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1] + [0] * 3)
    hint0011111111111 = get_hint([0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1] + [0] * 3)
    hint0001111111111 = get_hint([0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1] + [0] * 3)
    hint0000111111111 = get_hint([0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1] + [0] * 3)
    hint0000011111111 = get_hint([0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1] + [0] * 3)
    hint0000001111111 = get_hint([0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1] + [0] * 3)
    hint0000000111111 = get_hint([0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1] + [0] * 3)
    hint0000000011111 = get_hint([0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1] + [0] * 3)
    hint0000000001111 = get_hint([0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1] + [0] * 3)
    hint0000000000111 = get_hint([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1] + [0] * 3)
    hint0000000000011 = get_hint([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1] + [0] * 3)

    for row in rows:
        for b in hint0000000000001:
            if (sum(row) + b) % 257 in hint1111111111111 and \
                (sum(row[1:]) + b) % 257 in hint0111111111111 and \
                (sum(row[2:]) + b) % 257 in hint0011111111111 and \
                (sum(row[3:]) + b) % 257 in hint0001111111111 and \
                (sum(row[4:]) + b) % 257 in hint0000111111111 and \
                (sum(row[5:]) + b) % 257 in hint0000011111111 and \
                (sum(row[6:]) + b) % 257 in hint0000001111111 and \
                (sum(row[7:]) + b) % 257 in hint0000000111111 and \
                (sum(row[8:]) + b) % 257 in hint0000000011111 and \
                (sum(row[9:]) + b) % 257 in hint0000000001111 and \
                (sum(row[10:]) + b) % 257 in hint0000000000111 and \
                    (sum(row[11:]) + b) % 257 in hint0000000000011:

                row.append(b)
                break

    if not all(len(row) == 13 for row in rows):
        Pub_matrix_prog.status('Error')
        return [], []

    hint00000000000001 = get_hint([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1] + [0] * 2)
    hint11111111111111 = get_hint([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1] + [0] * 2)
    hint01111111111111 = get_hint([0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1] + [0] * 2)
    hint00111111111111 = get_hint([0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1] + [0] * 2)
    hint00011111111111 = get_hint([0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1] + [0] * 2)
    hint00001111111111 = get_hint([0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1] + [0] * 2)
    hint00000111111111 = get_hint([0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1] + [0] * 2)
    hint00000011111111 = get_hint([0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1] + [0] * 2)
    hint00000001111111 = get_hint([0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1] + [0] * 2)
    hint00000000111111 = get_hint([0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1] + [0] * 2)
    hint00000000011111 = get_hint([0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1] + [0] * 2)
    hint00000000001111 = get_hint([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1] + [0] * 2)
    hint00000000000111 = get_hint([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1] + [0] * 2)
    hint00000000000011 = get_hint([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1] + [0] * 2)

    for row in rows:
        for b in hint00000000000001:
            if (sum(row) + b) % 257 in hint11111111111111 and \
                (sum(row[1:]) + b) % 257 in hint01111111111111 and \
                (sum(row[2:]) + b) % 257 in hint00111111111111 and \
                (sum(row[3:]) + b) % 257 in hint00011111111111 and \
                (sum(row[4:]) + b) % 257 in hint00001111111111 and \
                (sum(row[5:]) + b) % 257 in hint00000111111111 and \
                (sum(row[6:]) + b) % 257 in hint00000011111111 and \
                (sum(row[7:]) + b) % 257 in hint00000001111111 and \
                (sum(row[8:]) + b) % 257 in hint00000000111111 and \
                (sum(row[9:]) + b) % 257 in hint00000000011111 and \
                (sum(row[10:]) + b) % 257 in hint00000000001111 and \
                (sum(row[11:]) + b) % 257 in hint00000000000111 and \
                    (sum(row[12:]) + b) % 257 in hint00000000000011:

                row.append(b)
                break

    if not all(len(row) == 14 for row in rows):
        Pub_matrix_prog.status('Error')
        return [], []

    hint000000000000001 = get_hint([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1] + [0])
    hint111111111111111 = get_hint([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1] + [0])
    hint011111111111111 = get_hint([0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1] + [0])
    hint001111111111111 = get_hint([0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1] + [0])
    hint000111111111111 = get_hint([0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1] + [0])
    hint000011111111111 = get_hint([0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1] + [0])
    hint000001111111111 = get_hint([0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1] + [0])
    hint000000111111111 = get_hint([0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1] + [0])
    hint000000011111111 = get_hint([0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1] + [0])
    hint000000001111111 = get_hint([0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1] + [0])
    hint000000000111111 = get_hint([0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1] + [0])
    hint000000000011111 = get_hint([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1] + [0])
    hint000000000001111 = get_hint([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1] + [0])
    hint000000000000111 = get_hint([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1] + [0])
    hint000000000000011 = get_hint([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1] + [0])

    for row in rows:
        for b in hint000000000000001:
            if (sum(row) + b) % 257 in hint111111111111111 and \
                (sum(row[1:]) + b) % 257 in hint011111111111111 and \
                (sum(row[2:]) + b) % 257 in hint001111111111111 and \
                (sum(row[3:]) + b) % 257 in hint000111111111111 and \
                (sum(row[4:]) + b) % 257 in hint000011111111111 and \
                (sum(row[5:]) + b) % 257 in hint000001111111111 and \
                (sum(row[6:]) + b) % 257 in hint000000111111111 and \
                (sum(row[7:]) + b) % 257 in hint000000011111111 and \
                (sum(row[8:]) + b) % 257 in hint000000001111111 and \
                (sum(row[9:]) + b) % 257 in hint000000000111111 and \
                (sum(row[10:]) + b) % 257 in hint000000000011111 and \
                (sum(row[11:]) + b) % 257 in hint000000000001111 and \
                (sum(row[12:]) + b) % 257 in hint000000000000111 and \
                    (sum(row[13:]) + b) % 257 in hint000000000000011:

                row.append(b)
                break

    if not all(len(row) == 15 for row in rows):
        Pub_matrix_prog.status('Error')
        return [], []

    hint0000000000000001 = get_hint([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
    hint1111111111111111 = get_hint([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1])
    hint0111111111111111 = get_hint([0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1])
    hint0011111111111111 = get_hint([0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1])
    hint0001111111111111 = get_hint([0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1])
    hint0000111111111111 = get_hint([0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1])
    hint0000011111111111 = get_hint([0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1])
    hint0000001111111111 = get_hint([0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1])
    hint0000000111111111 = get_hint([0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1])
    hint0000000011111111 = get_hint([0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1])
    hint0000000001111111 = get_hint([0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1])
    hint0000000000111111 = get_hint([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1])
    hint0000000000011111 = get_hint([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1])
    hint0000000000001111 = get_hint([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1])
    hint0000000000000111 = get_hint([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1])
    hint0000000000000011 = get_hint([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1])

    for row in rows:
        for b in hint0000000000000001:
            if (sum(row) + b) % 257 in hint1111111111111111 and \
                (sum(row[1:]) + b) % 257 in hint0111111111111111 and \
                (sum(row[2:]) + b) % 257 in hint0011111111111111 and \
                (sum(row[3:]) + b) % 257 in hint0001111111111111 and \
                (sum(row[4:]) + b) % 257 in hint0000111111111111 and \
                (sum(row[5:]) + b) % 257 in hint0000011111111111 and \
                (sum(row[6:]) + b) % 257 in hint0000001111111111 and \
                (sum(row[7:]) + b) % 257 in hint0000000111111111 and \
                (sum(row[8:]) + b) % 257 in hint0000000011111111 and \
                (sum(row[9:]) + b) % 257 in hint0000000001111111 and \
                (sum(row[10:]) + b) % 257 in hint0000000000111111 and \
                (sum(row[11:]) + b) % 257 in hint0000000000011111 and \
                (sum(row[12:]) + b) % 257 in hint0000000000001111 and \
                (sum(row[13:]) + b) % 257 in hint0000000000000111 and \
                    (sum(row[14:]) + b) % 257 in hint0000000000000011:

                row.append(b)
                break

    if not all(len(row) == 16 for row in rows):
        Pub_matrix_prog.status('Error')
        return [], []

    secret_rows = [[i if i >= 129 else 257 - i for i in j] for j in rows]

    io.sendlineafter(b'Choose an option\n', b'{"option":"get_secret"}')
    secret_vector = json.loads(io.recvline().decode()).get('secret')

    A = Matrix(F, secret_rows)

    if A.rank() == 16:
        return [sum(c) % 257 for c in A.columns()], sum(secret_vector) % 257

    Pub_matrix_prog.status('Rank error')
    return [], []


def main():
    io.sendlineafter(b'Choose an option\n', b'{"option":"get_flag"}')
    data = json.loads(io.recvline().decode())
    enc_flag, iv = map(bytes.fromhex, [data.get('encrypted_flag'), data.get('IV')])

    A, b = [], []

    while len(b) < 16:
        A_i, b_i = get_data()

        if A_i and b_i:
            A.append(A_i)
            b.append(b_i)
            log.success(f'{len(b)} -> {A_i = }; {b_i = }')

    g_prog.success()
    Pub_matrix_prog.success()

    secret_vector = Matrix(F, A).solve_right(vector(F, b))
    secret = bytes(secret_vector)
    log.info(f'Secret: {secret.decode()}')

    key = sha256(secret).digest()[-16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    flag = unpad(cipher.decrypt(enc_flag), AES.block_size)
    log.success(f'Flag: {flag.decode()}')


if __name__ == '__main__':
    io = get_process()
    main()
