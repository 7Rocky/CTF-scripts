#!/usr/bin/env python3

from pwn import process, remote, sys
from utils import generate_graph


def get_process():
    if len(sys.argv) == 1:
        return process(['python3', 'server copy.py'])

    host, port = sys.argv[1], sys.argv[2]
    io = remote(host, port)
    io.sendlineafter(b'Flag for cryptoGRAPHy 1: ', b'SEKAI{GES_15_34sy_2_br34k_kn@w1ng_th3_k3y}')
    return io


io = get_process()

NODES_SIZE = 130

round_prog = io.progress('Round')

for r in range(10):
    round_prog.status(f'{r + 1} / 10')

    data = {}
    nodes = [0] * NODES_SIZE

    io.recvuntil(b'[*] Destination: ')
    dest = int(io.recvline().decode())

    for i in range(NODES_SIZE):
        if i == dest:
            continue

        io.sendlineafter(b'> Query u,v: ', f'{i},{dest}'.encode())
        io.recvuntil(b'[*] Token: ')
        token = bytes.fromhex(io.recvline().decode())
        io.recvuntil(b'[*] Query Response: ')
        res = bytes.fromhex(io.recvline().decode())

        keys = [token[16:]] + [res[i+16:i+32]
                               for i in range(0, len(res) // 2, 32)]

        data[i] = list(map(lambda b: b.hex(), keys))

        if nodes[dest] == 0:
            nodes[dest] = keys[-1].hex()

        if nodes[i] == 0:
            nodes[i] = keys[0].hex()

    edges = set()

    for d in data.values():
        prev_node = nodes.index(d[0])

        for i, next_node in enumerate(d[1:] + [nodes[0]]):
            edge = (prev_node, nodes.index(next_node))

            if (edge[1], edge[0]) not in edges and edge[0] != edge[1] and edge != (dest, 0):
                edges.add(edge)

            prev_node = nodes.index(next_node)

    G = generate_graph(edges)
    degrees = sorted(map(lambda t: t[1], G.degree))

    io.sendlineafter(b'> Query u,v: ', f'{dest},{dest}'.encode())
    io.sendlineafter(b'> Answer: ', ' '.join(map(str, degrees)).encode())

round_prog.success('10 / 10')
print(io.recv().decode().strip())
# SEKAI{3ff1c13nt_GES_4_Shortest-Path-Queries-_-}
