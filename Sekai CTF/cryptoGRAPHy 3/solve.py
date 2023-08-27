#!/usr/bin/env python3

from utils import generate_graph
from pwn import process, remote, sys

from networkx.algorithms.isomorphism.tree_isomorphism import tree_isomorphism


def get_process():
    if len(sys.argv) == 1:
        return process(['python3', 'server copy.py'])

    host, port = sys.argv[1], sys.argv[2]
    io = remote(host, port)
    io.sendlineafter(b'Flag for cryptoGRAPHy 2: ', b'SEKAI{3ff1c13nt_GES_4_Shortest-Path-Queries-_-}')
    return io


io = get_process()

io.sendlineafter(b'> Option: ', b'1')
io.recvuntil(b'[*] Edges: ')
G = generate_graph(eval(io.recvline().decode()))

io.sendlineafter(b'> Option: ', b'2')
io.recvline()

queries = []

while True:
    line = io.recvline().decode()[:-1]
    if 'MENU' in line:
        break

    tok, res = map(bytes.fromhex, line.split(' '))

    queries.append({
        'token': tok[:32].hex(),
        'tok': [tok[i:i+32].hex() for i in range(32, len(tok), 32)],
        'res': [res[i:i+32].hex() for i in range(0, len(res), 32)]
    })

toks_0 = [q['token'] for q in queries if len(q['tok']) == 0]

mappings = {}


def define_tree(queries):
    nodes = [q['token'] for q in queries]
    edges = set()

    for node in nodes:
        for q in queries:
            if len(q['tok']) and q['tok'][0] == node:
                edges.add((node, q['token']))

    GG = generate_graph(edges)
    iso = tree_isomorphism(GG, G)

    for enc, node in iso:
        mappings[enc] = node


for tok in toks_0:
    define_tree([q for q in queries if tok in q['tok'] or tok == q['token']])

io.sendlineafter(b'> Option: ', b'3')

round_prog = io.progress('Round')

for r in range(10):
    round_prog.status(f'{r + 1} / 10')

    io.recvuntil(b'[*] Token: ')
    token = bytes.fromhex(io.recvline().decode())
    io.recvuntil(b'[*] Query Response: ')
    res = bytes.fromhex(io.recvline().decode())

    keys = [token.hex()] + [res[i:i+32].hex() for i in range(0, len(res) // 2, 32)]

    shortest_path = []

    for key in keys:
        shortest_path.append(mappings[key])

    io.sendlineafter(b'> Original query: ', ' '.join(map(str, shortest_path)).encode())

round_prog.success('10 / 10')
print(io.recv().decode().strip())
# SEKAI{Full_QR_Attack_is_not_easy_https://eprint.iacr.org/2022/838.pdf}
