#!/usr/bin/env python3

from pwn import process, remote, sys
from z3 import BitVec, LShR, sat, Solver


def get_process():
    if len(sys.argv) == 1:
        return process(['python3', 'server.py'])

    host, port = sys.argv[1], sys.argv[2]
    return remote(host, port)


io = get_process()


def play(choice: bytes = b'rock') -> int:
    io.sendlineafter(b'Choose rock, paper, or scissors: ', choice)
    res = io.recvline()

    if b'Tie' in res:
        return 0
    elif b'lose' in res:
        return 1
    elif b'win' in res:
        return 2


def LFSR(state):
    while 1:
        yield state & 0xf
        for _ in range(4):
            bit = (state ^ (state >> 1) ^ (state >> 3) ^ (state >> 4)) & 1
            state = (state >> 1) | (bit << 63)

def z3_LFSR(state):
    while 1:
        yield state & 0xf
        for _ in range(4):
            bit = (state ^ LShR(state, 1) ^ LShR(state, 3) ^ LShR(state, 4)) & 1
            state = LShR(state, 1) | (bit << 63)


state = BitVec('s', 64)
lfsr = z3_LFSR(state)

s = Solver()

for r in range(56):
    res = play()
    sym = next(lfsr) % 3
    s.add(sym == res)

if s.check() == sat:
    model = s.model()
    _state = int(model[state].as_long())
else:
    exit(1)

lfsr = LFSR(_state)

for _ in range(56):
    next(lfsr)

for _ in range(50):
    play([b'rock', b'paper', b'scissors'][(next(lfsr) + 1) % 3])

io.success(io.recvline().decode())
