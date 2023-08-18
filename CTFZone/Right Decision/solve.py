#!/usr/bin/env python3

from hashlib import md5
from pwn import remote, sys
from random import sample
from string import ascii_letters, digits
from typing import Callable, Tuple

alphabet = ascii_letters + digits


def get_process():
    host, port = sys.argv[1], sys.argv[2]
    return remote(host, port)


def parse_pow() -> Tuple[str, str, Callable]:
    io.recvuntil(b'Prefix: ')
    prefix = io.recvline().strip().decode()
    io.recvuntil(b'Target hash starts with:')
    target = io.recvline().strip().decode()
    return prefix, target, md5


def hash_pow(prefix: str, target: str, hash_fn: Callable) -> str:
    while True:
        payload = ''.join(sample(alphabet, 20))
        if hash_fn((prefix + payload).encode()).hexdigest().startswith(target):
            return payload


if __name__ == '__main__':
    io = get_process()
    io.sendlineafter(b'Enter: ', hash_pow(*parse_pow()).encode())
    io.sendlineafter(b'Present your vote: ', b'{"vote":true,"i":0,"value":0}')
    print(io.recvall().decode())
