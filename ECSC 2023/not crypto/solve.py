#!/usr/bin/env python3

from base64 import b64decode
from itertools import product
from typing import Set


def rot13(raw_string: str) -> str:
    result = []

    for char in raw_string:
        if 'a' <= char <= 'z':
            offset = ord('a')
            result.append(chr(((ord(char) - offset + 13) % 26) + offset))
        elif 'A' <= char <= 'Z':
            offset = ord('A')
            result.append(chr(((ord(char) - offset + 13) % 26) + offset))
        else:
            result.append(char)

    return ''.join(result)


def get_valid_chunks(chunk: str) -> Set[str]:
    valid_chunks = set()

    for i in range(16):
        test = ''
        test += chunk[0].upper() if i & 0b1000 else chunk[0]
        test += chunk[1].upper() if i & 0b0100 else chunk[1]
        test += chunk[2].upper() if i & 0b0010 else chunk[2]
        test += chunk[3].upper() if i & 0b0001 else chunk[3]

        if all(b in b'0123456789abcdef' + b'ECSC{}' for b in b64decode(test)):
            valid_chunks.add(test)

    return valid_chunks


ct = "ehagd3gzmjrmajvkamx5mql4zqdmmgewa2z5a2iymqx2zjdmz2h2lwyuzjmubtzjbqwvbqowbgpkbgxmazv5mgmwagavsd=="

lowercase_b64 = rot13(ct)

chunks = []

for i in range(0, len(lowercase_b64), 4):
    chunks.append(get_valid_chunks(lowercase_b64[i: i + 4]))

for c in product(*chunks):
    print(b64decode(''.join(c)).decode())
