#!/usr/bin/env python3

import json

from pwn import process, remote, sys
from sage.all import EllipticCurve, GF


def get_process():
    if len(sys.argv) == 1:
        return process(['sage', 'kernel_searcher.sage'])

    host, port = sys.argv[1], sys.argv[2]
    return remote(host, port)


A, B = 2 ** 216, 3 ** 137
p = A * B - 1

F = GF(p ** 2, modulus=[1, 0, 1], names='i')
i = F.gens()[0]

E = EllipticCurve(F, [0, 6, 0, 1, 0])

P = E(
    1640555213321637736080614728970921962714590288563692816952785470842808462670732196555713644986698688787353020078064569199240185333 *
    i + 8633131302536015373065425580178973814526244742660764898957635611033517358603093513483897324469034427019598357249425684820405193836,
    14394117136099871253105325964947616186856299274446824136456631692972014765735522929249115327770935064507795922916178933171663555625 *
    i + 4162970909124556003706955607859322868250797816630835660512553175654915928672047062846911893014330914397962880488079687378531477530
)

Q = E(
    18590308952679468489364793668589003541299106140709579196186461020066893645141198854487503147226318730158493210982567772716162869840 *
    i + 2634539327592482918121599540115765431217195093350648632832477775508933673747596362667240890051240463853167541162279343167040310088,
    13455704735691655302298811388539123261893682801800581597574165560696355678020645361403425129051999404542345275957892384971808056016 *
    i + 5939431588570449369158683956508528496223453666822913355462649580540912662646185179439579066285003135015364670770167824366051544351
)

io = get_process()

io.sendlineafter(b'Send the point you wish to evaluate: ',
                 json.dumps({'x0': '0', 'x1': '0'}).encode())
data = json.loads(io.recvline().decode())
x0, x1 = int(data.get('x0'), 16), int(data.get('x1'), 16)
x = F([x0, x1])
C = (- x ** 3 - x) / (x ** 2)

EE = EllipticCurve(F, [0, C, 0, 1, 0])

io.sendlineafter(b'Send the point you wish to evaluate: ',
                 json.dumps({'x0': hex(P[0][0]), 'x1': hex(P[0][1])}).encode())
data = json.loads(io.recvline().decode())
x0, x1 = int(data.get('x0'), 16), int(data.get('x1'), 16)
imP = EE.lift_x(F([x0, x1]))

io.sendlineafter(b'Send the point you wish to evaluate: ',
                 json.dumps({'x0': hex(Q[0][0]), 'x1': hex(Q[0][1])}).encode())
data = json.loads(io.recvline().decode())
x0, x1 = int(data.get('x0'), 16), int(data.get('x1'), 16)
imQ = EE.lift_x(F([x0, x1]))
io.close()


def dlog(G, nG):
    i = -1
    bits = []
    order = A

    while order:
        i += 1
        order //= 2

        if order * (nG - (sum(bits)) * G) != 0 * G:
            bits.append(2 ** i)

    return sum(bits)


d = dlog(imQ, -imP)
io.success(bytes.fromhex(hex(int(d))[2:]).decode())
