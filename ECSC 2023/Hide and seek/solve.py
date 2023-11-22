#!/usr/bin/env python3

from ast import literal_eval

from sage.all import CRT, discrete_log, EllipticCurve, factor, GF, proof

from Crypto.Util.number import long_to_bytes


proof.arithmetic(False)
p = 1789850433742566803999659961102071018708588095996784752439608585988988036381340404632423562593
a = 62150203092456938230366891668382702110196631396589305390157506915312399058961554609342345998
b = 1005820216843804918712728918305396768000492821656453232969553225956348680715987662653812284211
F = GF(p)
E = EllipticCurve(F, [a, b])
G = E.gens()[0]

G_order = G.order()
G_factors = factor(G_order)


def dlog(G, nG):
    dlogs, new_factors = [], []

    for p, e in G_factors:
        new_factors.append(p ** e)
        t = G_order // new_factors[-1]
        dlogs.append(discrete_log(t * nG, t * G, operation='+'))

    return CRT(dlogs, new_factors)


with open('output.txt') as f:
    data_raw = literal_eval(f.read().replace(' : 1)', ')').replace(' :', ','))

data = [(a, b, E(*R_data)) for a, b, R_data in data_raw]

a1, b1, R1 = data[0]
a2, b2, R2 = data[1]

P = int(pow(pow(b1, -1, G_order) * a1 - pow(b2, -1, G_order) * a2, -1, G_order)) * (int(pow(b1, -1, G_order)) * R1 - int(pow(b2, -1, G_order)) * R2)
Q = int(pow(pow(a1, -1, G_order) * b1 - pow(a2, -1, G_order) * b2, -1, G_order)) * (int(pow(a1, -1, G_order)) * R1 - int(pow(a2, -1, G_order)) * R2)

print('ECSC{' + long_to_bytes(int(dlog(P, Q))).decode() + '}')
