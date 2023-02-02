#!/usr/bin/env python3

from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
from Crypto.Util.Padding import unpad

from hashlib import sha256
from sage.all import matrix, QQ, Zmod


p = 4069937001870309288805965623396322384563730096882100588604666667233844487430163449354230919
g = 761690225239056989296458587964224591636809672476899126096331568501041989927462775870169890
y = 3856861197249284776013625513455404101895073264721385255129856925979499627575330256789520929
ms = (b'jctf{Puzzler_is_the_best_chall_author}', b'jctf{Wanna_see_you_trying_to_submit_that_flag}', b'jctf{D54_15_345y_4f73r_411}', b'jctf{n0_1d34}', b'jctf{s0_m4ny_fr33_s1g5}')
sigs = [(1234430664392743787630257388031047316821997031330839787382441766516744619882845371726433479, 883478467757628095229081460742191979896216430167019471897971078418352645136586828118018700), (1748400176200042123708476874280571916114895811026970462791925292863342243844069518123907016, 393625149677662932332357187873198135230656251678930039756678249504827719418549587156831030), (1389075138169306899495492856357153773415775002452775291705585460821530722304723598929266862, 781915465391184160994575003284903630852258678840377022165602064887288442417369465674198668), (1958157337340217176576113705810981137211234690293204330010317484823551198693733909083899867, 10566518658730065027243448201854036747278182399783616747373412863391884773803402507423867), (1502061706004805503203955848190130172580944756057566524292292418223793543600715005832239986, 1945316551688445103622226632281070969908748063265509793926846008296447432175736848474050566)]
c = '3c5f1079e0d30abf35d059ffea0ac6b460c1cd372d5622ede50df037f733015f'


def H(msg):
    return int.from_bytes(sha256(msg).digest(), 'big')


def get_x(k, h, r, s):
    return int(Zq((s * k - h) * r ** -1))


q = (p - 1) // 2

Zp = Zmod(p)
Zq = Zmod(q)

r = list(map(lambda sig: Zq(sig[0]), sigs))
s = list(map(lambda sig: Zq(sig[1]), sigs))
h = list(map(lambda m: Zq(H(m)), ms))

M = matrix(QQ, [
    [q, 0, 0, 0, 0, 0, 0],
    [0, q, 0, 0, 0, 0, 0],
    [0, 0, q, 0, 0, 0, 0],
    [0, 0, 0, q, 0, 0, 0],
    [0, 0, 0, 0, q, 0, 0],
    [r[i] * s[i] ** -1 for i in range(5)] + [2 ** 200 / q, 0],
    [h[i] * s[i] ** -1 for i in range(5)] + [0, q],
])

B = M.LLL()

for ks in B.rows():
    if r[0] == Zq(Zp(g) ** int(ks[0])):
        x = get_x(int(ks[0]), h[0], r[0], s[0])
        cipher = AES.new(long_to_bytes(x)[:16], AES.MODE_CBC, iv=b'\0' * 16)
        m = unpad(cipher.decrypt(bytes.fromhex(c)), 16)
        print(m.decode())