#!/usr/bin/env python3

from Crypto.Util.Padding import unpad
from Crypto.Util.number import long_to_bytes
from Crypto.Cipher import AES

from hashlib import sha256


def H(msg):
    return int.from_bytes(sha256(msg).digest(), 'big')


def convert_to_base(n, b):
    if n < 2:
        return [n]

    temp = n
    ans = []

    while temp != 0:
        ans = [temp % b] + ans
        temp //= b

    return ans


def cipolla(n, p):
    n %= p

    if n == 0 or n == 1:
        return [n, (p - n) % p]

    phi = p - 1

    if pow(n, phi // 2, p) != 1:
        return []

    if p % 4 == 3:
        ans = int(pow(n, (p + 1) // 4, p))
        return [ans, (p - ans) % p]

    aa = 0
    for i in range(1, p):
        temp = pow(((i * i - n) % p), phi // 2, p)

        if temp == phi:
            aa = i
            break

    exponent = convert_to_base((p + 1) // 2, 2)

    def cipolla_mult(ab, cd, w, p):
        a, b = ab
        c, d = cd
        return (a * c + b * d * w) % p, (a * d + b * c) % p

    x1 = (aa, 1)
    x2 = cipolla_mult(x1, x1, aa * aa - n, p)

    for i in range(1, len(exponent)):
        if exponent[i] == 0:
            x2 = cipolla_mult(x2, x1, aa * aa - n, p)
            x1 = cipolla_mult(x1, x1, aa * aa - n, p)
        else:
            x1 = cipolla_mult(x1, x2, aa * aa - n, p)
            x2 = cipolla_mult(x2, x2, aa * aa - n, p)
    return [x1[0], (p - x1[0]) % p]


p = 2418412161587048618911490514475907960012278945420538846001723790372197085472346428648374919
g = 2064228484934656182476030526252687681657855524182393204180796682805474532697783234019522938
y = 894978350337386203714743526086207453830598544444498469056621877210054843512079994718204008
ms = (b'jctf{f4k3_f!4g_7h3_f1r57}', b'jctf{f4k3_f!4g_7h3_53c0nd}', b'jctf{f4k3_f!4g_7h3_7h1rd}')
sigs = [(942248975683680318753150798164591935683431794761521087381578596465811760180113404300321118, 342812233069446068155480770741216218496427109436740920046532418711028275917065308430519273), (102001584770818641493080724572692756389337862746330230381962190229233871531362789283064508, 482354383195776716833349859090850583242412163611214463003633128285976770958780493119871011), (187377473811032611481162139226326301755478417757273410261128557099065854699728324076093828, 1171449558094661271371246349171199670184901923277811515634255397001853557943612820379515494)]
c = '4c76bd5dc8d57984526385d696fa0665e4c18f60b8593d42897aff792ec893d826c253646b9cb6875c91f2dfa25eedd4cc2936a3fe3174aa5b677a30ef965a7aa5dbf12c0c8234a73d0c5db5aea76644'

q = (p - 1) // 2


def sqrt(n):
    return cipolla(n, q)[1]


h1, h2, h3 = map(H, ms)
(r1, s1), (r2, s2), (r3, s3) = sigs

x = (-(s1*s2*sqrt((-3*pow(h1,2,q)*pow(r2,2,q)+6*h1*h2*r1*r2-3*pow(h2,2,q)*pow(r1,2,q))*pow(s3,2,q)+(((2*pow(h1,2,q)*r2-2*h1*h2*r1)*r3-2*h1*h3*r1*r2+2*h2*h3*pow(r1,2,q))*s2+((4*pow(h2,2,q)*r1-4*h1*h2*r2)*r3+4*h1*h3*pow(r2,2,q)-4*h2*h3*r1*r2)*s1)*s3+(pow(h1,2,q)*pow(r3,2,q)-2*h1*h3*r1*r3+pow(h3,2,q)*pow(r1,2,q))*pow(s2,2,q))+(2*h1*r1*pow(s2,2,q)+(-h1*r2-h2*r1)*s1*s2+2*h2*r2*pow(s1,2,q))*s3+(-h1*r3-h3*r1)*s1*pow(s2,2,q))*pow((2*pow(r1,2,q)*pow(s2,2,q)-2*r1*r2*s1*s2+2*pow(r2,2,q)*pow(s1,2,q))*s3-2*r1*r3*s1*pow(s2,2,q),-1,q)) % q

cipher = AES.new(long_to_bytes(x)[:16], AES.MODE_CBC, iv=b'\0' * 16)
print(unpad(cipher.decrypt(bytes.fromhex(c)), 16).decode())
