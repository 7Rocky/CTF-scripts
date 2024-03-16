#!/usr/bin/env python3

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

n = 118641897764566817417551054135914458085151243893181692085585606712347004549784923154978949512746946759125187896834583143236980760760749398862405478042140850200893707709475167551056980474794729592748211827841494511437980466936302569013868048998752111754493558258605042130232239629213049847684412075111663446003
ct = bytes.fromhex('7f33a035c6390508cee1d0277f4712bf01a01a46677233f16387fae072d07bdee4f535b0bd66efa4f2475dc8515696cbc4bc2280c20c93726212695d770b0a8295e2bacbd6b59487b329cc36a5516567b948fed368bf02c50a39e6549312dc6badfef84d4e30494e9ef0a47bd97305639c875b16306fcd91146d3d126c1ea476')
p = 151441473357136152985216980397525591305875094288738820699069271674022167902643
q = 15624342005774166525024608067426557093567392652723175301615422384508274269305

p_digits = []
q_digits = []

for d in str(p):
    p_digits.append(d)
    p_digits.append('0')

p = int(''.join(p_digits[:-1]))

for d in str(q):
    q_digits.append('0')
    q_digits.append(d)

q_digits.append('0')

q = int(''.join(q_digits))

for i in range(len(q_digits)):
    if i % 2 == 0:
        while n % (10 ** (i + 1)) != (p * q) % (10 ** (i + 1)):
            q += 10 ** i
    else:
        while n % (10 ** (i + 1)) != (p * q) % (10 ** (i + 1)):
            p += 10 ** i

assert p * q == n

e = 65537
d = pow(e, -1, (p - 1) * (q - 1))
cipher = PKCS1_OAEP.new(RSA.construct((n, e, d)))
pt = cipher.decrypt(ct)
print(pt.decode())
