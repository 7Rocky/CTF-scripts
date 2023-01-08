#!/usr/bin/env python3


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


def try_solve_rsa(p, e, n, c):
    q = n // p
    phi_n = (p - 1) * (q - 1)
    d = pow(e, -1, phi_n)
    m = bytes.fromhex(hex(pow(c, d, n))[2:])

    if b'ictf{' in m:
        print(m.decode())


def main():
    c = 15569903606447382190452764402941339626308156309636986531698075641473107888825711160984364441586276963257479852352024439669272637068620013057407377137911637080205270783751875254649182246877011645122001841598989475397059021324194631682020792613902300372771482794281500616138614387516591907166918187664621666490
    n = 81283896599045813695615008896209080391755326673500780817417128377398664124888617077128749041782926115197934608675318169630210349202663592403103605147532439239684659375112943455710243781419720100154056981849800941526147131241755497543856521554758965632640670209200105067782461743490004986695348945897409335607
    f = 2010730668992923175885112531238039994491180143490780125531231868948774097426456118161798553618093102828248541236857807034323904737818411561255591866642850
    l = 11080271608353917802026380896429927782165433472385279241830041700541865655511778460984708585966037382475401275633561847042649902895681873118114821383377947
    e = 65537

    p_8192 = f

    for p_4096 in cipolla(p_8192, l):
        for p_2048 in cipolla(p_4096, l):
            for p_1024 in cipolla(p_2048, l):
                for p_512 in cipolla(p_1024, l):
                    for p_256 in cipolla(p_512, l):
                        for p_128 in cipolla(p_256, l):
                            for p_64 in cipolla(p_128, l):
                                for p_32 in cipolla(p_64, l):
                                    for p_16 in cipolla(p_32, l):
                                        for p_8 in cipolla(p_16, l):
                                            for p_4 in cipolla(p_8, l):
                                                try_solve_rsa(p_4, e, n, c)
                                                try_solve_rsa(p_4 + l, e, n, c)
                                                for p_2 in cipolla(p_4, l):
                                                    for p_1 in cipolla(p_2, l):
                                                        try_solve_rsa(p_1, e, n, c)
                                                        try_solve_rsa(p_1 + l, e, n, c)


if __name__ == '__main__':
    main()
