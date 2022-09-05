#!/usr/bin/env python3

def main():
    ct = bytes.fromhex('970a17121d121d2b28181a19083b2f021d0d03030e1526370d091c2f360f392b1c0d3a340e1c263e070003061711013b32021d173a2b1c090f31351f06072b2b1c0d3a390f1b01072b3c0b09132d33030311')
    key = ord('i') ^ ct[0]
    flag = b''

    for b in ct:
        flag += bytes([b ^ key])
        key = flag[-1]

    print(flag.decode())


if __name__ == '__main__':
    main()
