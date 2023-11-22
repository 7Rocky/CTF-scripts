#!/usr/bin/env python3

from chal import AES, ed25519, json, key_image, NUM_LEVELS


data = json.load(open('data.json'))
levels = data['levels']
my_keys = []

for l in levels:
    image, sigc, sigr = l['signature']
    q = sigr[-1]
    for i in range(NUM_LEVELS - 1):
        priv = (q - sigr[i]) * pow(sigc[i], -1, ed25519.l) % ed25519.l
        if image == key_image(priv):
            my_keys.append(i)
            break
    else:
        my_keys.append(NUM_LEVELS - 1)

key = ''.join([l['public_keys'][i][:2] for i, l in zip(my_keys, levels)])
iv = bytes.fromhex(data['iv'])
ct = bytes.fromhex(data['enc'])

print(AES.new(bytes.fromhex(key), AES.MODE_CBC, iv).decrypt(ct).decode())
