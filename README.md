# CTF-scripts

This repository is made to upload some custom interesting scripts in different programming languages that are useful to solve CTF challenges.

Detailed write-ups are posted on my personal blog: https://7rocky.github.io/en/ctf.

For every challenge, there is a `README.md` file that has a link to the write-up.

The aim of this repository is to provide useful scripts that can be adapted to other circumstances and show how some techniques can be performed using a certain programming language.

Hope it is useful! :smile:


## BlackHat MEA CTF

| Crypto                                           | Scripts / Programs                                     | Language | Purpose                           |
| ------------------------------------------------ | ------------------------------------------------------ | -------- | --------------------------------- |
| [Ursa Minor](BlackHat%20MEA%20CTF/Ursa%20Minor/) | [solve.py](BlackHat%20MEA%20CTF/Ursa%20Minor/solve.py) | Python   | RSA. Binary Search. Smooth primes |

| Pwn                                                              | Scripts / Programs                                            | Language | Purpose                                                                                      |
| ---------------------------------------------------------------- | ------------------------------------------------------------- | -------- | -------------------------------------------------------------------------------------------- |
| [fno-stack-protector](BlackHat%20MEA%20CTF/fno-stack-protector/) | [solve.py](BlackHat%20MEA%20CTF/fno-stack-protector/solve.py) | Python   | 64-bit binary. Buffer Overflow. Redirect program execution                                   |
| [Robot Fatory](BlackHat%20MEA%20CTF/Robot%20Factory/)            | [solve.py](BlackHat%20MEA%20CTF/Robot%20Factory/solve.py)     | Python   | 64-bit binary. Heap exploitation. Unsorted bin attack. Fastbin attack. GOT overwrite         |
| [Secret Note](BlackHat%20MEA%20CTF/Secret%20Note/)               | [solve.py](BlackHat%20MEA%20CTF/Secret%20Note/solve.py)       | Python   | 64-bit binary. Buffer Overflow. Format String vulnerability. PIE, Canary, NX and ASLR bypass |

| Rev                                                              | Scripts / Programs                                               | Language | Purpose                            |
| ---------------------------------------------------------------- | ---------------------------------------------------------------- | -------- | ---------------------------------- |
| [Hope you know JS](BlackHat%20MEA%20CTF/Hope%20you%20know%20JS/) | [solve.py](BlackHat%20MEA%20CTF/Hope%20you%20know%20JS/solve.py) | Python   | z3 solution to a set of conditions |


## CTFlearn

| Binary                                              | Scripts / Programs                                                                                         | Language         | Purpose                                                           |
| --------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- | ---------------- | ----------------------------------------------------------------- |
| [Favourite Color](CTFlearn/Binary/Favorite%20Color) | [solve.py](CTFlearn/Binary/Favorite%20Color/solve.py)                                                      | Python           | 32-bit binary. Buffer Overflow. Calling a function with arguments |
| [Shell time!](CTFlearn/Binary/Shell%20time!)        | [solve.py](CTFlearn/Binary/Shell%20time!/solve.py)<br>[solve2.py](CTFlearn/Binary/Shell%20time!/solve2.py) | Python<br>Python | 32-bit binary. Buffer Overflow. Ret2Libc                          |

| Programming                                                | Scripts / Programs                                                                                                       | Language     | Purpose                                               |
| ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ | ------------ | ----------------------------------------------------- |
| [Simple Programming](CTFlearn/Binary/Simple%20Programming) | [solve.rb](CTFlearn/Binary/Simple%20Programming/solve.rb)<br>[solve2.rb](CTFlearn/Binary/Simple%20Programming/solve2.rb) | Ruby<br>Ruby | Iterate a file and count lines that match a condition |


## ImaginaryCTF

| Crypto                                                                           | Scripts / Programs                                                      | Language | Purpose                                                          |
| -------------------------------------------------------------------------------- | ----------------------------------------------------------------------- | -------- | ---------------------------------------------------------------- |
| [Personalized](ImaginaryCTF/Crypto/Personalized)                                 | [solve.py](ImaginaryCTF/Crypto/Personalized/solve.py)                   | Python   | ImaginaryCTF 07/08/2022. 75 points. RSA. PRNG seed. CRT          |
| [Relatively Small Arguments](ImaginaryCTF/Crypto/Relatively%20Small%20Arguments) | [solve.py](ImaginaryCTF/Crypto/Relatively%20Small%20Arguments/solve.py) | Python   | ImaginaryCTF 14/07/2022. 75 points. RSA. Wiener's attack         |
| [Rotating Secret Assembler](ImaginaryCTF/Crypto/Rotating%20Secret%20Assembler)   | [solve.py](ImaginaryCTF/Crypto/Rotating%20Secret%20Assembler/solve.py)  | Python   | ImaginaryCTF 05/07/2022. 50 points. RSA. Greatest Common Divisor |

| Pwn                                                                 | Scripts / Programs                                               | Language | Purpose                                                                                              |
| ------------------------------------------------------------------- | ---------------------------------------------------------------- | -------- | ---------------------------------------------------------------------------------------------------- |
| [Notepad as a Service](ImaginaryCTF/Pwn/Notepad%20as%20a%20Service) | [solve.py](ImaginaryCTF/Pwn/Notepad%20as%20a%20Service/solve.py) | Python   | ImaginaryCTF 11/07/2022. 75 points. 64-bit binary. Buffer Overflow. Ret2Libc. Canary and ASLR bypass |
| [show-me-what-you-got](ImaginaryCTF/Pwn/show-me-what-you-got)       | [solve.py](ImaginaryCTF/Pwn/show-me-what-you-got/solve.py)       | Python   | ImaginaryCTF 08/08/2022. 75 points. 64-bit binary. Format String vulnerability. GOT overwrite        |

| Reversing                               | Scripts / Programs                                 | Language | Purpose                                                          |       
| --------------------------------------- | -------------------------------------------------- | -------- | ---------------------------------------------------------------- |
| [xorrot](ImaginaryCTF/Reversing/xorrot) | [solve.py](ImaginaryCTF/Reversing/xorrot/solve.py) | Python   | ImaginaryCTF 07/07/2022. 50 points. XOR cipher with rotating key |


## picoCTF

| Binary Exploitation                                                                    | Scripts / Programs                                                                                                                                                                                      | Language              | Purpose                                                                                                                       |
| -------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| [seed-sPRiNG](picoCTF/Binary%20Exploitation/seed-sPRiNG)                               | [prng.c](picoCTF/Binary%20Exploitation/seed-sPRiNG/prng.c)                                                                                                                                              | C                     | picoCTF 2019. 350 points. 32-bit binary. PRNG                                                                                 |
| [Guessing Game 1](picoCTF/Binary%20Exploitation/Guessing%20Game%201)                   | [solve.py](picoCTF/Binary%20Exploitation/Guessing%20Game%201/solve.py)                                                                                                                                  | Python                | picoCTF 2020 Mini-Competition. 250 points. 64-bit static binary. Buffer Overflow. ROP chain                                   |
| [Guessing Game 2](picoCTF/Binary%20Exploitation/Guessing%20Game%202)                   | [solve.py](picoCTF/Binary%20Exploitation/Guessing%20Game%202/solve.py)                                                                                                                                  | Python                | picoCTF 2020 Mini-Competition. 300 points. 32-bit binary. Buffer Overflow and Format String. Ret2Libc. Bypass ASLR and canary |
| [Bizz Fuzz](picoCTF/Binary%20Exploitation/Bizz%20Fuzz)                                 | [find_bof.py](picoCTF/Binary%20Exploitation/Bizz%20Fuzz/find_bof.py)<br>[solve.py](picoCTF/Binary%20Exploitation/Bizz%20Fuzz/solve.py)                                                                  | Python<br>Python      | picoCTF 2021. 500 points. 32-bit binary. Reversing. Long way to a hidden Buffer Overflow. Redirecting program execution       |
| [filtered-shellcode](picoCTF/Binary%20Exploitation/filtered-shellcode)                 | [code.asm](picoCTF/Binary%20Exploitation/filtered-shellcode/code.asm)                                                                                                                                   | Assembly              | picoCTF 2021. 160 points. 32-bit binary. Custom shellcode                                                                     |
| [Here's a LIBC](picoCTF/Binary%20Exploitation/Here's%20a%20LIBC)                       | [solve.py](picoCTF/Binary%20Exploitation/Here's%20a%20LIBC/solve.py)<br>[solve2.py](picoCTF/Binary%20Exploitation/Here's%20a%20LIBC/solve2.py)                                                          | Python<br>Python      | picoCTF 2021. 90 points. 64-bit binary. Buffer Overflow. Ret2Libc                                                             |
| [Stonks](picoCTF/Binary%20Exploitation/Stonks)                                         | [solve.py](picoCTF/Binary%20Exploitation/Stonks/solve.py)                                                                                                                                               | Python                | picoCTF 2021. 20 points. 32-bit binary. Format String. Memory leaks                                                           |
| [The Office](picoCTF/Binary%20Exploitation/The%20Office)                               | [canary.c](picoCTF/Binary%20Exploitation/The%20Office/canary.c)<br>[solve.py](picoCTF/Binary%20Exploitation/The%20Office/solve.py)<br>[solve2.py](picoCTF/Binary%20Exploitation/The%20Office/solve2.py) | C<br>Python<br>Python | picoCTF 2021. 400 points. 32-bit binary. Heap Exploitation. Heap overflow. PRNG. Use After Free                               |
| [Unsubscriptions Are Free](picoCTF/Binary%20Exploitation/Unsubscriptions%20Are%20Free) | [solve.py](picoCTF/Binary%20Exploitation/Unsubscriptions%20Are%20Free/solve.py)                                                                                                                         | Python                | picoCTF 2021. 100 points. 32-bit binary. Heap exploitation. Use After Free                                                    |
| [fermat-strings](picoCTF/Binary%20Exploitation/fermat-strings)                         | [solve.py](picoCTF/Binary%20Exploitation/fermat-strings/solve.py)                                                                                                                                       | Python                | picoMini by redpwn. 250 points. 64-bit binary. Format String. GOT overwrite and ASLR bypass                                   |

| Cryptography                                      | Scripts / Programs                                     | Language | Purpose                                  |
| ------------------------------------------------- | ------------------------------------------------------ | -------- | ---------------------------------------- |
| [Sum-O-Primes](picoCTF/Cryptography/Sum-O-Primes) | [solve.py](picoCTF/Cryptography/Sum-O-Primes/solve.py) | Python   | picoCTF 2022. 400 points. RSA decryption |


## Securinets

| Pwn                               | Scripts / Programs                        | Language | Purpose                                                                                         |
| --------------------------------- | ----------------------------------------- | -------- | ----------------------------------------------------------------------------------------------- |
| [scrambler](Securinets/scrambler) | [solve.py](Securinets/scrambler/solve.py) | Python   | Securinets Finals 2022. 64-bit binary. ROP. Ret2Libc. GOT overwrite. Stack Pivot. Seccomp rules |


## SEETF

| Crypto                               | Scripts / Programs                        | Language | Purpose                               |
| ------------------------------------ | ----------------------------------------- | -------- | ------------------------------------- |
| [Close Enough](SEETF/Close%20Enough) | [solve.py](SEETF/Close%20Enough/solve.py) | Python   | SEETF 2022. RSA. Wrong implementation |

| Rev                          | Scripts / Programs                   | Language | Purpose                                      |
| ---------------------------- | ------------------------------------ | -------- | -------------------------------------------- |
| [babyreeee](SEETF/babyreeee) | [solve.py](SEETF/babyreeee/solve.py) | Python   | SEETF 2022. Revert encryption algorithm. XOR |
