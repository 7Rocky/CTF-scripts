# CTF-scripts

This repository is made to upload some custom interesting scripts in different programming languages that are useful to solve CTF challenges.

Detailed write-ups are posted on my personal blog: https://7rocky.github.io/en/ctf.

For every challenge, there is a `README.md` file that has a link to the write-up.

The aim of this repository is to provide useful scripts that can be adapted to other circumstances and show how some techniques can be performed using a certain programming language.

Hope it is useful! :smile:


## BlackHat MEA CTF

| Crypto                                          | Scripts / Programs                                     | Language | Purpose                           |
| ----------------------------------------------- | ------------------------------------------------------ | -------- | --------------------------------- |
| [Ursa Minor](BlackHat%20MEA%20CTF/Ursa%20Minor) | [solve.py](BlackHat%20MEA%20CTF/Ursa%20Minor/solve.py) | Python   | RSA. Binary Search. Smooth primes |

| Pwn                                                             | Scripts / Programs                                            | Language | Purpose                                                                                      |
| --------------------------------------------------------------- | ------------------------------------------------------------- | -------- | -------------------------------------------------------------------------------------------- |
| [fno-stack-protector](BlackHat%20MEA%20CTF/fno-stack-protector) | [solve.py](BlackHat%20MEA%20CTF/fno-stack-protector/solve.py) | Python   | 64-bit binary. Buffer Overflow. Redirect program execution                                   |
| [Robot Fatory](BlackHat%20MEA%20CTF/Robot%20Factory)            | [solve.py](BlackHat%20MEA%20CTF/Robot%20Factory/solve.py)     | Python   | 64-bit binary. Heap exploitation. Unsorted Bin attack. Fast Bin attack. GOT overwrite        |
| [Secret Note](BlackHat%20MEA%20CTF/Secret%20Note)               | [solve.py](BlackHat%20MEA%20CTF/Secret%20Note/solve.py)       | Python   | 64-bit binary. Buffer Overflow. Format String vulnerability. PIE, Canary, NX and ASLR bypass |

| Rev                                                             | Scripts / Programs                                               | Language | Purpose                              |
| --------------------------------------------------------------- | ---------------------------------------------------------------- | -------- | ------------------------------------ |
| [Hope you know JS](BlackHat%20MEA%20CTF/Hope%20you%20know%20JS) | [solve.py](BlackHat%20MEA%20CTF/Hope%20you%20know%20JS/solve.py) | Python   | `z3` solution to a set of conditions |


## corCTF 2023

| Crypto                            | Scripts / Programs                      | Language | Purpose                                 |
| --------------------------------- | --------------------------------------- | -------- | --------------------------------------- |
| [fizzbuzz101](corCTF/fizzbuzz101) | [solve.py](corCTF/fizzbuzz101/solve.py) | Python   | corCTF 2023. RSA decryption. LSB oracle |


## CTFlearn

| Binary                                              | Scripts / Programs                                                                                         | Language         | Purpose                                                           |
| --------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- | ---------------- | ----------------------------------------------------------------- |
| [Favourite Color](CTFlearn/Binary/Favorite%20Color) | [solve.py](CTFlearn/Binary/Favorite%20Color/solve.py)                                                      | Python           | 32-bit binary. Buffer Overflow. Calling a function with arguments |
| [Shell time!](CTFlearn/Binary/Shell%20time!)        | [solve.py](CTFlearn/Binary/Shell%20time!/solve.py)<br>[solve2.py](CTFlearn/Binary/Shell%20time!/solve2.py) | Python<br>Python | 32-bit binary. Buffer Overflow. Ret2Libc                          |

| Programming                                                | Scripts / Programs                                                                                                       | Language     | Purpose                                               |
| ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ | ------------ | ----------------------------------------------------- |
| [Simple Programming](CTFlearn/Binary/Simple%20Programming) | [solve.rb](CTFlearn/Binary/Simple%20Programming/solve.rb)<br>[solve2.rb](CTFlearn/Binary/Simple%20Programming/solve2.rb) | Ruby<br>Ruby | Iterate a file and count lines that match a condition |


## CTFZone

| Crypto                                                           | Scripts / Programs                                          | Language | Purpose                                                                                |
| ---------------------------------------------------------------- | ----------------------------------------------------------- | -------- | -------------------------------------------------------------------------------------- |
| [Come on feel the nonce](CTFZone/Come%20on%20feel%20the%20nonce) | [solve.py](CTFZone/Come%20on%20feel%20the%20nonce/solve.py) | Python   | CTFZone Quals 2023. ECDSA. Biased nonces. Hidden Number Problem. LLL lattice reduction |
| [Right Decision](CTFZone/Right%20Decision)                       | [solve.py](CTFZone/Right%20Decision/solve.py)               | Python   | CTFZone Quals 2023. Shamir Secret Sharing. System of equations                         |


## HackTheBoo CTF

| Crypto                                   | Scripts / Programs                                  | Language | Purpose                              |
| ---------------------------------------- | --------------------------------------------------- | -------- | ------------------------------------ |
| [AHS512](HackTheBoo%20CTF/Crypto/AHS512) | [solve.py](HackTheBoo%20CTF/Crypto/AHS512/solve.py) | Python   | Custom hash function. Bit operations |

| Forensics                                                                 | Scripts / Programs                                                     | Language | Purpose                                   |
| ------------------------------------------------------------------------- | ---------------------------------------------------------------------- | -------- | ----------------------------------------- |
| [Halloween Invitation](HackTheBoo%20CTF/Forensics/Halloween%20Invitation) | [solve.py](HackTheBoo%20CTF/Forensics/Halloween%20Invitation/solve.py) | Python   | Microsoft Office VBA macros deobfuscation |

| Pwn                                               | Scripts / Programs                                      | Language | Purpose                                                   |
| ------------------------------------------------- | ------------------------------------------------------- | -------- | --------------------------------------------------------- |
| [Entity](HackTheBoo%20CTF/Pwn/Entity)             | [solve.py](HackTheBoo%20CTF/Pwn/Entity/solve.py)        | Python   | 64-bit binary. Union structure. Type confusion            |
| [Finale](HackTheBoo%20CTF/Pwn/Finale)             | [solve.py](HackTheBoo%20CTF/Pwn/Finale/solve.py)        | Python   | 64-bit binary. open-read-write ROP chain                  |
| [Pumpking](HackTheBoo%20CTF/Pwn/Pumpking)         | [solve.py](HackTheBoo%20CTF/Pwn/Pumpking/solve.py)      | Python   | 64-bit binary. `seccomp` rules. Custom shellcode          |
| [Spooky Time](HackTheBoo%20CTF/Pwn/Spooky%20Time) | [solve.py](HackTheBoo%20CTF/Pwn/Spooky%20Time/solve.py) | Python   | 64-bit binary. Format String vulnerability. GOT overwrite |


## HITCON CTF

| Crypto                                   | Scripts / Programs                                   | Language | Purpose                                                                                                            |
| ---------------------------------------- | ---------------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------ |
| [Share](HITCON%20CTF/Careless%20Padding) | [solve.py](HITCON%20CTF/Careless%20Padding/solve.py) | Python   | HITCON CTF Quals 2023. Padding Oracle Attack. Custom padding. Guessing                                             |
| [Share](HITCON%20CTF/Share)              | [solve.py](HITCON%20CTF/Share/solve.py)              | Python   | HITCON CTF Quals 2023. Shamir Secret Sharing. Lagrange interpolation. Chinese Remainder Theorem. `multiprocessing` |


## HTB Cyber Apocalypse 2023

| Crypto                                                                                              | Scripts / Programs                                                                         | Language          | Purpose                                                                     |
| --------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ | ----------------- | --------------------------------------------------------------------------- |
| [Biased Heritage](HTB%20Cyber%20Apocalypse%202023/Crypto/Biased%20Heritage)                         | [solve.py](HTB%20Cyber%20Apocalypse%202023/Crypto/Biased%20Heritage/solve.py)              | Python / SageMath | Schnorr signature. Hidden Number Problem. LLL lattice reduction             |
| [Colliding Heritage](HTB%20Cyber%20Apocalypse%202023/Crypto/Colliding%20Heritage)                   | [solve.py](HTB%20Cyber%20Apocalypse%202023/Crypto/Colliding%20Heritage/solve.py)           | Python            | Schnorr signature. MD5 collision                                            |
| [Converging Visions](HTB%20Cyber%20Apocalypse%202023/Crypto/Converging%20Visions)                   | [solve.py](HTB%20Cyber%20Apocalypse%202023/Crypto/Converging%20Visions/solve.py)           | Python / SageMath | ECC. Binary search. Finding curve parameters. Smart's attack. PRNG          |
| [Elliptic Labyrinth](HTB%20Cyber%20Apocalypse%202023/Crypto/Elliptic%20Labyrinth)                   | [solve.py](HTB%20Cyber%20Apocalypse%202023/Crypto/Elliptic%20Labyrinth/solve.py)           | Python            | ECC. Finding curve parameters                                               |
| [Elliptic Labyrinth Revenge](HTB%20Cyber%20Apocalypse%202023/Crypto/Elliptic%20Labyrinth%20Revenge) | [solve.py](HTB%20Cyber%20Apocalypse%202023/Crypto/Elliptic%20Labyrinth%20Revenge/solve.py) | Python / SageMath | ECC. Finding curve parameters. Coppersmith method on a bivariate polynomial |

| Hardware                                              | Scripts / Programs                                                 | Language | Purpose                                                                 |
| ----------------------------------------------------- | ------------------------------------------------------------------ | -------- | ----------------------------------------------------------------------- |
| [HM74](HTB%20Cyber%20Apocalypse%202023/Hardware/HM74) | [solve.py](HTB%20Cyber%20Apocalypse%202023/Hardware/HM74/solve.py) | Python   | Noisy channel. Hamming codes. Statistically find correct message blocks |

| Misc                                                          | Scripts / Programs                                                   | Language | Purpose                           |
| ------------------------------------------------------------- | -------------------------------------------------------------------- | -------- | --------------------------------- |
| [Calibrator](HTB%20Cyber%20Apocalypse%202023/Misc/Calibrator) | [solve.py](HTB%20Cyber%20Apocalypse%202023/Misc/Calibrator/solve.py) | Python   | Binary search. Euclidean distance |

| Pwn                                                                    | Scripts / Programs                                                         | Language | Purpose                                                                    |
| ---------------------------------------------------------------------- | -------------------------------------------------------------------------- | -------- | -------------------------------------------------------------------------- |
| [Control Room](HTB%20Cyber%20Apocalypse%202023/Pwn/Control%20Room)     | [solve.py](HTB%20Cyber%20Apocalypse%202023/Pwn/Control%20Room/solve.py)    | Python   | 64-bit binary. OOB write. GOT overwrite                                    |
| [Labyrinth](HTB%20Cyber%20Apocalypse%202023/Pwn/Labyrinth)             | [solve.py](HTB%20Cyber%20Apocalypse%202023/Pwn/Labyrinth/solve.py)         | Python   | 64-bit binary. Buffer Overflow. Redirecting program execition              |
| [Math Door](HTB%20Cyber%20Apocalypse%202023/Pwn/Math%20Door)           | [solve.py](HTB%20Cyber%20Apocalypse%202023/Pwn/Math%20Door/solve.py)       | Python   | 64-bit binary. Heap exploitation. Heap _feng shui_. Tcache Poisoning. FSOP |
| [Pandora's Box](HTB%20Cyber%20Apocalypse%202023/Pwn/Pandora%27s%20Box) | [solve.py](HTB%20Cyber%20Apocalypse%202023/Pwn/Pandora%27s%20Box/solve.py) | Python   | 64-bit binary. Buffer Overflow. Ret2Libc                                   |
| [Void](HTB%20Cyber%20Apocalypse%202023/Pwn/Void)                       | [solve.py](HTB%20Cyber%20Apocalypse%202023/Pwn/Void/solve.py)              | Python   | 64-bit binary. Buffer Overflow. ret2dlresolve                              |


## HTB UniCTF

| Crypto                                             | Scripts / Programs                                     | Language          | Purpose                             |
| -------------------------------------------------- | ------------------------------------------------------ | ----------------- | ----------------------------------- |
| [AESWCM](HTB%20UniCTF/Crypto/AESWCM)               | [solve.py](HTB%20UniCTF/Crypto/AESWCM/solve.py)        | Python            | Custom encryption using AES and XOR |
| [Bank-er-smith](HTB%20UniCTF/Crypto/Bank-er-smith) | [solve.py](HTB%20UniCTF/Crypto/Bank-er-smith/solve.py) | Python / SageMath | RSA. Known bits. Coppersmith attack |

| Pwn                                                 | Scripts / Programs                                     | Language | Purpose                                                           |
| --------------------------------------------------- | ------------------------------------------------------ | -------- | ----------------------------------------------------------------- |
| [Sacred Scrolls](HTB%20UniCTF/Pwn/Sacred%20Scrolls) | [solve.py](HTB%20UniCTF/Pwn/Sacred%20Scrolls/solve.py) | Python   | 64-bit binary. Buffer Overflow. Ret2Libc                          |
| [Spellbook](HTB%20UniCTF/Pwn/Spellbook)             | [solve.py](HTB%20UniCTF/Pwn/Spellbook/solve.py)        | Python   | 64-bit binary. Heap exploitation. Use After Free. Fast Bin attack |

| Reversing                                               | Scripts / Programs                                          | Language | Purpose                              |
| ------------------------------------------------------- | ----------------------------------------------------------- | -------- | ------------------------------------ |
| [Potion Master](HTB%20UniCTF/Reversing/Potion%20Master) | [solve.py](HTB%20UniCTF/Reversing/Potion%20Master/solve.py) | Python   | `z3` solution to a set of conditions |

| Web                                                         | Scripts / Programs                                         | Language | Purpose                                                      |
| ----------------------------------------------------------- | ---------------------------------------------------------- | -------- | ------------------------------------------------------------ |
| [BatchCraft Potions](HTB%20UniCTF/Web/BatchCraft%20Potions) | [solve.py](HTB%20UniCTF/Web/BatchCraft%20Potions/solve.py) | Python   | GraphQL batching attack. Send XSS and DOM Clobbering payload |


## ImaginaryCTF

| Crypto                                                                                     | Scripts / Programs                                                              | Language | Purpose                                                                                |
| ------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------- | -------- | -------------------------------------------------------------------------------------- |
| [Easy DSA: Elated once](ImaginaryCTF/Crypto/Easy%20DSA:%20Elated%20once)                   | [solve.py](ImaginaryCTF/Crypto/Easy%20DSA:%20Elated%20once/solve.py)            | Python   | ImaginaryCTF 24/01/2023. 100 points. DSA. LCG. Modular system of equations             |
| [Easy DSA: Lovely Little Lane](ImaginaryCTF/Crypto/Easy%20DSA:%20Lovely%20Little%20Lane)   | [solve.py](ImaginaryCTF/Crypto/Easy%20DSA:%20Lovely%20Little%20Lane/solve.py)   | Python   | ImaginaryCTF 21/01/2023. 125 points. DSA. Hidden Number Problem. LLL lattice reduction |
| [Personalized](ImaginaryCTF/Crypto/Personalized)                                           | [solve.py](ImaginaryCTF/Crypto/Personalized/solve.py)                           | Python   | ImaginaryCTF 07/08/2022. 75 points. RSA. PRNG seed. CRT                                |
| [Rather Secure Attachment](ImaginaryCTF/Crypto/Rather%20Secure%20Attachment)               | [solve.py](ImaginaryCTF/Crypto/Rather%20Secure%20Attachment/solve.py)           | Python   | ImaginaryCTF 08/12/2022. 100 points. RSA. Cipolla's Algorithm                          |
| [Relatively Small Arguments](ImaginaryCTF/Crypto/Relatively%20Small%20Arguments)           | [solve.py](ImaginaryCTF/Crypto/Relatively%20Small%20Arguments/solve.py)         | Python   | ImaginaryCTF 14/07/2022. 75 points. RSA. Wiener's attack                               |
| [Ron was wrong, Whit is right](ImaginaryCTF/Crypto/Ron%20was%20wrong,%20Whit%20is%20right) | [solve.py](ImaginaryCTF/Crypto/Ron%20was%20wrong,%20Whit%20is%20right/solve.py) | Python   | ImaginaryCTF 28/11/2022. 75 points. RSA. Greatest Common Divisor. Bad PRNG             |
| [Rotating Secret Assembler](ImaginaryCTF/Crypto/Rotating%20Secret%20Assembler)             | [solve.py](ImaginaryCTF/Crypto/Rotating%20Secret%20Assembler/solve.py)          | Python   | ImaginaryCTF 05/07/2022. 50 points. RSA. Greatest Common Divisor                       |

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
| [zero_to_hero](picoCTF/Binary%20Exploitation/zero_to_hero)                             | [solve.py](picoCTF/Binary%20Exploitation/zero_to_hero/solve.py)                                                                                                                                         | Python                | picoCTF 2019. 500 points. 64-bit binary. Heap exploitation. Null byte poisoning. Tcache poisoning                             |
| [Guessing Game 1](picoCTF/Binary%20Exploitation/Guessing%20Game%201)                   | [solve.py](picoCTF/Binary%20Exploitation/Guessing%20Game%201/solve.py)                                                                                                                                  | Python                | picoCTF 2020 Mini-Competition. 250 points. 64-bit static binary. Buffer Overflow. ROP chain                                   |
| [Guessing Game 2](picoCTF/Binary%20Exploitation/Guessing%20Game%202)                   | [solve.py](picoCTF/Binary%20Exploitation/Guessing%20Game%202/solve.py)                                                                                                                                  | Python                | picoCTF 2020 Mini-Competition. 300 points. 32-bit binary. Buffer Overflow and Format String. Ret2Libc. Bypass ASLR and canary |
| [Bizz Fuzz](picoCTF/Binary%20Exploitation/Bizz%20Fuzz)                                 | [find_bof.py](picoCTF/Binary%20Exploitation/Bizz%20Fuzz/find_bof.py)<br>[solve.py](picoCTF/Binary%20Exploitation/Bizz%20Fuzz/solve.py)                                                                  | Python<br>Python      | picoCTF 2021. 500 points. 32-bit binary. Reversing. Long way to a hidden Buffer Overflow. Redirecting program execution       |
| [filtered-shellcode](picoCTF/Binary%20Exploitation/filtered-shellcode)                 | [code.asm](picoCTF/Binary%20Exploitation/filtered-shellcode/code.asm)                                                                                                                                   | Assembly              | picoCTF 2021. 160 points. 32-bit binary. Custom shellcode                                                                     |
| [Here's a LIBC](picoCTF/Binary%20Exploitation/Here's%20a%20LIBC)                       | [solve.py](picoCTF/Binary%20Exploitation/Here's%20a%20LIBC/solve.py)<br>[solve2.py](picoCTF/Binary%20Exploitation/Here's%20a%20LIBC/solve2.py)                                                          | Python<br>Python      | picoCTF 2021. 90 points. 64-bit binary. Buffer Overflow. Ret2Libc                                                             |
| [Stonks](picoCTF/Binary%20Exploitation/Stonks)                                         | [solve.py](picoCTF/Binary%20Exploitation/Stonks/solve.py)                                                                                                                                               | Python                | picoCTF 2021. 20 points. 32-bit binary. Format String. Memory leaks                                                           |
| [The Office](picoCTF/Binary%20Exploitation/The%20Office)                               | [canary.c](picoCTF/Binary%20Exploitation/The%20Office/canary.c)<br>[solve.py](picoCTF/Binary%20Exploitation/The%20Office/solve.py)<br>[solve2.py](picoCTF/Binary%20Exploitation/The%20Office/solve2.py) | C<br>Python<br>Python | picoCTF 2021. 400 points. 32-bit binary. Heap Exploitation. Heap overflow. PRNG. Use After Free                               |
| [Unsubscriptions Are Free](picoCTF/Binary%20Exploitation/Unsubscriptions%20Are%20Free) | [solve.py](picoCTF/Binary%20Exploitation/Unsubscriptions%20Are%20Free/solve.py)                                                                                                                         | Python                | picoCTF 2021. 100 points. 32-bit binary. Heap exploitation. Use After Free                                                    |
| [fermat-strings](picoCTF/Binary%20Exploitation/fermat-strings)                         | [solve.py](picoCTF/Binary%20Exploitation/fermat-strings/solve.py)                                                                                                                                       | Python                | picoMini by redpwn. 250 points. 64-bit binary. Format String. GOT overwrite and ASLR bypass                                   |
| [SaaS](picoCTF/Binary%20Exploitation/SaaS)                                             | [solve.py](picoCTF/Binary%20Exploitation/SaaS/solve.py)                                                                                                                                                 | Python                | picoMini by redpwn. 350 points. 64-bit binary. `seccomp` rules. Custom shellcode                                              |

| Cryptography                                      | Scripts / Programs                                     | Language | Purpose                                  |
| ------------------------------------------------- | ------------------------------------------------------ | -------- | ---------------------------------------- |
| [Sum-O-Primes](picoCTF/Cryptography/Sum-O-Primes) | [solve.py](picoCTF/Cryptography/Sum-O-Primes/solve.py) | Python   | picoCTF 2022. 400 points. RSA decryption |


## Securinets

| Crypto                                                      | Scripts / Programs                                       | Language | Purpose                                                                                            |
| ----------------------------------------------------------- | -------------------------------------------------------- | -------- | -------------------------------------------------------------------------------------------------- |
| [Farfour Post Quantom](Securinets/Farfour%20Post%20Quantom) | [solve.py](Securinets/Farfour%20Post%20Quantom/solve.py) | Python   | Securinets Quals 2023. Matrix operations. Modular arithmetic. Shuffling. Solve system of equations |
| [PolyLCG](Securinets/PolyLCG)                               | [solve.py](Securinets/PolyLCG/solve.py)                  | Python   | Securinets Quals 2023. Modular polynomials                                                         |

| Pwn                               | Scripts / Programs                        | Language | Purpose                                                                                         |
| --------------------------------- | ----------------------------------------- | -------- | ----------------------------------------------------------------------------------------------- |
| [scrambler](Securinets/scrambler) | [solve.py](Securinets/scrambler/solve.py) | Python   | Securinets Finals 2022. 64-bit binary. ROP. Ret2Libc. GOT overwrite. Stack Pivot. `seccomp` rules |


## SEETF

| Crypto                               | Scripts / Programs                        | Language | Purpose                               |
| ------------------------------------ | ----------------------------------------- | -------- | ------------------------------------- |
| [Close Enough](SEETF/Close%20Enough) | [solve.py](SEETF/Close%20Enough/solve.py) | Python   | SEETF 2022. RSA. Wrong implementation |

| Rev                          | Scripts / Programs                   | Language | Purpose                                      |
| ---------------------------- | ------------------------------------ | -------- | -------------------------------------------- |
| [babyreeee](SEETF/babyreeee) | [solve.py](SEETF/babyreeee/solve.py) | Python   | SEETF 2022. Revert encryption algorithm. XOR |


## Sekai CTF

| Crypto                                         | Scripts / Programs                                | Language          | Purpose                                                                                 |
| ---------------------------------------------- | ------------------------------------------------- | ----------------- | --------------------------------------------------------------------------------------- |
| [cryptoGRAPHy 1](Sekai%20CTF/cryptoGRAPHy%201) | [solve.py](Sekai%20CTF/cryptoGRAPHy%201/solve.py) | Python            | Sekai CTF 2023. Graph Encryption Scheme. Key leakage. Decryption                        |
| [cryptoGRAPHy 2](Sekai%20CTF/cryptoGRAPHy%202) | [solve.py](Sekai%20CTF/cryptoGRAPHy%202/solve.py) | Python            | Sekai CTF 2023. Graph Encryption Scheme. Single-Destination Shortest Path. Node degrees |
| [cryptoGRAPHy 3](Sekai%20CTF/cryptoGRAPHy%203) | [solve.py](Sekai%20CTF/cryptoGRAPHy%203/solve.py) | Python            | Sekai CTF 2023. Graph Encryption Scheme. Query recovery. Tree isomorphisms              |
| [Noisy CRC](Sekai%20CTF/Noisy%20CRC)           | [solve.py](Sekai%20CTF/Noisy%20CRC/solve.py)      | Python / SageMath | Sekai CTF 2023. CRC. Chinese Remainder Theorem. Brute force                             |
