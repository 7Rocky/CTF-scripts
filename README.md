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


## corCTF

| Crypto                            | Scripts / Programs                      | Language          | Purpose                                                  |
| --------------------------------- | --------------------------------------- | ----------------- | -------------------------------------------------------- |
| [fizzbuzz101](corCTF/fizzbuzz101) | [solve.py](corCTF/fizzbuzz101/solve.py) | Python            | corCTF 2023. RSA decryption. LSB oracle                  |
| [fizzbuzz102](corCTF/fizzbuzz102) | [solve.py](corCTF/fizzbuzz102/solve.py) | Python            | corCTF 2023. RSA decryption. LSB oracle. LCG             |
| [qcg-k](corCTF/qcg-k)             | [solve.py](corCTF/qcg-k/solve.py)       | Python / SageMath | corCTF 2023. DSA. Recurrence relation. Nonces            |
| [two-wrongs](corCTF/two-wrongs)   | [solve.py](corCTF/two-wrongs/solve.py)  | Python            | corCTF 2024. Quantum Computing. Quantum Error Correction |


## CrewCTF

| Crypto                                                         | Scripts / Programs                                                   | Language          | Purpose                                                            |
| -------------------------------------------------------------- | -------------------------------------------------------------------- | ----------------- | ------------------------------------------------------------------ |
| [4ES](CrewCTF/4ES)                                             | [solve.go](CrewCTF/4ES/solve.go)<br>[solve.py](CrewCTF/4ES/solve.py) | Go<br>Python      | CrewCTF 2024. AES. Meet-in-the-middle                              |
| [Read between the lines](CrewCTF/Read%20between%20the%20lines) | [solve.py](CrewCTF/Read%20between%20the%20lines/solve.py)            | Python / SageMath | CrewCTF 2024. RSA. Integer linear relations. LLL lattice reduction |


| Pwn                                      | Scripts / Programs                           | Language | Purpose                                                             |
| ---------------------------------------- | -------------------------------------------- | -------- | ------------------------------------------------------------------- |
| [Format muscle](CrewCTF/Format%20muscle) | [solve.py](CrewCTF/Format%20muscle/solve.py) | Python   | CrewCTF 2024. Format String vulnerability. musl libc. Exit handlers |


## CTFlearn

| Binary                                              | Scripts / Programs                                                                                         | Language         | Purpose                                                           |
| --------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- | ---------------- | ----------------------------------------------------------------- |
| [Favourite Color](CTFlearn/Binary/Favorite%20Color) | [solve.py](CTFlearn/Binary/Favorite%20Color/solve.py)                                                      | Python           | 32-bit binary. Buffer Overflow. Calling a function with arguments |
| [Shell time!](CTFlearn/Binary/Shell%20time!)        | [solve.py](CTFlearn/Binary/Shell%20time!/solve.py)<br>[solve2.py](CTFlearn/Binary/Shell%20time!/solve2.py) | Python<br>Python | 32-bit binary. Buffer Overflow. ret2libc                          |

| Programming                                                | Scripts / Programs                                                                                                       | Language     | Purpose                                               |
| ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ | ------------ | ----------------------------------------------------- |
| [Simple Programming](CTFlearn/Binary/Simple%20Programming) | [solve.rb](CTFlearn/Binary/Simple%20Programming/solve.rb)<br>[solve2.rb](CTFlearn/Binary/Simple%20Programming/solve2.rb) | Ruby<br>Ruby | Iterate a file and count lines that match a condition |


## CTFZone

| Crypto                                                           | Scripts / Programs                                          | Language          | Purpose                                                                                |
| ---------------------------------------------------------------- | ----------------------------------------------------------- | ----------------- | -------------------------------------------------------------------------------------- |
| [Come on feel the nonce](CTFZone/Come%20on%20feel%20the%20nonce) | [solve.py](CTFZone/Come%20on%20feel%20the%20nonce/solve.py) | Python / SageMath | CTFZone 2023 Quals. ECDSA. Biased nonces. Hidden Number Problem. LLL lattice reduction |
| [Right Decision](CTFZone/Right%20Decision)                       | [solve.py](CTFZone/Right%20Decision/solve.py)               | Python            | CTFZone 2023 Quals. Shamir Secret Sharing. System of equations                         |


## DiceCTF

| Crypto                           | Scripts / Programs                      | Language          | Purpose                                                            |
| -------------------------------- | --------------------------------------- | ----------------- | ------------------------------------------------------------------ |
| [rps-casino](DiceCTF/rps-casino) | [solve.py](DiceCTF/rps-casino/solve.py) | Python            | DiceCTF 2024 Quals. LFSR. Modular arithmetic. `z3`                 |
| [winter](DiceCTF/winter)         | [solve.py](DiceCTF/winter/solve.py)     | Python            | DiceCTF 2024 Quals. Winternitz One-Time Signature                  |
| [yaonet](DiceCTF/yaonet)         | [solve.py](DiceCTF/yaonet/solve.py)     | Python / SageMath | DiceCTF 2024 Quals. ECC. Baby-step, giant-step. Meet-in-the-middle |

| Pwn                            | Scripts / Programs                     | Language  | Purpose                                                                                       |
| ------------------------------ | -------------------------------------- | --------- | --------------------------------------------------------------------------------------------- |
| [baby-talk](DiceCTF/baby-talk) | [solve.py](DiceCTF/baby-talk/solve.py) | Python    | DiceCTF 2024 Quals. Heap exploitation. Null-byte poison. Overlapping chunks. Tcache poisoning |
| [oboe](DiceCTF/oboe)           | [solve.c](DiceCTF/oboe/solve.c)        | C         | DiceCTF 2025 Quals. Kernel exploitation. Heap exploitation. Off-by-one. Use After Free. ROP   |


## ECSC 2023

| Crypto                                                   | Scripts / Programs                                        | Language          | Purpose                                                   |
| -------------------------------------------------------- | --------------------------------------------------------- | ----------------- | --------------------------------------------------------- |
| [Blind](ECSC%202023/Blind)                               | [solve.sage](ECSC%202023/Blind/solve.sage)                | SageMath          | ECDSA. Signature verification. XOR                        |
| [Hide and seek](ECSC%202023/Hide%20and%20seek)           | [solve.py](ECSC%202023/Hide%20and%20seek/solve.py)        | Python / SageMath | ECC. Point arithmetic. Discrete logarithm. Pohlig-Hellman |
| [Irish flan](ECSC%202023/Irish%20flan)                   | [solve.py](ECSC%202023/Irish%20flan/solve.py)             | Python / SageMath | Quaternions. Matrix equations. Kernel                     |
| [Kernel searcher](ECSC%202023/Kernel%20searcher)         | [solve.py](ECSC%202023/Kernel%20searcher/solve.py)        | Python / SageMath | Isogeny. Finding curve parameters. Discrete logarithm     |
| [not crypto](ECSC%202023/not%20crypto)                   | [solve.py](ECSC%202023/not%20crypto/solve.py)             | Python            | ROT13. Base64 encoding. ASCII bytes                       |
| [Put a ring on it](ECSC%202023/Put%20a%20ring%20on%20it) | [solve.py](ECSC%202023/Put%20a%20ring%20on%20it/solve.py) | Python            | Ring signature. Oracle                                    |
| [RRSSAA](ECSC%202023/RRSSAA)                             | [solve.py](ECSC%202023/RRSSAA/solve.py)                   | Python            | Multi-prime RSA. PRNG seed. RSA-CRT decryption            |
| [Tough decisions](ECSC%202023/Tough%20decisions)         | [solve.py](ECSC%202023/Tough%20decisions/solve.py)        | Python / SageMath | Learning With Errors. Modular arithmetic                  |
| [Twist and shout](ECSC%202023/Twist%20and%20shout)       | [solve.py](ECSC%202023/Twist%20and%20shout/solve.py)      | Python / SageMath | ECC. Invalid Curve Attack. Quadratic Twist                |
| [WOTS up](ECSC%202023/WOTS%20up)                         | [solve.py](ECSC%202023/WOTS%20up/solve.py)                | Python            | Winternitz One-Time Signature. Hash functions. Induction  |
| [WOTS up 2](ECSC%202023/WOTS%20up%202)                   | [solve.py](ECSC%202023/WOTS%20up%202/solve.py)            | Python            | Winternitz One-Time Signature. Hash functions             |


## Hack.lu CTF

| Crypto                                           | Scripts / Programs                                  | Language          | Purpose                                                                                                        |
| ------------------------------------------------ | --------------------------------------------------- | ----------------- | -------------------------------------------------------------------------------------------------------------- |
| [Spooky Safebox](Hack.lu%20CTF/Spooky%20Safebox) | [solve.py](Hack.lu%20CTF/Spooky%20Safebox/solve.py) | Python / SageMath | Hack.lu CTF 2023. ECC. ECDSA. Public key recovery. Biased nonces. Hidden Number Problem. LLL lattice reduction |


## HackOn CTF

| Crypto                                                        | Scripts / Programs                                                                                             | Language                    | Purpose                                                                                                     |
| ------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------- | ----------------------------------------------------------------------------------------------------------- |
| [Jorge Wants a Token](HackOn%20CTF/Jorge%20Wants%20a%20Token) | [solve.py](HackOn%20CTF/Jorge%20Wants%20a%20Token/solve.py)                                                    | Python / SageMath           | HackOn CTF 2024. JWT. ECDSA biased nonces. Hidden Number Problem. LLL lattice reduction. Discrete logarithm |
| [Pederson](HackOn%20CTF/Pederson)                             | [solve.py](HackOn%20CTF/Pederson/solve.py)                                                                     | Python                      | HackOn CTF 2025. Modular arithmetic. Xoshiro256**. LFSR. `z3` solver                                        |
| [Play Time](HackOn%20CTF/Play%20Time)                         | [solve_sage.py](HackOn%20CTF/Play%20Time/solve_sage.py)<br>[solve_z3.py](HackOn%20CTF/Play%20Time/solve_z3.py) | Python / SageMath<br>Python | HackOn CTF 2025. Zero-knowledge proof. Pedersen commitment                                                  |
| [RSACBC](HackOn%20CTF/RSACBC)                                 | [solve.py](HackOn%20CTF/RSACBC/solve.py)                                                                       | Python                      | HackOn CTF 2025. RSA. XOR. Binomial theorem. GCD                                                            |

| Pwn                                                                     | Scripts / Programs                                                                                                                                         | Language         | Purpose                                                                                               |
| ----------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------- | ----------------------------------------------------------------------------------------------------- |
| [Baby Note(streses)](HackOn%20CTF/Baby%20Note(streses))                 | [solve.py](HackOn%20CTF/Baby%20Note(streses)/solve.py)                                                                                                     | Python           | HackOn CTF 2025. OOB. Buffer Overflow. Canary bypass. ret2libc                                        |
| [BOF that's too ez](HackOn%20CTF/BOF%20that%27s%20too%20ez)             | [solve_manual.py](HackOn%20CTF/BOF%20that%27s%20too%20ez/solve_manual.py)<br>[solve_pwntools.py](HackOn%20CTF/BOF%20that%27s%20too%20ez/solve_pwntools.py) | Python<br>Python | HackOn CTF 2025. Buffer Overflow. ROP. Stack Pivot. ret2dlresolve                                     |
| [Note Father - Redemption](HackOn%20CTF/Note%20Father%20-%20Redemption) | [solve.py](HackOn%20CTF/Note%20Father%20-%20Redemption/solve.py)                                                                                           | Python           | HackOn CTF 2025. Heap exploitation. Tcache poisoning. TLS-Storage `dtor_list`                         |
| [Kerbab](HackOn%20CTF/Kerbab)                                           | [exploit.c](HackOn%20CTF/Kerbab/exploit.c)                                                                                                                 | C                | HackOn CTF 2024. Kernel exploitation. Heap exploitation. Off-by-one. `seccomp` rules                  |
| [Noleak](HackOn%20CTF/Noleak)                                           | [solve.py](HackOn%20CTF/Noleak/solve.py)                                                                                                                   | Python           | HackOn CTF 2024. Buffer Overflow. ROP. ret2dlresolve                                                  |
| [Quememu](HackOn%20CTF/Quememu)                                         | [exploit.c](HackOn%20CTF/Quememu/exploit.c)                                                                                                                | C                | HackOn CTF 2024. PCI device. MMIO. `qemu` escape. OOB read and write. `mprotect` and shellcode        |

| Web                                 | Scripts / Programs                           | Language | Purpose                                                |
| ----------------------------------- | -------------------------------------------- | -------- | ------------------------------------------------------ |
| [Guglu v2](HackOn%20CTF/Guglu%20v2) | [solve.py](HackOn%20CTF/Guglu%20v2/solve.py) | Python   | HackOn CTF 2024. Flag exfiltration with boolean oracle |


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

| Crypto                                              | Scripts / Programs                                   | Language          | Purpose                                                                                                            |
| --------------------------------------------------- | ---------------------------------------------------- | ----------------- | ------------------------------------------------------------------------------------------------------------------ |
| [Careless Padding](HITCON%20CTF/Careless%20Padding) | [solve.py](HITCON%20CTF/Careless%20Padding/solve.py) | Python            | HITCON CTF Quals 2023. Padding Oracle Attack. Custom padding. Guessing                                             |
| [Share](HITCON%20CTF/Share)                         | [solve.py](HITCON%20CTF/Share/solve.py)              | Python / SageMath | HITCON CTF Quals 2023. Shamir Secret Sharing. Lagrange interpolation. Chinese Remainder Theorem. `multiprocessing` |


## HTB Cyber Apocalypse

| Crypto                                                                                              | Scripts / Programs                                                                  | Language          | Purpose                                                                                                           |
| --------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- | ----------------- | ----------------------------------------------------------------------------------------------------------------- |
| [Biased Heritage](HTB%20Cyber%20Apocalypse/Crypto/Biased%20Heritage)                                | [solve.py](HTB%20Cyber%20Apocalypse/Crypto/Biased%20Heritage/solve.py)              | Python / SageMath | HTB CA 2023. Schnorr signature. Hidden Number Problem. LLL lattice reduction                                      |
| [Colliding Heritage](HTB%20Cyber%20Apocalypse/Crypto/Colliding%20Heritage)                          | [solve.py](HTB%20Cyber%20Apocalypse/Crypto/Colliding%20Heritage/solve.py)           | Python            | HTB CA 2023. Schnorr signature. MD5 collision                                                                     |
| [Converging Visions](HTB%20Cyber%20Apocalypse/Crypto/Converging%20Visions)                          | [solve.py](HTB%20Cyber%20Apocalypse/Crypto/Converging%20Visions/solve.py)           | Python / SageMath | HTB CA 2023. ECC. Binary search. Finding curve parameters. Smart's attack. PRNG                                   |
| [Copperbox](HTB%20Cyber%20Apocalypse/Crypto/Copperbox)                                              | [solve.sage](HTB%20Cyber%20Apocalypse/Crypto/Copperbox/solve.sage)                  | SageMath          | HTB CA 2025. Truncated LCG. Coppersmith method on a bivariate polynomial                                          |
| [Elliptic Labyrinth](HTB%20Cyber%20Apocalypse/Crypto/Elliptic%20Labyrinth)                          | [solve.py](HTB%20Cyber%20Apocalypse/Crypto/Elliptic%20Labyrinth/solve.py)           | Python            | HTB CA 2023. ECC. Finding curve parameters                                                                        |
| [Elliptic Labyrinth Revenge](HTB%20Cyber%20Apocalypse/Crypto/Elliptic%20Labyrinth%20Revenge)        | [solve.py](HTB%20Cyber%20Apocalypse/Crypto/Elliptic%20Labyrinth%20Revenge/solve.py) | Python / SageMath | HTB CA 2023. ECC. Finding curve parameters. Coppersmith method on a bivariate polynomial                          |
| [Hourcle](HTB%20Cyber%20Apocalypse/Crypto/Hourcle)                                                  | [solve.go](HTB%20Cyber%20Apocalypse/Crypto/Hourcle/solve.go)                        | Go                | HTB CA 2023. AES CBC. Decryption oracle                                                                           |
| [Partial Tenacity](HTB%20Cyber%20Apocalypse/Crypto/Partial%20Tenacity)                              | [solve.py](HTB%20Cyber%20Apocalypse/Crypto/Partial%20Tenacity/solve.py)             | Python            | HTB CA 2024. RSA. Partially-known private information. Modular arithmetic                                         |
| [Tsayaki](HTB%20Cyber%20Apocalypse/Crypto/Tsayaki)                                                  | [solve.py](HTB%20Cyber%20Apocalypse/Crypto/Tsayaki/solve.py)                        | Python            | HTB CA 2024. TEA. Equivalent keys. CBC mode                                                                       |
| [Twin Oracles](HTB%20Cyber%20Apocalypse/Crypto/Twin%20Oracles)                                      | [solve.py](HTB%20Cyber%20Apocalypse/Crypto/Twin%20Oracles/solve.py)                 | Python            | HTB CA 2025. RSA. PRNG. LSB and MSB oracles                                                                       |
| [Verilicious](HTB%20Cyber%20Apocalypse/Crypto/Verilicious)                                          | [solve.py](HTB%20Cyber%20Apocalypse/Crypto/Verilicious/solve.py)                    | Python / SageMath | HTB CA 2025. RSA PKCS#1 v1.5. Padding Oracle. Bleichenbacher attack. Hidden Number Problem. LLL lattice reduction |

| Hardware                                              | Scripts / Programs                                          | Language | Purpose                                                                              |
| ----------------------------------------------------- | ----------------------------------------------------------- | -------- | ------------------------------------------------------------------------------------ |
| [HM74](HTB%20Cyber%20Apocalypse/Hardware/HM74)        | [solve.py](HTB%20Cyber%20Apocalypse/Hardware/HM74/solve.py) | Python   | HTB CA 2023. Noisy channel. Hamming codes. Statistically find correct message blocks |

| Misc                                                                   | Scripts / Programs                                                      | Language | Purpose                                                               |
| ---------------------------------------------------------------------- | ----------------------------------------------------------------------- | -------- | --------------------------------------------------------------------- |
| [Calibrator](HTB%20Cyber%20Apocalypse/Misc/Calibrator)                 | [solve.py](HTB%20Cyber%20Apocalypse/Misc/Calibrator/solve.py)           | Python   | HTB CA 2023. Binary search. Euclidean distance                        |
| [Path of Survival](HTB%20Cyber%20Apocalypse/Misc/Path%20of%20Survival) | [solve.py](HTB%20Cyber%20Apocalypse/Misc/Path%20of%20Survival/solve.py) | Python   | HTB CA 2024. Path-finding. Breadth-first Search. Dijkstra's algorithm |

| Pwn                                                                    | Scripts / Programs                                                  | Language | Purpose                                                                                                                       |
| ---------------------------------------------------------------------- | ------------------------------------------------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------- |
| [Control Room](HTB%20Cyber%20Apocalypse/Pwn/Control%20Room)            | [solve.py](HTB%20Cyber%20Apocalypse/Pwn/Control%20Room/solve.py)    | Python   | HTB CA 2023. 64-bit binary. OOB write. GOT overwrite                                                                          |
| [Crossbow](HTB%20Cyber%20Apocalypse/Pwn/Crossbow)                      | [solve.py](HTB%20Cyber%20Apocalypse/Pwn/Crossbow/solve.py)          | Python   | HTB CA 2025. 64-bit binary. OOB. Buffer Overflow. ROP. `sys_execve`                                                           |
| [Labyrinth](HTB%20Cyber%20Apocalypse/Pwn/Labyrinth)                    | [solve.py](HTB%20Cyber%20Apocalypse/Pwn/Labyrinth/solve.py)         | Python   | HTB CA 2023. 64-bit binary. Buffer Overflow. Redirecting program execition                                                    |
| [Gloater](HTB%20Cyber%20Apocalypse/Pwn/Gloater)                        | [solve.py](HTB%20Cyber%20Apocalypse/Pwn/Gloater/solve.py)           | Python   | HTB CA 2024. 64-bit binary. Heap exploitation. House of Spirit. Overlapping chunks. Tcache poisoning. TLS-Storage `dtor_list` |
| [Maze of Mist](HTB%20Cyber%20Apocalypse/Pwn/Maze%20of%20Mist)          | [solve.py](HTB%20Cyber%20Apocalypse/Pwn/Maze%20of%20Mist/solve.py)  | Python   | HTB CA 2024. 32-bit binary. Buffer Overflow. vDSO ROP. `sys_execve`                                                           |
| [Math Door](HTB%20Cyber%20Apocalypse/Pwn/Math%20Door)                  | [solve.py](HTB%20Cyber%20Apocalypse/Pwn/Math%20Door/solve.py)       | Python   | HTB CA 2023. 64-bit binary. Heap exploitation. Heap _feng shui_. Tcache poisoning. `FILE` structure attack                    |
| [Oracle](HTB%20Cyber%20Apocalypse/Pwn/Oracle)                          | [solve.py](HTB%20Cyber%20Apocalypse/Pwn/Oracle/solve.py)            | Python   | HTB CA 2024. 64-bit binary. Heap exploitation. Buffer Overflow. ROP                                                           |
| [Pandora's Box](HTB%20Cyber%20Apocalypse/Pwn/Pandora%27s%20Box)        | [solve.py](HTB%20Cyber%20Apocalypse/Pwn/Pandora%27s%20Box/solve.py) | Python   | HTB CA 2023. 64-bit binary. Buffer Overflow. ret2libc                                                                         |
| [Quack Quack](HTB%20Cyber%20Apocalypse/Pwn/Quack%20Quack)              | [solve.py](HTB%20Cyber%20Apocalypse/Pwn/Quack%20Quack/solve.py)     | Python   | HTB CA 2025. 64-bit binary. Buffer Overflow. Canary bypass. Redirecting program execition                                     |
| [Void](HTB%20Cyber%20Apocalypse/Pwn/Void)                              | [solve.py](HTB%20Cyber%20Apocalypse/Pwn/Void/solve.py)              | Python   | HTB CA 2023. 64-bit binary. Buffer Overflow. ret2dlresolve                                                                    |


## HTB UniCTF

| Crypto                                               | Scripts / Programs                                           | Language          | Purpose                                                                                    |
| ---------------------------------------------------- | ------------------------------------------------------------ | ----------------- | ------------------------------------------------------------------------------------------ |
| [AESWCM](HTB%20UniCTF/Crypto/AESWCM)                 | [solve.py](HTB%20UniCTF/Crypto/AESWCM/solve.py)              | Python            | HTB UniCTF 2022. Custom encryption using AES and XOR                                       |
| [Bank-er-smith](HTB%20UniCTF/Crypto/Bank-er-smith)   | [solve.py](HTB%20UniCTF/Crypto/Bank-er-smith/solve.py)       | Python / SageMath | HTB UniCTF 2022. RSA. Known bits. Coppersmith attack                                       |
| [Clutch](HTB%20UniCTF/Crypto/Clutch)                 | [solve.py](HTB%20UniCTF/Crypto/Clutch/solve.py)              | Python            | HTB UniCTF 2024. Quantum Criptography. Frame-based Quantum Key Distribution                |
| [Mayday Mayday](HTB%20UniCTF/Crypto/Mayday%20Mayday) | [solve.py](HTB%20UniCTF/Crypto/Mayday%20Mayday/solve.py)     | Python / SageMath | HTB UniCTF 2023. RSA-CRT. Modular arithmetic. Coppersmith method                           |
| [MSS Revenge](HTB%20UniCTF/Crypto/MSS%20Revenge)     | [solve.py](HTB%20UniCTF/Crypto/MSS%20Revenge/solve.py)       | Python            | HTB UniCTF 2023. Mignotte Secret Sharing. Modular arithmetic. Chinese Remainder Theorem    |
| [Zombie Rolled](HTB%20UniCTF/Crypto/Zombie%20Rolled) | [solve.sage](HTB%20UniCTF/Crypto/Zombie%20Rolled/solve.sage) | SageMath          | HTB UniCTF 2023. Fractions. GCD. RSA signature. Coppersmith method on bivariate polynomial |

| Pwn                                                           | Scripts / Programs                                           | Language | Purpose                                                                                                                                             |
| ------------------------------------------------------------- | ------------------------------------------------------------ | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| [Dead or Alive](HTB%20UniCTF/Pwn/Dead%20or%20Alive)           | [solve.py](HTB%20UniCTF/Pwn/Dead%20or%20Alive/solve.py)      | Python   | HTB UniCTF 2024. 64-bit binary. Heap exploitation. House of Spirit. Heap _feng-shui_. Overlapping chunks. Tcache poisoning. TLS-storage `dtor_list` |
| [Great Old Talisman](HTB%20UniCTF/Pwn/Great%20Old%20Talisman) | [solve.py](HTB%20UniCTF/Pwn/Great%20Old%20Talisman/solve.py) | Python   | HTB UniCTF 2023. 64-bit binary. OOB write. Partial GOT overwrite                                                                                    |
| [Sacred Scrolls](HTB%20UniCTF/Pwn/Sacred%20Scrolls)           | [solve.py](HTB%20UniCTF/Pwn/Sacred%20Scrolls/solve.py)       | Python   | HTB UniCTF 2022. 64-bit binary. Buffer Overflow. ret2libc                                                                                           |
| [Spellbook](HTB%20UniCTF/Pwn/Spellbook)                       | [solve.py](HTB%20UniCTF/Pwn/Spellbook/solve.py)              | Python   | HTB UniCTF 2022. 64-bit binary. Heap exploitation. Use After Free. Fast Bin attack                                                                  |
| [Zombiedote](HTB%20UniCTF/Pwn/Zombiedote)                     | [solve.py](HTB%20UniCTF/Pwn/Zombiedote/solve.py)             | Python   | HTB UniCTF 2023. 64-bit binary. Heap exploitation. OOB read and write. Integer Overflow. Floating-point numbers. TLS-storage `dtor_list`            |
| [Zombienator](HTB%20UniCTF/Pwn/Zombienator)                   | [solve.py](HTB%20UniCTF/Pwn/Zombienator/solve.py)            | Python   | HTB UniCTF 2023. 64-bit binary. Heap exploitation. Buffer Overflow. Floating-point numbers. Canary bypass. ret2libc. Oracle                         |

| Reversing                                               | Scripts / Programs                                          | Language | Purpose                                               |
| ------------------------------------------------------- | ----------------------------------------------------------- | -------- | ----------------------------------------------------- |
| [Potion Master](HTB%20UniCTF/Reversing/Potion%20Master) | [solve.py](HTB%20UniCTF/Reversing/Potion%20Master/solve.py) | Python   | HTB UniCTF 2022. `z3` solution to a set of conditions |

| Web                                                         | Scripts / Programs                                         | Language | Purpose                                                                       |
| ----------------------------------------------------------- | ---------------------------------------------------------- | -------- | ----------------------------------------------------------------------------- |
| [BatchCraft Potions](HTB%20UniCTF/Web/BatchCraft%20Potions) | [solve.py](HTB%20UniCTF/Web/BatchCraft%20Potions/solve.py) | Python   | HTB UniCTF 2022. GraphQL batching attack. Send XSS and DOM Clobbering payload |
| [Breaking Bank](HTB%20UniCTF/Web/Breaking%20Bank)           | [solve.py](HTB%20UniCTF/Web/Breaking%20Bank/solve.py)      | Python   | HTB UniCTF 2024. Open Redirect. JWKS and JWT forgery. OTP bypass              |


## ImaginaryCTF

| Crypto                                                                                     | Scripts / Programs                                                              | Language          | Purpose                                                                                |
| ------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------- | ----------------- | -------------------------------------------------------------------------------------- |
| [Easy DSA: Elated once](ImaginaryCTF/Crypto/Easy%20DSA:%20Elated%20once)                   | [solve.py](ImaginaryCTF/Crypto/Easy%20DSA:%20Elated%20once/solve.py)            | Python            | ImaginaryCTF 24/01/2023. 100 points. DSA. LCG. Modular system of equations             |
| [Easy DSA: Lovely Little Lane](ImaginaryCTF/Crypto/Easy%20DSA:%20Lovely%20Little%20Lane)   | [solve.py](ImaginaryCTF/Crypto/Easy%20DSA:%20Lovely%20Little%20Lane/solve.py)   | Python / SageMath | ImaginaryCTF 21/01/2023. 125 points. DSA. Hidden Number Problem. LLL lattice reduction |
| [Personalized](ImaginaryCTF/Crypto/Personalized)                                           | [solve.py](ImaginaryCTF/Crypto/Personalized/solve.py)                           | Python / SageMath | ImaginaryCTF 07/08/2022. 75 points. RSA. PRNG seed. CRT                                |
| [Rather Secure Attachment](ImaginaryCTF/Crypto/Rather%20Secure%20Attachment)               | [solve.py](ImaginaryCTF/Crypto/Rather%20Secure%20Attachment/solve.py)           | Python            | ImaginaryCTF 08/12/2022. 100 points. RSA. Cipolla's Algorithm                          |
| [Relatively Small Arguments](ImaginaryCTF/Crypto/Relatively%20Small%20Arguments)           | [solve.py](ImaginaryCTF/Crypto/Relatively%20Small%20Arguments/solve.py)         | Python            | ImaginaryCTF 14/07/2022. 75 points. RSA. Wiener's attack                               |
| [Ron was wrong, Whit is right](ImaginaryCTF/Crypto/Ron%20was%20wrong,%20Whit%20is%20right) | [solve.py](ImaginaryCTF/Crypto/Ron%20was%20wrong,%20Whit%20is%20right/solve.py) | Python            | ImaginaryCTF 28/11/2022. 75 points. RSA. Greatest Common Divisor. Bad PRNG             |
| [Rotating Secret Assembler](ImaginaryCTF/Crypto/Rotating%20Secret%20Assembler)             | [solve.py](ImaginaryCTF/Crypto/Rotating%20Secret%20Assembler/solve.py)          | Python            | ImaginaryCTF 05/07/2022. 50 points. RSA. Greatest Common Divisor                       |

| Pwn                                                                 | Scripts / Programs                                               | Language | Purpose                                                                                              |
| ------------------------------------------------------------------- | ---------------------------------------------------------------- | -------- | ---------------------------------------------------------------------------------------------------- |
| [Notepad as a Service](ImaginaryCTF/Pwn/Notepad%20as%20a%20Service) | [solve.py](ImaginaryCTF/Pwn/Notepad%20as%20a%20Service/solve.py) | Python   | ImaginaryCTF 11/07/2022. 75 points. 64-bit binary. Buffer Overflow. ret2libc. Canary and ASLR bypass |
| [show-me-what-you-got](ImaginaryCTF/Pwn/show-me-what-you-got)       | [solve.py](ImaginaryCTF/Pwn/show-me-what-you-got/solve.py)       | Python   | ImaginaryCTF 08/08/2022. 75 points. 64-bit binary. Format String vulnerability. GOT overwrite        |

| Reversing                               | Scripts / Programs                                 | Language | Purpose                                                          |       
| --------------------------------------- | -------------------------------------------------- | -------- | ---------------------------------------------------------------- |
| [xorrot](ImaginaryCTF/Reversing/xorrot) | [solve.py](ImaginaryCTF/Reversing/xorrot/solve.py) | Python   | ImaginaryCTF 07/07/2022. 50 points. XOR cipher with rotating key |


## m0leCon CTF

| Reversing                            | Scripts / Programs                            | Language | Purpose                                                            |
| ------------------------------------ | --------------------------------------------- | -------- | ------------------------------------------------------------------ |
| [Go Sweep](m0leCon%20CTF/Go%20Sweep) | [solve.go](m0leCon%20CTF/Go%20Sweep/solve.go) | Go       | m0lecon CTF 2025 Teaser. Go binary. PRNG. Time-based seed. Threads |


## picoCTF

| Binary Exploitation                                                                    | Scripts / Programs                                                                                                                                                                                      | Language              | Purpose                                                                                                                       |
| -------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| [seed-sPRiNG](picoCTF/Binary%20Exploitation/seed-sPRiNG)                               | [prng.c](picoCTF/Binary%20Exploitation/seed-sPRiNG/prng.c)                                                                                                                                              | C                     | picoCTF 2019. 350 points. 32-bit binary. PRNG                                                                                 |
| [zero_to_hero](picoCTF/Binary%20Exploitation/zero_to_hero)                             | [solve.py](picoCTF/Binary%20Exploitation/zero_to_hero/solve.py)                                                                                                                                         | Python                | picoCTF 2019. 500 points. 64-bit binary. Heap exploitation. Null byte poisoning. Tcache poisoning                             |
| [Guessing Game 1](picoCTF/Binary%20Exploitation/Guessing%20Game%201)                   | [solve.py](picoCTF/Binary%20Exploitation/Guessing%20Game%201/solve.py)                                                                                                                                  | Python                | picoCTF 2020 Mini-Competition. 250 points. 64-bit static binary. Buffer Overflow. ROP chain                                   |
| [Guessing Game 2](picoCTF/Binary%20Exploitation/Guessing%20Game%202)                   | [solve.py](picoCTF/Binary%20Exploitation/Guessing%20Game%202/solve.py)                                                                                                                                  | Python                | picoCTF 2020 Mini-Competition. 300 points. 32-bit binary. Buffer Overflow and Format String. ret2libc. Bypass ASLR and canary |
| [Bizz Fuzz](picoCTF/Binary%20Exploitation/Bizz%20Fuzz)                                 | [find_bof.py](picoCTF/Binary%20Exploitation/Bizz%20Fuzz/find_bof.py)<br>[solve.py](picoCTF/Binary%20Exploitation/Bizz%20Fuzz/solve.py)                                                                  | Python<br>Python      | picoCTF 2021. 500 points. 32-bit binary. Reversing. Long way to a hidden Buffer Overflow. Redirecting program execution       |
| [filtered-shellcode](picoCTF/Binary%20Exploitation/filtered-shellcode)                 | [code.asm](picoCTF/Binary%20Exploitation/filtered-shellcode/code.asm)                                                                                                                                   | Assembly              | picoCTF 2021. 160 points. 32-bit binary. Custom shellcode                                                                     |
| [Here's a LIBC](picoCTF/Binary%20Exploitation/Here's%20a%20LIBC)                       | [solve.py](picoCTF/Binary%20Exploitation/Here's%20a%20LIBC/solve.py)<br>[solve2.py](picoCTF/Binary%20Exploitation/Here's%20a%20LIBC/solve2.py)                                                          | Python<br>Python      | picoCTF 2021. 90 points. 64-bit binary. Buffer Overflow. ret2libc                                                             |
| [Stonks](picoCTF/Binary%20Exploitation/Stonks)                                         | [solve.py](picoCTF/Binary%20Exploitation/Stonks/solve.py)                                                                                                                                               | Python                | picoCTF 2021. 20 points. 32-bit binary. Format String. Memory leaks                                                           |
| [The Office](picoCTF/Binary%20Exploitation/The%20Office)                               | [canary.c](picoCTF/Binary%20Exploitation/The%20Office/canary.c)<br>[solve.py](picoCTF/Binary%20Exploitation/The%20Office/solve.py)<br>[solve2.py](picoCTF/Binary%20Exploitation/The%20Office/solve2.py) | C<br>Python<br>Python | picoCTF 2021. 400 points. 32-bit binary. Heap Exploitation. Heap overflow. PRNG. Use After Free                               |
| [Unsubscriptions Are Free](picoCTF/Binary%20Exploitation/Unsubscriptions%20Are%20Free) | [solve.py](picoCTF/Binary%20Exploitation/Unsubscriptions%20Are%20Free/solve.py)                                                                                                                         | Python                | picoCTF 2021. 100 points. 32-bit binary. Heap exploitation. Use After Free                                                    |
| [fermat-strings](picoCTF/Binary%20Exploitation/fermat-strings)                         | [solve.py](picoCTF/Binary%20Exploitation/fermat-strings/solve.py)                                                                                                                                       | Python                | picoMini by redpwn. 250 points. 64-bit binary. Format String. GOT overwrite and ASLR bypass                                   |
| [SaaS](picoCTF/Binary%20Exploitation/SaaS)                                             | [solve.py](picoCTF/Binary%20Exploitation/SaaS/solve.py)                                                                                                                                                 | Python                | picoMini by redpwn. 350 points. 64-bit binary. `seccomp` rules. Custom shellcode                                              |

| Cryptography                                      | Scripts / Programs                                     | Language | Purpose                                  |
| ------------------------------------------------- | ------------------------------------------------------ | -------- | ---------------------------------------- |
| [Sum-O-Primes](picoCTF/Cryptography/Sum-O-Primes) | [solve.py](picoCTF/Cryptography/Sum-O-Primes/solve.py) | Python   | picoCTF 2022. 400 points. RSA decryption |


## Plaid CTF

| Crypto                                                                         | Scripts / Programs                                                 | Language          | Purpose                                                                    |
| ------------------------------------------------------------------------------ | ------------------------------------------------------------------ | ----------------- | -------------------------------------------------------------------------- |
| [DHCPPP](Plaid%20CTF/DHCPPP)                                                   | [solve.py](Plaid%20CTF/DHCPPP/solve.py)                            | Python / SageMath | Plaid CTF 2024. ChaCha20-Poly1305. Nonce reuse. DNS                        |
| [Paranormial Commitment Scheme](Plaid%20CTF/Paranormial%20Commitment%20Scheme) | [solve.py](Plaid%20CTF/Paranormial%20Commitment%20Scheme/solve.rs) | Rust              | Plaid CTF 2024. BLS12-381. Elliptic curve pairings. Lagrange interpolation |


## SECCON CTF

| Crypto                                | Scripts / Programs                           | Language | Purpose                                            |
| ------------------------------------- | -------------------------------------------- | ---------| -------------------------------------------------- |
| [plai_n_rsa](SECCON%20CTF/plai_n_rsa) | [solve.py](SECCON%20CTF/plai_n_rsa/solve.py) | Python   | SECCON CTF Quals 2023. RSA. Euler totient function |


## Securinets

| Crypto                                                      | Scripts / Programs                                       | Language          | Purpose                                                                                            |
| ----------------------------------------------------------- | -------------------------------------------------------- | ----------------- | -------------------------------------------------------------------------------------------------- |
| [Farfour Post Quantom](Securinets/Farfour%20Post%20Quantom) | [solve.py](Securinets/Farfour%20Post%20Quantom/solve.py) | Python / SageMath | Securinets Quals 2023. Matrix operations. Modular arithmetic. Shuffling. Solve system of equations |
| [PolyLCG](Securinets/PolyLCG)                               | [solve.py](Securinets/PolyLCG/solve.py)                  | Python            | Securinets Quals 2023. Modular polynomials                                                         |

| Pwn                               | Scripts / Programs                        | Language | Purpose                                                                                         |
| --------------------------------- | ----------------------------------------- | -------- | ----------------------------------------------------------------------------------------------- |
| [scrambler](Securinets/scrambler) | [solve.py](Securinets/scrambler/solve.py) | Python   | Securinets Finals 2022. 64-bit binary. ROP. ret2libc. GOT overwrite. Stack Pivot. `seccomp` rules |


## SEETF

| Crypto                               | Scripts / Programs                        | Language | Purpose                               |
| ------------------------------------ | ----------------------------------------- | -------- | ------------------------------------- |
| [Close Enough](SEETF/Close%20Enough) | [solve.py](SEETF/Close%20Enough/solve.py) | Python   | SEETF 2022. RSA. Wrong implementation |

| Rev                          | Scripts / Programs                   | Language | Purpose                                      |
| ---------------------------- | ------------------------------------ | -------- | -------------------------------------------- |
| [babyreeee](SEETF/babyreeee) | [solve.py](SEETF/babyreeee/solve.py) | Python   | SEETF 2022. Revert encryption algorithm. XOR |


## SekaiCTF

| Crypto                                      | Scripts / Programs                             | Language          | Purpose                                                                                |
| ------------------------------------------- | ---------------------------------------------- | ----------------- | -------------------------------------------------------------------------------------- |
| [cryptoGRAPHy 1](SekaiCTF/cryptoGRAPHy%201) | [solve.py](SekaiCTF/cryptoGRAPHy%201/solve.py) | Python            | SekaiCTF 2023. Graph Encryption Scheme. Key leakage. Decryption                        |
| [cryptoGRAPHy 2](SekaiCTF/cryptoGRAPHy%202) | [solve.py](SekaiCTF/cryptoGRAPHy%202/solve.py) | Python            | SekaiCTF 2023. Graph Encryption Scheme. Single-Destination Shortest Path. Node degrees |
| [cryptoGRAPHy 3](SekaiCTF/cryptoGRAPHy%203) | [solve.py](SekaiCTF/cryptoGRAPHy%203/solve.py) | Python            | SekaiCTF 2023. Graph Encryption Scheme. Query recovery. Tree isomorphisms              |
| [Noisy CRC](SekaiCTF/Noisy%20CRC)           | [solve.py](SekaiCTF/Noisy%20CRC/solve.py)      | Python / SageMath | SekaiCTF 2023. CRC. Chinese Remainder Theorem. Brute force                             |
| [はやぶさ](SekaiCTF/はやぶさ)                  | [solve.py](SekaiCTF/はやぶさ/solve.py)          | Python / SageMath | SekaiCTF 2024. Falcon. Lattice attack on NTRU. BKZ. Key recovery attack                |
| [マスタースパーク](SekaiCTF/マスタースパーク)     | [solve.py](SekaiCTF/マスタースパーク/solve.py)   | Python / SageMath | SekaiCTF 2024. Isogeny-based cryptography. CSIDH. Discrete logarithm. CRT              |

| Pwn                              | Scripts / Programs                        | Language | Purpose                                      |
| -------------------------------- | ----------------------------------------- | -------- | -------------------------------------------- |
| [speedpwn](SekaiCTF/speedpwn) | [solve.py](SekaiCTF/speedpwn/solve.py) | Python   | SekaiCTF 2024. Uninitialized values. Oracle. `FILE` structure attack. GOT overwrite |


## TeamItaly CTF

| Crypto                                                     | Scripts / Programs                                        | Language | Purpose                                                                  |
| ---------------------------------------------------------- | --------------------------------------------------------- | -------- | ------------------------------------------------------------------------ |
| [Big RSA](TeamItaly%20CTF/Big%20RSA)                       | [solve.py](TeamItaly%20CTF/Big%20RSA/solve.py)            | Python   | TeamItaly CTF 2023. RSA. Factorial. Modular arithmetic. Integer division |
| [Scrambled Pizzeria](TeamItaly%20CTF/Scrambled%20Pizzeria) | [solve.py](TeamItaly%20CTF/Scrambled%20Pizzeria/solve.py) | Python   | TeamItaly CTF 2023. XOR. Permutations and substitutions                  |
