---
layout: post
title:  "ASIS-2017 pwn writeup"
date:   2017-04-13 19:24:07
categories: ctf
permalink: /archivers/ASIS-2017-pwn-writeup
---

i learned a lot from this ctf, still have too much thing need to leran.
## Start

a smiple stack overflow question. read 0x400 bytes to stack which can only store 0x10 bytes. first check the security mechanism:
```C
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : disabled
PIE       : disabled
RELRO     : Partial
gdb-peda$ 
```
as we can see, no NX. so we can execute shellcode to get a shell, one more chanllenge is that we need to put shellcode to a address we already kown. so firt overwrite the ebp to bss address, and then call read. at last, get a shell.

## start_hard

compare with Start, nothing different but the secutiry machanism:
```C
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
gdb-peda$ 
```
so we can put shellcode to stack or bss directly, we need find a way to close NX or ROP. 
there are two key point to solve the problem. frst is the __libc_csu_init() universal gadget. and the second is read function in libc at last will call syscall 
``` C
.text:00000000000DB590                 cmp     cs:dword_39D740, 0
.text:00000000000DB597                 jnz     short loc_DB5A9
.text:00000000000DB599                 mov     eax, 0
.text:00000000000DB59E                 syscall
```
as shown above, if wefirst put all the regs proper numbers and then overwrite the last byte of read got from 0x90 to 0x9e, we can call any function as we can. 
so first put shellcode to bss section, then bruteforce the syscall address(last byte of read got), after call mprotect to close NX, then get a shell.

## fulang 

this problem is like one problem of  pwnable.kr. using a global ptr `fu ` point to the global array `data` , input to handle the global ptr. we can first change `fu` points to itself, then overwrite the address to strlen got, after that we can leak strlen address and overwrite strlen got to system address. then overwrite the puts got to main addr, at last input `/bin/sh` to execute `system('/bin/sh')` to get a shell.

## Random_Generator

first call `getRandoms` in pruduce some random number stored in stack. after that we can read 7 bytes from the area where originally points to the random number. this problem though has a stack overflow in the end but has canary, so we need to figure out a wey to bypass it. the key point is that after  `getRandoms` return back, the memory area of random number will be replaced by canary. so at here we can get canary to bypass it.
another question we need to figure out is how to build rop without `'0a|09|0b|20|0d'`. for if there exsit those bytes, the scanf will cut down the input, and the got and plt address contain those bytes. what we do is use ROPgadget with `ROPgadget  --binary  Random_Generator  --badbytes '0a|09|0b|20|0d'`. we get a gadget `0x0000000000400f8f : syscall ; ret` so we can do rop with this particular gadget and get a shell.

## crcme

input a string then get the crc32 of the string. the vuln is you though input the length of the string, but it call gets to get input. so there exsits stack overflow. what we input can overflow the point that original point to input. so we can overwrite to got to leak the crc32 and bruteforce to get the address of fucntion. it is viable if we make the length of string is 1 or 4 bytes.
so we can leak libc directly. because it has canary opened, so we need to leak canary. i find there exsits a global ptr points to stack area (len), wo we can leak stack address, and then we can use stack address to leak canary. after that we can bypass canary and build rop to get a shell.

## pray_CaNaKMgF

we can call `pray` to read `/proc/self/maps` to leak the address todefeat ASLR and by abusing double free into fast bin attack we can overflow `__malloc_hook` by address of system,the reason why we overwrite `__malloc_hook` is that need to bypass the size check, 
``` C
if (__builtin_expect (fastbin_index (chunksize (victim)) != idx, 0)){
    errstr = "malloc(): memory corruption (fast)";
    errout:
    malloc_printerr (check_action, errstr, chunk2mem (victim), av);
    return NULL;
}
```
the `__malloc_hook` address around exists the size number can actually bapass the check. then we can call malloc(bin_sh_addr) to execute `__malloc_hook(bin_sh_addr)` to get a shell
```C
void *(*hook) (size_t, const void *)
    = atomic_forced_read (__malloc_hook);
if (__builtin_expect (hook != NULL, 0))
    return (*hook)(bytes, RETURN_ADDRESS (0));
```

## CaNaKMgF_remastered

the difference between **CaNaKMgF_remastered** and **pray_CaNaKMgF** is that we can't read anything and the other is that **CaNaKMgF_remastered** has **PIE** security machanism, so at first we need figure out how to defeat aslr and we also can't call `__malloc_hook( int size)` like **pray_CaNaKMgF** , because `bin_sh_addr` is greater than `int`.we also need to find a way to get  a shell.
first, defeat aslr, we can get memory leak of heap by reading contents of *fastbin chunk*, and we can get memory leak of libc arena by reading contents of *smallbin chunk*.
second we can't simple call malloc, but we can find a way to execute RCE. we overwrite `__malloc_hook` to RCE address  and trigger double free error, which will trigger our hook and get a shell.

## link

at last i wanna thanks the guys for sharing the writeups. actually, i can't do all the problem by myself. i read a lot of guys blog  after the end of this ctf. especially ,the exp of  **CaNaKMgF_remastered** and **pray_CaNaKMgF**  i just copy that from [PaulCher](https://gist.github.com/PaulCher/756503140162b255a478aa395343d201)
