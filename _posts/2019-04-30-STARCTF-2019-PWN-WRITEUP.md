---
layout: post
title:  "*CTF 2019 PWN WRITEUP"
date:   2019-04-30 21:30:00
categories: ctf
permalink: /archivers/STARCTF_2019_PWN_WRITEUP
---
***KEEP HOLDING ON***

First, i'd like to propose a tool [**pwn_debug**](https://github.com/ray-cp/pwn_debug) to you for debugging ctf pwn games. it came out to me after participating a lot games during recent years.

It mainly has four features:
* Support glibc source debugging no matter x86 or 64, easy to debug libc functions such as malloc and free.
* Support different libc versions no  matter the host versions. for example, allow running libc 2.29 on ubuntu which originally runs  on libc 2.23.
* Support easily making breakpoints, no matter the PIE of the program is opened or not.
* Easy to use(i think, lol), you just need add a little thing based on your original pwntool script.

## quicksort 

It is a relative simple game in this contents, which is a array sorting program. 

the vuln is a obvious stack overflow. Though set the array to heap, but the string we input is set to stack. And the string is inputed via `gets` function. so we can overwrite the stack totally and do something bad.

How to exploit it? `canary` is opened in the program, so we can't directly overwrite the return address to get the shell. Luckily, there is a pointer in the stack which originally points to array. we can  overwrite this pointer to achieve anywhere writing.

The exploit process is: 
1. overwrite the pointer to `atoi got`.
2. write the `atoi got` to `printf plt`.
3.  leak stack and libc address and canary by fmt vuln.
4.  get the shell.

one thing need to point out is that there is a `free` before the main function return, so we need build a fake heap to free and arrive the main return to get the shell.

## babyshell

just input a shellcode that consist of specified bytes. it supposed to be a game for testing the ability of writting shellcode. 

but there is a little trick to bypass the check. the program ends the check by `null` byte. we can use a `short jmp` in the start of the array and write our shellcode in the behind. all we need to do is that find a 'short jmp' made of the specific bytes.  the following shellcode is size of two `74 00`, that can jump to our shellcode.
```
jmp xx
xx:
```

## girlfriend

it is a typical uaf problem. it supposed to be easy, but it runs on libc 2.29(again, recommend **pwn_debug** to you for run libc 2.29). compare with tcache before, there is a `free` check in tcache, shown as below:
```
if (__glibc_unlikely (e->key == tcache))
    {
      tcache_entry *tmp;
      LIBC_PROBE (memory_tcache_double_free, 2, e, tc_idx);
      for (tmp = tcache->entries[tc_idx];
     tmp;
     tmp = tmp->next)
        if (tmp == e)
    malloc_printerr ("free(): double free detected in tcache 2");
```
so we can't directly double free the bins to tcache again, so what we need to do is that `play the game in fastbin link`.

the whole process includes:
1. full the tcache first.
2. then leak address by free the chunk to unsorted bin.
3. double free chunks on fastbin link.
4. attack to get the `__free_hook`
5. write `system_addr` to `__free_hook` and get the shell.

## upxofcpp

it is a interesting problem, which is a program that packed by upx. so the first thing is that use `upx -d upxofcpp` to unpack it and drag the unpacked program into ida to analyze.

we can see a `double free` vuln in `remove_vec`,  it seems we can use this vuln do a lot of things. But after looking for a circle, it seems that there is no where to leak. and we only can control the `rip` to heap address.

if only the `nx` is `disabled`! when check the security mechanism of the unpacked program, it tells that `nx` is `enabled`:
```
  Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

suddenly, i think that the upx need to unpack the text and the memory may different than this unpacked program. so i run the `unpacked` program and the use gdb to `attach` on that process to check the memory. bingo, the heap is also executable, we can execute shellcode directly to get the shell:
```
          0x200000           0x400000 rwxp   200000 0
    0x7ff570b55000     0x7ff570b59000 rwxp     4000 0
    0x7ff570b59000     0x7ff570b6f000 r-xp    16000 0      /lib/x86_64-linux-gnu/libgcc_s.so.1
    0x7ff570b6f000     0x7ff570d6e000 ---p   1ff000 16000  /lib/x86_64-linux-gnu/libgcc_s.so.1
    0x7ff570d6e000     0x7ff570d6f000 rwxp     1000 15000  /lib/x86_64-linux-gnu/libgcc_s.so.1
    0x7ff570d6f000     0x7ff570d70000 rwxp     1000 0
    0x7ff570d70000     0x7ff570e78000 r-xp   108000 0      /lib/x86_64-linux-gnu/libm-2.23.so
    0x7ff570e78000     0x7ff571077000 ---p   1ff000 108000 /lib/x86_64-linux-gnu/libm-2.23.so
    0x7ff571077000     0x7ff571078000 r-xp     1000 107000 /lib/x86_64-linux-gnu/libm-2.23.so
    0x7ff571078000     0x7ff571079000 rwxp     1000 108000 /lib/x86_64-linux-gnu/libm-2.23.so
    0x7ff571079000     0x7ff571239000 r-xp   1c0000 0      /lib/x86_64-linux-gnu/libc-2.23.so
    0x7ff571239000     0x7ff571439000 ---p   200000 1c0000 /lib/x86_64-linux-gnu/libc-2.23.so
    0x7ff571439000     0x7ff57143d000 r-xp     4000 1c0000 /lib/x86_64-linux-gnu/libc-2.23.so
    0x7ff57143d000     0x7ff57143f000 rwxp     2000 1c4000 /lib/x86_64-linux-gnu/libc-2.23.so
    0x7ff57143f000     0x7ff571443000 rwxp     4000 0
    0x7ff571443000     0x7ff5715b5000 r-xp   172000 0      /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.21
    0x7ff5715b5000     0x7ff5717b5000 ---p   200000 172000 /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.21
    0x7ff5717b5000     0x7ff5717bf000 r-xp     a000 172000 /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.21
    0x7ff5717bf000     0x7ff5717c1000 rwxp     2000 17c000 /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.21
    0x7ff5717c1000     0x7ff5717c5000 rwxp     4000 0
    0x7ff5717e3000     0x7ff571809000 r-xp    26000 0      /lib/x86_64-linux-gnu/ld-2.23.so
    0x7ff571809000     0x7ff571a08000 ---p   1ff000 0
    0x7ff571a08000     0x7ff571a09000 r-xp     1000 25000  /lib/x86_64-linux-gnu/ld-2.23.so
    0x7ff571a09000     0x7ff571a0a000 rwxp     1000 26000  /lib/x86_64-linux-gnu/ld-2.23.so
    0x7ff571a0a000     0x7ff571a0b000 rwxp     1000 0
    0x7ff571a0b000     0x7ff571a0e000 r-xp     3000 0
    0x7ff571a0e000     0x7ff571c0d000 ---p   1ff000 0
    0x7ff571c0d000     0x7ff571c0e000 r-xp     1000 0
    0x7ff571c0e000     0x7ff571c0f000 rwxp     1000 0
    0x7ff571c0f000     0x7ff571c10000 r-xp     1000 0      /home/raycp/work/starctf2019/upxofcpp/upx
    0x7ff571c10000     0x7ff571c11000 rwxp     1000 0
    0x7ff57340a000     0x7ff57343c000 rwxp    32000 0      [heap]
    0x7fff0576c000     0x7fff0578d000 rwxp    21000 0      [stack]
    0x7fff057a9000     0x7fff057ac000 r--p     3000 0      [vvar]
    0x7fff057ac000     0x7fff057ae000 r-xp     2000 0      [vdso]
0xffffffffff600000 0xffffffffff601000 r-xp     1000 0      [vsyscall]
```

## conclude

During the game,  among all the six normal pwn games, i didn't figure out how to solve the `heap_master`. it was a little pity, should do better next time.

again, recommend the [**pwn_debug**](https://github.com/ray-cp/pwn_debug) to you, hope it may do a little favor for your pwn process.

the whole exp is in my [github](https://github.com/ray-cp/ctf-pwn/tree/master/2019/starctf2019).
