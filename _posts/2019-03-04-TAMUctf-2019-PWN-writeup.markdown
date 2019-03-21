---
layout: post
title:  "TAMUctf 2019 PWN writeup"
date:   2019-03-04 20:06:00
categories: ctf
permalink: /archivers/TAMUctf-2019-PWN-writeup
---
# TAMUctf 2019 pwn writeup

## pwn1

a simple stack overflow, just overwrite the variable in the stack to execute the backdoor. 

the offset is:
```python
offset=0x3b-0x10=0x2b
```

## pwn2 
a partial overwrite problem. with pie opened, we can't do simple stack overflow to get shell. deep into the code,  i find there is `off-by-one` in `select_func`.

we can change the last byte of the pointer of function `two` which is `\xAD` to any byte. luckly, a backdoor `print_flag` is in `0x6D8`. as we know, the last three byte of the address are not randomrized in aslr. so we can change the last byte of  the function `two` pointer  from  `\xAD` to `\xd8` to get flag.

## pwn3 
Still a simple stack overflow problem. this time there is no backdoor, the pie is also opened. so we need to find a way to get shell.

check the programe in gdb with `checksec` command, find the nx is closed, and the stack address is also printed. so i can directly execute shellcode to get shell.

## pwn4
It should be a simple stack overflow problem with `rop attack`. But there is a command which can bypass the `strchr` check. I can use `;sh` to which then will be `system("ls;sh")` to get a shell. Don't need to use any skill, easy.

the expected answer should be return to `system` function with `secret` string `\bin\sh`.

## pwn5
the same with pwn4, i can use `;sh` directly to get the shell and cat the flag.txt. 

the flag is `gigem{r37urn_0r13n73d_pr4c71c3}`, which means the expected solution should build `ROP chain` to get the shell. It is build by static method which can find any gadget i want to use.

## VeggieTales
no binary given out, no solution.

## pwn6 
waiting for writeup

## conclusion
all the exp is in my [github](https://github.com/ray-cp/ctf-pwn/tree/master/tamuctf2019)