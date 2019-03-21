---
layout: post
title:  "CODEGATE 2019 PWN writeup"
date:   2019-01-27 20:06:00
categories: ctf
permalink: /archivers/CODEGATE-2019-PWN-writeup
---
***STILL LOVE PWN AND EXPLOIT***

## aeiou
### vuln
It seems like a heap problem, but there is no loop in main function. We can only do action on time. When look into the programe, I find that there is a stack overflow in teach number function which address is 0x4013aa. The buff is only 0x1000, but we can input 0x10000. Obviously, it is a stack overflow vuln.
### exploit
How to get the shell? First, check the security mechanism:
```C
gdb-peda$ checksec
CANARY    : ENABLED
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : FULL
gdb-peda$ 
```
As we can see, the canary is opened. We can't just overwrite the return address directly, for there is the canary protection. 

How to figure out the problem? Back to the programe, i find that the function is in a thread which is made by `pthread_create`. It is a little wired, i think it may be the key. 

After searching in the internet, i found a technique to bypass canary. when a thread is created by `pthread_create` function, to ensure the thread has its own stack, process will use `TLS` to store the variable and things. So the `stack` is belonged to thread itself(`TLS`), and is created by `mmap` function. Canary is also under the stack,which is the `stack_guard` in the `tcbhead_t`struct.
```C
typedef struct
{
  void *tcb;        /* Pointer to the TCB.  Not necessarily the
               thread descriptor used by libpthread.  */
  dtv_t *dtv;
  void *self;       /* Pointer to the thread descriptor.  */
  int multiple_threads;
  int gscope_flag;
  uintptr_t sysinfo;
  uintptr_t stack_guard;
  uintptr_t pointer_guard;
  ...
} tcbhead_t;
```
So the way we bypass the canary is that we input long buff and it will finaly overwrite the canary. With this way, we can do ROP attack easily. The full exp link is shown at the bottom.

## god-the-reum
### vuln
the vuln is obvious, which is a `uaf` in `withdraw` function in `0xF2E`. The funtion free the heap pointer but does not clean the value of pointer, we can still use the pointer to do anything such as leaking.

### expolit
first, check the security mechanism: 
```C
gdb-peda$ checksec
CANARY    : ENABLED
FORTIFY   : disabled
NX        : ENABLED
PIE       : ENABLED
RELRO     : FULL
gdb-peda$ 
```
one thing we need to care is that this programe is run under the `libc 2.27`, which os is ubuntu 18.4. there is `tcache` in `libc 2.27`.

next, we need to leak heap address, we can use `withdraw` funtion to free a chunk to `tcache`, and then use `uaf` vuln (`withdraw` again) to free the same chunk(there is no check in `tcache`), then we can use `show` to leak the address of heap.

How to leak libc address? after leak the heap address, we can know the money we need to substract, so we can free the same chunk 7 times and the chunk will be put into `unsorted bin`. Then we can use `show` function to leak the libc address.

Now we get all the address we need, so we can use `developer` function to overwrite the tcache chain to get the memory which address is `__free_hook`, then we write `one gadget` address into `__free_hook`. 

Finally, get the shell.

## maris_shop
### vuln
There is a `uaf` vuln. We can first create 16 carts. And when we buy all the carts, it will free all the carts but just set 15 carts pointer and leave the last ont unclean. That's the pointer we can use to leak address and exploit.

### expolit
first, check the security mechanism: 
```C
gdb-peda$ checksec
CANARY    : ENABLED
FORTIFY   : disabled
NX        : ENABLED
PIE       : ENABLED
RELRO     : Partial
gdb-peda$ 
```
There is a small trick to bypass `money check`, which is we can use `0 amount`.

The whole process is shown as below:
1. we create 16 carts. 
2. we by all the carts, the programe will free all the pointer and leave the 15th pointer unclean. 
3. we show the 15th pointer and leak the address of libc.
4. we add the 15th carts and make unsorted bin attack, which overwrite `stdin->_IO_buf_end` to point to `main_arena`.
5. we call fgets will overwrite the `stdin->vtable`, address of which  contains `one gadgets` .
6. get shell

## conclusion
all the exp is in my [github](https://github.com/ray-cp/ctf-pwn/tree/master/codegate2019)