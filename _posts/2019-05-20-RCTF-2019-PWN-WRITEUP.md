---
layout: post
title:  "RCTF 2019 PWN WRITEUP"
date:   2019-05-20 23:30:00
categories: ctf
permalink: /archivers/RCTF_2019_PWN_WRITEUP
---
Best love to my girlfriend on 5.20, lol.

During the contest, i finished 4 games, left `syscall_interface` undone. i was the 4th to finish the `chat`, which is a exciting thing.  here i'll post the writeup of `babyheap`, `shellcoder`, `many_note`and `chat`. 


## babyheap

there is a `off-by-null` vuln in `edit` function, it seems like this is a regular `overlap chunk`heap problem.
```
ret_value = read_n((char *)global_mmap[2 * v0], (unsigned int)global_mmap[2 * v0 + 1]);
    *((_BYTE *)&global_mmap[2 * v0]->ptr + ret_value) = 0;// off-by-null
```

we can use the overlap chunk to leak `libc address`. and in  regular `overlap chunk`heap problem, we can use the overlap chunk to form a `uaf` which then malloc out `__malloc_hook`. and then we can write `one gadget` into `__malloc_hook` and finally get the shell.

unlukily, there are some limitations in this game:
* there is no fastbin chunks when `free`, for it calls `mallopt(1, 0)` to set `global_max_fat` to 0x10.
* there is a `seccomp` sandbox to limit the syscall which can't use `execve` to get shell.
```
$ seccomp-tools dump ./babyheap
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x01 0x00 0xc000003e  if (A == ARCH_X86_64) goto 0003
 0002: 0x06 0x00 0x00 0x00000000  return KILL
 0003: 0x20 0x00 0x00 0x00000000  A = sys_number
 0004: 0x15 0x00 0x01 0x00000029  if (A != socket) goto 0006
 0005: 0x06 0x00 0x00 0x00000000  return KILL
 0006: 0x15 0x00 0x01 0x0000003b  if (A != execve) goto 0008
 0007: 0x06 0x00 0x00 0x00000000  return KILL
 0008: 0x15 0x00 0x01 0x00000039  if (A != fork) goto 0010
 0009: 0x06 0x00 0x00 0x00000000  return KILL
 0010: 0x15 0x00 0x01 0x0000009d  if (A != prctl) goto 0012
 0011: 0x06 0x00 0x00 0x00000000  return KILL
 0012: 0x15 0x00 0x01 0x0000003a  if (A != vfork) goto 0014
 0013: 0x06 0x00 0x00 0x00000000  return KILL
 0014: 0x15 0x00 0x01 0x00000065  if (A != ptrace) goto 0016
 0015: 0x06 0x00 0x00 0x00000000  return KILL
 0016: 0x15 0x00 0x01 0x0000003e  if (A != kill) goto 0018
 0017: 0x06 0x00 0x00 0x00000000  return KILL
 0018: 0x15 0x00 0x01 0x00000038  if (A != clone) goto 0020
 0019: 0x06 0x00 0x00 0x00000000  return KILL
 0020: 0x06 0x00 0x00 0x7fff0000  return ALLOW

```

so first thing we need to figure out how to get the `fastbin`,  we can use `unsorted bin attack` to overwrite the `global_max_fast`. after that we can use `fastbin` and do `fastbin` attack. you can see this [link](https://ray-cp.github.io/archivers/heap_global_max_fast_exploit) to learn more about attack with `global_max_fast`.

one problem solved, how about the `can't use execve problem`? it seems like we can only use shellcode or rop to read the `flag`.

i used `rop` to execute `mprotect` and make stack executable, then execute shellcode to read the `flag` file. but before we can rop, there are several step:

1. overwrite the top chunk to `__free_hook-0xb58`.
2. malloc out chunk to `__free_hook`.
3. overwrite `__free_hook` to `printf address`.
4. leak `stack` address.
5. overwrite the top chunk to `return stack`
6. malloc out the stack and input rop chain and shellcode.
7. overwrite `__free_hook` to `ret gadget`.
7.  execute the rop to make stack executable and execute shellcode to read flag file.

## shellcoder 

seven bytes shellcode, which clean all the register except `rdi`, so we can use shellcode as below to read more shellcode:
```
xchg rdi,rsi;
xor edx,esi;
syscall
```
the program also forbid the `execve` call  and try to test the ability to write shellcode to traversing the directory to read the file. but in exp i just give the shellcode to get the shell.

## many_note

we can use the first input `name` to leak libc address.

the vuln is in func `0xb0b` that it call read with the size of the `total size` which is supposed to be `remainder size`. so it is a heap overflow problem.

but how to use, we used to learn overwrite the top chunk size, and then free it into unsorted bin, and then do unsorted bin attack in `house of orange`.

but here it can't realized, for it is in `thread arena` and not in `main arean`. when top chunk is not enough, it will not free the old top chunk, instead it will directly expand the old top chunk according to the source code:
```
  if (av != &main_arena)
{
      heap_info *old_heap, *heap;
      size_t old_heap_size;

      /* First try to extend the current heap. */
      old_heap = heap_for_ptr (old_top);
      old_heap_size = old_heap->size;
      if ((long) (MINSIZE + nb - old_size) > 0
          && grow_heap (old_heap, MINSIZE + nb - old_size) == 0)
        {
          av->system_mem += old_heap->size - old_heap_size;
          set_head (old_top, (((char *) old_heap + old_heap->size) - (char *) old_top)
                    | PREV_INUSE);
        }
        else if ((heap = new_heap (nb + (MINSIZE + sizeof (*heap)), mp_.top_pad)))
        {
          ...
              _int_free (av, old_top, 1);
            }
``` 

normally , the `grow_heap` function returns zero, so it directly expand the old top. go into the `grow_heap` to find how to make `grow_heap` function return none zero:

```
static int
grow_heap (heap_info *h, long diff)
{
  size_t pagesize = GLRO (dl_pagesize);
  long new_size;

  diff = ALIGN_UP (diff, pagesize);
  new_size = (long) h->size + diff;
  if ((unsigned long) new_size > (unsigned long) HEAP_MAX_SIZE)
    return -1;

  if ((unsigned long) new_size > h->mprotect_size)
    {
      if (__mprotect ((char *) h + h->mprotect_size,
                      (unsigned long) new_size - h->mprotect_size,
                      PROT_READ | PROT_WRITE) != 0)
        return -2;

      h->mprotect_size = new_size;
    }

  h->size = new_size;
  LIBC_PROBE (memory_heap_more, 2, h, h->size);
  return 0;
}
```

so we need to expand the old size bigger than `HEAP_MAX_SIZE` （which seems to be 0x400000, if i didn't remember wrong.) , it will return none zero. 

so i think  that's why it allows malloc so many times. when you can call `free` with heap overflow, you almost can do anything you want with `tcache`.

source code is your friend, debug glibc with debug symbols is a pleasure thing. again, recommend [pwn_debug](https://github.com/ray-cp/pwn_debug) to you, which can help you easily debug program with debug symbols.


## chat

i should be finished it earlier, for i'm on the train in the last hour. do the game during trip is painful, but thanks god, i finished at last.

go back to the problem, it is a little complicated program that there is a lot of structure in it.

i won't analysis the program step by step, and will just point where is the vuln. you can check the program with my `ida` in my github, which try my best to do the structure building. 

there a two vulns in the program:
* one is in say function, that the first `message_mmap_offset` is overlapping with the `message content` for all the content of the `message_mmap` is `null`, so the next `find_mmap_ptr_last` return the same address with the last mmap.
* the second is a uaf vuln. when `modify` the name,  it use `login_user` global pointer, but when in sync, it free the user structure with `user_link`, if we deploy the heap appropriately,  we will get a uaf.

so how to use these two vuln? first we can use the first vuln to leak libc address. we can overwrite `message_mmap_offset` with our `message content` to a big value which point to the `ld.so` memory.  the `mmap` memory  is next to `ld.so` memory:
```
pwndbg> vmmap
...
    0x7f0537944000     0x7f0537969000 r-xp    25000 0  /glibc/x64/2.27/lib/ld-2.27.so
    0x7f0537b56000     0x7f0537b68000 rw-p    12000 0
    0x7f0537b68000     0x7f0537b69000 r--p     1000 24000  /glibc/x64/2.27/lib/ld-2.27.so
    0x7f0537b69000     0x7f0537b6a000 rw-p     1000 25000  /glibc/x64/2.27/lib/ld-2.27.so
 ...   
```
the offset is always the same `0x13000`:
```
pwndbg> print 0x7f0537b69000 -0x7f0537b56000
$1 = 0x13000
```
and in `ld.so`, there a libc address `__GI___libc_malloc`
```
telescope 0x7f0537b69000
00:0000│   0x7f0537b69000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x224e68 /* 'hN"' */
01:0008│   0x7f0537b69008 (_GLOBAL_OFFSET_TABLE_+8) ◂— 0x0
... ↓
03:0018│   0x7f0537b69018 (_GLOBAL_OFFSET_TABLE_+24) —▸ 0x7f05376ba270 (_dl_catch_exception) ◂— push   rbx
04:0020│   0x7f0537b69020 (_GLOBAL_OFFSET_TABLE_+32) —▸ 0x7f05375ea070 (malloc) ◂— push   rbp

```
so we can overwrite `message_mmap_offset` to `0x13020` which point to `0x7f0537b69020` finally and it will leak out libc address.

after link, we can use the uaf to do `tcache` attack and overwrite `strchr got` to `system` address and get the shell.

actually, there is another vuln, but it doesn't have any affect. we can input the name with `256` byte and it will leak out heap address.

## syscall_interface

it is first use brk syscall to leak heap address.

and then brute force to guess the offset between the heap address and text address. and then use srop to read ropchain and payload to heap.

and use stack pivot to execute rop chain and get the shell.

it is easy, but i hate brute force in the game. and i also didn't think it need to use brute force to guess the offset, i think it should be a syscall to leak the libc address directly. what stupid of i am.

## conclusion

All the exp and files(except for syscall_interface) are in my [github](https://github.com/ray-cp/ctf-pwn/tree/master/2019/rctf2019)






