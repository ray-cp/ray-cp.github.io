---
layout: post
title:  "堆中global_max_fast相关利用"
date:   2019-05-15 16:11:00
categories: ctf
permalink: /archivers/heap_global_max_fast_exploit
---

**欢迎关注公众号[平凡路上](https://mp.weixin.qq.com/s/TR-JuE2nl3W7ZmufAfpBZA)，平凡路上是一个致力于二进制漏洞分析与利用经验交流的公众号。**

## 前言

事情的起因还要从*ctf 2019说起，`heap_master`里能用`unsorted bin attack`实现一次任意地址写，一开始想到的是写stdout来实现地址泄露 ，但是这样要写两次才能实现，花了很大的经历找另外一次写，仍然没有找到，很绝望。

事后看wp看到是用一次写实现对变量`global_max_fast`的覆盖，从而实现后续的利用，对`malloc`以及`free`中涉及`global_max_fast`进行了一定的分析，并结合在网上找到的相关的题目进行了相应的实践。

在开始之前向大家推荐下我写的一个框架[pwn_debug](https://github.com/ray-cp/pwn_debug)，写它的本意是方便大家的调试，主要的特点有：
1. 支持带符号调试glibc，脚本中支持安装debug版的glibc（x64和x86都支持），以实现调试的时候可以看到glibc源码。
2. 支持不同版本的glibc调试。如在ubuntu16上调试libc-2.29。
3. 下断点方便，不管程序是否开启PIE。
4. 使用方便，与pwntools兼容起来很简单（我觉得）。

## 源码分析
此次的源码是基于`libc-2.23`的，后续的版本加入了`tcache`，该机制相对来说比较简单与独立，所以还是基于2.23进行相应的分析，在64位系统上进行。
`global_max_fast`这个全局变量的作用是用来标志`fastbin`的大小的阈值，小于这个值的堆块会被认为是fastbin，使用fastbin的相应机制进行管理。看下它的定义：
```c
#define set_max_fast(s) \
  global_max_fast = (((s) == 0)                 \
                     ? SMALLBIN_WIDTH : ((s + SIZE_SZ) & ~MALLOC_ALIGN_MASK))
#define get_max_fast() global_max_fast
```

`set_max_fast`初始化函数开始是在`malloc_init_state`调用的，可以看到这个宏定义的作用是设置`global_max_fast`默认值，默认值是0x80。

然后看`malloc`中对于`fastbin`的处理，fastbin处理很简单，就是找到对应的fastbin的单链表，并从中取出堆块，如果size检查通过就将该堆块返回：
```
if ((unsigned long) (nb) <= (unsigned long) (get_max_fast ()))
    {
      idx = fastbin_index (nb);
      mfastbinptr *fb = &fastbin (av, idx);  ## 找到对应的单链表
      mchunkptr pp = *fb;
      do
        {
          victim = pp;
          if (victim == NULL)
            break;
        }
      while ((pp = catomic_compare_and_exchange_val_acq (fb, victim->fd, victim))
             != victim);
      if (victim != 0)
        {
          if (__builtin_expect (fastbin_index (chunksize (victim)) != idx, 0))  ## 检查size
            {
              errstr = "malloc(): memory corruption (fast)";
            errout:
              malloc_printerr (check_action, errstr, chunk2mem (victim), av);
              return NULL;
            }
          check_remalloced_chunk (av, victim, nb);
          void *p = chunk2mem (victim);
          alloc_perturb (p, bytes);
          return p;  #返回
        }
    }
```
查看free中的fastbin相关的处理源码：
```
if ((unsigned long)(size) <= (unsigned long)(get_max_fast ())

  ...
  ## 对size进行基本的检查
    if (__builtin_expect (chunk_at_offset (p, size)->size <= 2 * SIZE_SZ, 0)
  || __builtin_expect (chunksize (chunk_at_offset (p, size))
           >= av->system_mem, 0))
      {
  ...
  ## 对next chunk的size进行检查
  if (chunk_at_offset (p, size)->size <= 2 * SIZE_SZ
        || chunksize (chunk_at_offset (p, size)) >= av->system_mem;
        }))
    {
      errstr = "free(): invalid next size (fast)";
      goto errout;
    }
  ...
  
  ## 获取对应的fastbin index
    unsigned int idx = fastbin_index(size);
    fb = &fastbin (av, idx);

    ...
    
    do
      {
  /* Check that the top of the bin is not the record we are going to add
     (i.e., double free).  */
  if (__builtin_expect (old == p, 0))
    {
      errstr = "double free or corruption (fasttop)";
      goto errout;
    }
    ...
  p->fd = old2 = old;
      }
```
对于fastbin的free过程主要包括如下：
1. 对释放的堆块的size进行基本的检查。
2. 对释放堆块的下一个堆块的size进行基本的检查。
3. 获取释放堆块所对应的fastbin链表对应的索引。
4. 检查是否是double free。
5. 释放进单链表。

fastbin的单链表管理是比较简单的，与`global_max_fast`相关且需要注意的代码则是fastbin 所对应的index获取以及index所对应的指针获取的代码，即`fastbin_index`宏以及`fastbin`宏，对应代码如下：
```
#define fastbin_index(sz) \
  ((((unsigned int) (sz)) >> (SIZE_SZ == 8 ? 4 : 3)) - 2)

#define fastbin(ar_ptr, idx) ((ar_ptr)->fastbinsY[idx])
```
可以看到这两个宏仅仅是利用偏移来定位数组的指针，但是arena所对应的`malloc_state`中fastbins数组相关的定义为：
```
mfastbinptr fastbinsY[NFASTBINS]
  
#define NFASTBINS  (fastbin_index (request2size (MAX_FAST_SIZE)) + 1)
```
到这里问题就比较明显了，如果可以改写`global_max_fast`为一个较大的值，然后释放一个较大的堆块时，由于fastbins数组空间是有限的，其相对偏移将会往后覆盖，如果释放堆块的size可控，就可实现往fastbins数组（main_arena）后的`任意地址`写入所堆块的地址。

即利用`global_max_fast`进行相关的攻击

## 利用场景

对于`global_max_fast`的利用首先要解决的事情是如何覆盖`global_max_fast`。适用的场景应是存在任意地址写的漏洞，但是写入的地址却是不可控的（也是一个比较大的值），因为如果写入的值也是可控的话就不需要使用这个方法就能解决了，最典型的应该是`unsorted bin attack`，可实现往任意地址写入main_arena中的地址。

前置条件我想大概可能是需要泄露一个libc的地址，否则的话可能会像`heap_master`中一样需要爆破4bit的地址。

实现任意地址写的方式是：通过地址与fastbin数组的偏移计算出所需`free`的堆块的size，然后释放相应的堆块，即可实现往该地址写入堆块的地址以进一步利用。

计算偏移的代码可以如下：
```
fastbin_ptr=libc_base+libc.symbols['main_arena']+8
idx=(target_addr-fastbin_ptr)/8
size=idx*0x10+0x20
```

此时要解决的事情是往哪里写以达到实现利用的目的。可能有很多的地方，理论上来说只要是`main_arena`结构体后面的是函数指针或是结构体指针的地址都可以，目前很容易能够预想到的是：
* _IO_list_all
* stdout
* stdin
* stderr
* __free_hook

复写前面四个就是使用`IO_file`攻击那一套方法，伪造结构体来实现任意读任意写或者伪造vtable来实现`house of orange`攻击。

复写`__free_hook`的话则需要一次uaf来修改释放进去的fd改成`system`或者`one gadget`，再将堆块申请出来，从而实现将`__free_hook`改写成`system`或者`one gadget`。

## 实践
在网上找了一下，利用过程中涉及到`global_max_fast`的题目加上*ctf的heap_master，总共有4题：
* BCTF 2018的baby_arena
* 0CTF 2016的zerostorage
* 胖哈勃杯pwn500-house of lemon
* *CTF 2019的heap_master

其中`胖哈勃杯pwn500-house of lemon`，在网上找了半天没找到题目，问出题的`0x9a82`师傅求题目，师傅说年代太久远了，找不到了，所以最终题目数量是三题。

### baby_arena

题目的意思比较简单，提供了三个功能分别是：`Create Order`、`Delete Order`以及`login`的功能。

漏洞也很明显，存在两个漏洞：一个是在create的时候遇到换行符就return了，没有加入`\x00`字节，导致可以泄露地址；另一个是`login`中存在一个栈溢出漏洞，不能覆盖返回地址，但是可以覆盖`user`指针，导致可以实现任意地址写的漏洞，但是该漏洞写的内容是不可控的，只能写`admin`或`clientele`字符串。

如何利用？

首先使用第一个漏洞泄露处libc的地址，根据libc的地址计算得到`global_max_fast`以及`_IO_list_all`的等地址。

然后利用任意地址写的漏洞将`global_max_fast`从0x80覆盖为`0x6E696D6461`（admin），根据偏移释放一个堆块至`_IO_list_all`，将该堆块申请出来伪造好IO_file结构，重新free至`_IO_list_all`，接下来要做的就是触发FSOP，由于申请的size都会被认为是`fastbin`，因此想要触发错误很简单，随意申请一个大小的堆块就会触发io flush，从而getshell。

### zerostorage

这题应该是比较经典的`unsoted bin attack`题，ctf wiki和[brieflyx](http://brieflyx.me/2016/ctf-writeups/0ctf-2016-zerostorage/)大佬的博客的writeup都有写。

值得一提的是writeup是基于老版本的内核，利用泄露出的libc地址通过偏移能够得到程序基址，目前主流的版本好像都不可以了，想了很久，找到一个只需要libc地址就能成功利用的方法，后续也会另外写一个详细的过程发出来。

此题最主要的一个漏洞就是`uaf`，在`merge`的时候`from id`和`to id`没有进行检查，二者可以相同，导致了一个uaf漏洞的形成，从而可以实现泄露libc地址、堆地址和进行`unsorted bin attack`

在得到泄露出的地址后，利用`unsorted bin attack`将`global_max_fast`覆盖成`main_arena`上的地址。接下来释放的堆块都会被当成fastbin往main_arena后面的地址上复写了。

但是往哪里写，前面`_IO_list_all`以及`__free_hook`这些目标的偏移所对应的size都是大于0x1000的，而题目的size是限制在0x1000以内的，使得申请出来的堆块size没法达到目标，所以没办法后续进行利用。

现有的writeup是老版本的内核中可通过libc基址得到程序基址，在程序bss段里构造伪造的fastbin从而实现泄露随机的异或key然后实现任意写。

没有程序基址如何操作呢，关键因素最后找到`merge`的时候没有对`merge`出来的size进行检查，由于堆块最大可为`0x1000`，因此最大可以merge出来0x2000大小的堆块，可以满足需求，复写到`_IO_list_all`，从而可通过伪造`io file`，像baby_arena一样的利用方式，最终拿到shell。由于篇幅的限制，细节就不说了，会在之后的文章给出。

### heap_master

`heap_master`的[官方解](https://www.xctf.org.cn/library/details/0140928636b196af6995785bdf6de4a116c68a55/)是用`large bin attack`，经过分析，也可以使用`unsorted bin attack`和`global_max_fast`结合起来来实现get shell。

这题首先mmap出来0x10000大小的内存，给了`add`、`edit`、`delete`三个选项，`add`函数是通过malloc申请出来一个堆块，但是`edit`以及`delete`都是对于mmap出来的堆块操作，一个很奇怪的题。

分析下来，漏洞存在的地方是可以在大的内存块中伪造堆块释放进去main_arena里，同时仍然可以`edit`，可以说是一个变相的uaf。

没有泄露，也不能控制malloc出来的堆块，如何利用呢？答案在于`unsorted bin attack`和`global_max_fast`。

具体来说，首先伪造堆块释放到`unsorted bin`里面，然后再`edit` 堆块的`bk`的后俩字节为`global_max_fast-0x10`的地址，进行`unsorted bin attack`以实现将`global_max_fast`覆盖为`main_arena`中的地址，由于后两字节的低12字节是确定的，因此只需要爆破4 bit就可以了，还是很快的。

将`global_max_fast`复写后，我们就拥有了任意地址写堆块地址的能力，往哪里写，写哪一个堆块地址进去呢？

目前首要解决的问题仍然是如何泄露地址，此时就想到了修改`stdout`结构体里面的内容来实现任意地址泄露，原理在[文章](https://ray-cp.github.io/archivers/HCTF-2018-PWN-writeup#任意读)里描述的比较清楚了，要想实现地址泄露，需要修改`stdout` file结构体实现以下条件：
* `_IO_write_base`指向想要泄露的地方。
* `_IO_write_ptr`指向泄露结束的地址。
* `_IO_read_end`等于`_IO_write_base`以绕过限制。

此时任意地址写的目标就确定了，就是上面三个字段的地址，根据偏移将上面三个字段设置为堆地址，其中`_IO_write_base`以及`_IO_read_end`指向之前释放进`unsorted bin`里包含libc地址的堆块的地址，`_IO_write_ptr`指向它结束的地址，完成以后，再次调用`printf`函数的时候libc地址就会泄露出来了。

泄露完成以后就好做了，由于释放堆块的size是可以随意伪造的，因此我们可以将目标定位`__free_hook`（size为0x3920），如何向该hook指针填入`system`地址呢，原理是利用uaf，具体的操作是先释放一个堆块到`__free_hook`中，此时`__free_hook`包含的是堆的地址，然后`edit`那个堆块，将它的`fd`改写成`system`地址，然后再将堆块申请出来，链表操作完成以后`system`地址的值就会填入到`__free_hook`里了，再释放一个堆块即可得到shell。

### house of lemon
很可惜没有找到题目，哪位师傅如果有的话可以联系我一下，我也想看看。题目的设计与解法0x9a82师傅在它的[博客](https://www.cnblogs.com/Ox9A82/p/7112061.html)里写的很清楚了，有需要的可以学习学习。

## 小结

文章主要描述了有关堆利用中`global_max_fast`相关的原理以及题目的解析，感觉这种方法相关的一些场景包括：
* 可能能够得到libc地址。
* 能够控制free堆块的size。
* 能往任意地址写但是却无法控制写的内容。

以此来实现往`main_arena`后面的任意地址写堆块地址的效果，以实现后续的利用，相关的漏洞利用方式包括`unsorted bin attack`以及house of orange（IO file）等。

所有题目的链接和脚本在我的[github](https://github.com/ray-cp/ctf-pwn/tree/master/PWN_CATEGORY/heap/global_max_fast)里面，exp的编写用了[pwn_debug](https://github.com/ray-cp/pwn_debug)，因此再次向大家推荐下这个框架。

最后需要提一句的是脚本里面很多使用的符号在release版本的glibc中是没有的，大家本地调试的时候可能需要把偏移改一下。

文章首发于[先知社区](https://xz.aliyun.com/t/5082)

## 参考链接
1. [BCTF2018 baby_arena](https://www.jianshu.com/p/e1effb2e046e)
2. [0CTF 2016 - Zerostorage Writeup](http://brieflyx.me/2016/ctf-writeups/0ctf-2016-zerostorage/)
3. [胖哈勃杯Pwn400、Pwn500详解](https://www.cnblogs.com/Ox9A82/p/7112061.html)












