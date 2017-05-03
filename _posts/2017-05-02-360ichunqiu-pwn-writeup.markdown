---
layout: post
title:  "360春秋杯 pwn writeup"
date:   2017-05-02 24:00:00
categories: ctf
permalink: /archivers/360春秋杯-pwn-writeup
---

这段时间心有点浮躁，这样不太好，还是得沉住气，五一好好调整了下，继续出发。
这个比赛当时写出了一题smallest，第二题hiddenlove题目限制的厉害，确实不会写，看了大佬的writeup才会的，不过竟然是原题改编，也是有点尴尬，当然从比赛中还是学到了东西，这样是毋庸置疑的。

## smallest

题目很简单，应该使用汇编语言直接写的，通过`syscall`调用`read`，导致栈溢出，这题很尴尬，因为栈溢出返回地址并不能调用任何函数，同时还开了nx，所以得想其他的办法，想到了之前学的**srop**。关于`srop`的原理我在后面会给出相应的链接，就不重复了。通过`srop`去调用`mprotect`，将代码段改成可写的，然后读shllcode进去执行，这样就可以拿到shell了。

这题还有一个关键的地方就是该如何找到一个合适的`rsp`，`rsp`中保存着已知可执行的指令地址。这里困扰了我很久，最后在`0x400018`的地方存了程序的入口地址，原因是`elf`文件结构会保存程序入口，这样我们就可以回到main函数再一次写shellcode了，幸亏最后还是想了出来。
```C
gdb-peda$ x/4gx 0x400000
0x400000:   0x00010102464c457f  0x0000000000000000
0x400010:   0x00000001003e0002  0x00000000004000b0
```


## hiddenlove

这题漏洞在读入数据时有一个`off-by-one`的漏洞，在读入八个字节的`name`时会将之前申请的`secret`的指针地址的最后一个字节覆盖为`\x00`，这里一开始我就想到`shrink chunk`，但是当看到只允许进行一次编辑和删除的时候，就有点懵逼了。当时想了很久，什么`unlink`、`double free`啥的都想了，还是不行，所以最后放弃了。

后面看大佬的writeup，才知道在##libc2.23##之后，如果没有调用`setbuf(stdin,0)`的话，调用scanf会在堆上有一个缓存，即`scanf`的输入流在没有刷新的情况下会在堆上申请堆块存储。通过这个特性所以可以事先利用`scanf`可以多申请一个堆块，这个通过**控制输入的大小**以及构造好**最后16个字节(伪造堆块的`prev size`及`size`段)**使其在`secret`字段地址被覆盖为`\x00`后会构成新的堆块(从而在`free`的时候不会出错)。这样构成的堆块就包含了最开始的结构体，从而重新申请与编辑的时候实现了数据的写控制。这段话有点绕，当时我看别人writeup的时候也是有点晕，后面调了以后才懂的。

在能写数据以后，首先想的是泄露地址，将·`atoi`的`got`覆盖成`printf`的`plt`地址，这样就可以泄露地址得到`system`函数地址，同时还可以利用格式化字符串漏洞将控制编辑的字段重置，使得可以重新将`atoi`的`got`改成`system`函数地址，从而得到了shell。

## 链接

 [Sigreturn Oriented Programming (SROP) Attack攻击原理](http://www.freebuf.com/articles/network/87447.html)

[exp](https://github.com/ray-cp/ctf-pwn/tree/master/360ichunqiu) 

