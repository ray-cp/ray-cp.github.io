---
layout: post
title:  "强网杯-pwn-writeup"
date:   2018-04-26 08:00:00
categories: CTF
permalink: /archivers/内强网杯-pwn-writeup
---
## opm
### 漏洞
add role中存在很明显的栈溢出漏洞，可以覆盖堆指针，同时堆指针中存在函数指针，可造成利用。

### 利用
由于开了PIE，最大的难题在于如何泄露地址，这题一开始一直想的是使用`\x00`覆盖最堆指针的最低位，由于使用了new，在堆首有很大一片空间，所以其实可以覆盖倒数第二位，这样控制的空间就大了很多，就可以很轻松的泄露出堆地址，泄露出堆地址后，泄露函数指针得到程序基址，再泄露`got`表得到libc基址，最后利用`one gadget`得到shell。

## note
### 漏洞
在change title选项中存在一字节溢出，可形成unlink攻击。

### 利用
使用change content中的`realloc`来实现free的功能。realloc的特性如下：
1. 对ptr进行判断，如果ptr为NULL，则函数相当于malloc(new_size),试着分配一块大小为new_size的内存，如果成功将地址返回，否则返回NULL。如果ptr不为NULL，则进入2
2. 查看ptr是不是在堆中，如果不是的话会跑出异常错误，会发生realloc invalid pointer。如果ptr在堆中，则查看new_size大小，如果new_size大小为0，则相当于free(ptr)，将ptr指针释放，返回NULL，如果new_size小于原大小，则ptr中的数据可能会丢失，只有new_size大小的数据会保存（这里很重要），如果size等于原大小，等于啥都没做，如果size大于原大小，则看ptr所在的位置还有没有足够的连续内存空间，如果有的话，分配更多的空间，返回的地址和ptr相同，如果没有的话，则会使用malloc分配更大的内存，将旧的内容拷贝到新的内存中，把旧的内存free掉，则返回新地址，否则返回NULL。
使用unlink功能修改`title`的全局指针，从而达到任意写的目的，最终复写`__realloc_hook`指针为system函数以获得shell。

## gamebox
### 漏洞
存在两个漏洞：
1. 一个是格式化字符串漏洞，地址在show rank选项里，地址为0x1033
2. 一个是`off-by-null`漏洞，在play选项中，地址是0x1689。

### 利用
第一个难题首先是绕过cookie的检查，cookie检查使用的是rand函数，由于种子未随机化，所以可以本地同步调用rand函数获得。接着使用格式化字符串漏洞来地址泄露获取相应libc以及程序基址等，其实可以使用格式化字符串一个漏洞就能拿到shell，只是比较麻烦，我当时使用的是格式化字符串漏洞。在这只是使用格式化字符串漏洞来泄露地址，最后使用`off-by-null`来构造`overlap chunk`构造fastbin attack来覆盖`malloc hook`指针。最后使用`one gadget`来获得shell。

## silent
### 漏洞
典型的堆题，漏洞很明显，free全局指针后没有清空，可以有`uaf`，也可以有`double free`，由于存在全局指针，`unlink attack`也可以。

### 利用
这里使用最快捷的`uaf`，由于给了`system`函数，所以也无需泄露，利用`uaf`修改`fastbin`的链表，直接把free的got改成system的plt即可。

## silent2
### 漏洞
仍然是`uaf`漏洞，但是无法申请与释放fastbin。

### 利用
无法利用fastbin，所以使用`uaf`构造了`overlap chunk`，最后`unlink`攻击得到shell。

## raise pig
### 漏洞
仍然是`uaf`，可以利用释放后内存空间没清空，并且使用的是read来输入name，不会在字符串后加入`'\x00'`。

### 利用
首先使用利用未清空内存空间来泄露libc地址，从而得到one gadget的地址，再构造`fastbin attack`，复写`malloc_hook`指针，但是通过malloc执行one gadget得不到shell，环境变量不对，看大佬的wp说是触发`malloc_printerr`函数来触发`malloc_hook`可以得到shell。新姿势。。。

## 小结
认真工作，认真生活，还有很多要学。
所有的[exp](https://github.com/ray-cp/ctf-pwn/tree/master/强网杯)在这里



