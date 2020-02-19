---
layout: post
title:  "qemu-pwn-seccon-2018-q-escape"
date:   2019-12-12 08:00:00
categories: vm-escape
permalink: /archivers/qemu-pwn-seccon-2018-q-escape
---

**欢迎关注公众号[平凡路上](https://mp.weixin.qq.com/s/TR-JuE2nl3W7ZmufAfpBZA)，平凡路上是一个致力于二进制漏洞分析与利用经验交流的公众号。**

## 描述

[官方](https://github.com/SECCON/SECCON2018_online_CTF/tree/master/Pwn/q-escape)的描述如下：

```bash
q-escape

We developed a new device named CYDF :)
Ubuntu 16.04 latest
nc q-escape.pwn.seccon.jp 1337
```

将文件下下来，目录如下：

```bash
$ ll
-rw-rw-r--  1 raycp raycp 1.7M Aug 21 08:03 initramfs.igz
drwxr-xr-x  6 raycp raycp 4.0K Oct 22  2018 pc-bios
-rwxr-xr-x  1 raycp raycp  28M Oct 22  2018 qemu-system-x86_64
-rwxr-xr-x  1 raycp raycp  256 Oct 22  2018 run.sh
-rw-------  1 raycp raycp 7.9M Oct 22  2018 vmlinuz-4.15.0-36-generic
```

run.sh中的内容是：

```bash
#!/bin/sh
./qemu-system-x86_64 \
        -m 64 \
        -initrd ./initramfs.igz \
        -kernel ./vmlinuz-4.15.0-36-generic \
        -append "priority=low console=ttyS0" \
        -nographic \
        -L ./pc-bios \
        -vga std \
        -device cydf-vga \
        -monitor telnet:127.0.0.1:2222,server,nowait

```

可以知道设备名称是`cydf-vga`以及在本地的2222端口开启了qemu monitor。

## 分析

首先仍然是`sudo ./run.sh`把虚拟机跑起来，我的环境是ubuntu18，报了下面的错误：

```bash
./qemu-system-x86_64: error while loading shared libraries: libcapstone.so.3: cannot open shared object file: No such file or directory
```

解决方案：

```bash
sudo apt-get install libcapstone3
```

虚拟机跑起来的同时把`qemu-system-x86_64`拖进ida进行分析，查找`cydf-vga`相关函数：

![cydf-vga-related-function](https://raw.githubusercontent.com/ray-cp/ray-cp.github.io/master/_img/2019-12-12-qemu-pwn-seccon-2018-q-escape/cydf-vga-related-function.png)

查看`cydf_vga_class_init`函数，知道了它的`device_id`为`0xB8`、`vendor_id`为`0x1013`，`class_id` 为`0x300`。同时根据字符串`Cydf CLGD 54xx VGA`去搜索，进行相应比对，找到了该设备是`Cirrus CLGD 54xx VGA Emulator`改过来的。`Cirrus`在qemu中源码路径为[`./hw/display/cirrus_vga.c`](https://github.com/qemu/qemu/blob/master/hw/display/cirrus_vga.c)。

先在虚拟机中查看设备信息，根据设备id等信息，可以知道它是最后一个`00:04.0 Class 0300: 1013:00b8`：

```bash
/ # lspci
00:00.0 Class 0600: 8086:1237
00:01.3 Class 0680: 8086:7113
00:03.0 Class 0200: 8086:100e
00:01.1 Class 0101: 8086:7010
00:02.0 Class 0300: 1234:1111
00:01.0 Class 0601: 8086:7000
00:04.0 Class 0300: 1013:00b8
```

由于它里面的lspci不支持`-v`等参数，所以要看它的内存以及端口空间，可以去读取它的`resource`文件，可以看到它有三个mmio空间：

```bash
/ # cat /sys/devices/pci0000\:00/0000\:00\:04.0/resource
0x00000000fa000000 0x00000000fbffffff 0x0000000000042208
0x00000000febc1000 0x00000000febc1fff 0x0000000000040200
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x00000000febb0000 0x00000000febbffff 0x0000000000046200
```

另一个方法是`telnet 127.0.0.1 2222`连上它的[monitor](https://www.xuebuyuan.com/3206943.html)，可以看到相应的地址空间：

```bash
info pci
...
Bus  0, device   4, function 0:
    VGA controller: PCI device 1013:00b8
      BAR0: 32 bit prefetchable memory at 0xfa000000 [0xfbffffff].
      BAR1: 32 bit memory at 0xfebc1000 [0xfebc1fff].
      BAR6: 32 bit memory at 0xffffffffffffffff [0x0000fffe].
      id ""
```

一个奇怪的问题是在`cydf_init_common`函数中看到了三个注册I/O函数：

```c
memory_region_init_io(&s->cydf_vga_io, owner, &cydf_vga_io_ops, s, "cydf-io", 0x30uLL);
...
memory_region_init_io(&s->low_mem, owner, &cydf_vga_mem_ops, s, "cydf-low-memory", 0x20000uLL);
...
memory_region_init_io(&s->cydf_mmio_io, owner, &cydf_mmio_io_ops, s, "cydf-mmio", 0x1000uLL);
```

可以看到函数中注册了`0x30`大小的PMIO，`0x20000`大小的MMIO以及`0x1000`大小的MMIO。但是为啥在设备中只看到了`BAR1`中`0x1000`大小的MMIO空间，其余两个去哪里了？

在`cirrus_vga.c`中有下面两行注释：

```c
/* Register ioport 0x3b0 - 0x3df */
...
/* memory access between 0xa0000-0xbffff */
```

`cat /proc/iomem`和`cat /proc/ioports`查看相应的MMIO和PMIO：

```bash
/ # cat /proc/iomem
...
000a0000-000bffff : PCI Bus 0000:00
...
04000000-febfffff : PCI Bus 0000:00
...
  febc1000-febc1fff : 0000:00:04.0
  
/ # cat /proc/ioports
...
  03c0-03df : vga+
...
```

因此另外两个0x30大小的PMIO空间以及0x20000大小的MMIO空间看起来似乎是vga的地址空间，根据师傅们的writeup以及[Mapping of Display Memory into CPU Address Space ](http://www.osdever.net/FreeVGA/vga/vgamem.htm)和[Addressing details](https://en.wikipedia.org/wiki/Video_Graphics_Array#Addressing_details)可以知道，地址`000a0000-000bffff`确实是vga的空间。

有了源码的参考看起来会方便很多，接下来对比二者，以找到题目中什么地方被修改了。经过比对，最主要的变化是在`cydf_vga_mem_write`函数，同时在`CydfVGAState`结构体中加入了两个字段：

```c
000133D8 vs              VulnState_0 16 dup(?)
000134D8 latch           dd 4 dup(?)
```

`VulnState`的定义为：

```c
00000000 VulnState_0     struc ; (sizeof=0x10, align=0x8, copyof_4201)
00000000                                         ; XREF: CydfVGAState/r
00000000                                         ; CydfVGAState_0/r
00000000 buf             dq ?                    ; offset
00000008 max_size        dd ?
0000000C cur_size        dd ?
00000010 VulnState_0     ends
```

接下来看`cydf_vga_mem_write`函数存在区别的部分主要的内容是什么（漏洞是什么）：

```c
void __fastcall cydf_vga_mem_write(CydfVGAState *opaque, hwaddr addr, uint64_t mem_value, uint32_t size)
{
  ...

  if ( !(opaque->vga.sr[7] & 1) )
  {
    vga_mem_writeb(&opaque->vga, addr, mem_value);
    return;
  }
  if ( addr <= 0xFFFF )
  {
    ...
  }
  if ( addr - 0x18000 <= 0xFF )
  {
    ...
  }
  else
  {
    v6 = 205 * opaque->vga.sr[0xCC];
    LOWORD(v6) = opaque->vga.sr[0xCC] / 5u;
    cmd = opaque->vga.sr[0xCC] - 5 * v6;
    if ( *(_WORD *)&opaque->vga.sr[0xCD] )      // cmd = sr[0xcc]%5
      LODWORD(mem_value) = (opaque->vga.sr[0xCD] << 16) | (opaque->vga.sr[0xCE] << 8) | mem_value;                                      // idx=sr[0xcd]
    if ( (_BYTE)cmd == 2 )                      // cmd 2 printf buff
    {
      idx = BYTE2(mem_value);
      if ( idx <= 0x10 )
      {
        v25 = (char *)*((_QWORD *)&opaque->vga.vram_ptr + 2 * (idx + 0x133D));
        if ( v25 )
          __printf_chk(1LL, v25);
      }
    }
    else
    {
      if ( (unsigned __int8)cmd <= 2u )
      {
        if ( (_BYTE)cmd == 1 )                  // cmd 1 vs buff[cur_size++]=value, cur_size < max_size
        {
          if ( BYTE2(mem_value) > 0x10uLL )
            return;
          v8 = (__int64)opaque + 16 * BYTE2(mem_value);
          vs_buff = *(_QWORD *)(v8 + 0x133D8);  // 0x133d8 vuln_state buff
          if ( !vs_buff )
            return;
          cur_size = *(unsigned int *)(v8 + 0x133E4);// 0x133e4 cur_size
          if ( (unsigned int)cur_size >= *(_DWORD *)(v8 + 0x133E0) )// 0x133e0 max_size
            return;
LABEL_26:
          *(_DWORD *)(v8 + 0x133E4) = cur_size + 1;
          *(_BYTE *)(vs_buff + cur_size) = mem_value;
          return;
        }
        goto LABEL_35;
      }
      if ( (_BYTE)cmd != 3 )
      {
        if ( (_BYTE)cmd == 4 )                  // cmd 4 vs buff[cur_size++]=value, no cur_size check
        {
          if ( BYTE2(mem_value) > 0x10uLL )
            return;
          v8 = (__int64)opaque + 16 * BYTE2(mem_value);
          vs_buff = *(_QWORD *)(v8 + 0x133D8);
          if ( !vs_buff )
            return;
          cur_size = *(unsigned int *)(v8 + 0x133E4);
          if ( (unsigned int)cur_size > 0xFFF )
            return;
          goto LABEL_26;
        }
LABEL_35:
        v20 = vulncnt;
        if ( vulncnt <= 0x10 && (unsigned __int16)mem_value <= 0x1000uLL )// cmd 0 vs buff[vulcnt]=malloc(value)
        {
          mem_valuea = mem_value;
          ptr = malloc((unsigned __int16)mem_value);
          v22 = (__int64)opaque + 16 * v20;
          *(_QWORD *)(v22 + 0x133D8) = ptr;
          if ( ptr )
          {
            vulncnt = v20 + 1;
            *(_DWORD *)(v22 + 0x133E0) = mem_valuea;
          }
        }
        return;
      }
      if ( BYTE2(mem_value) <= 0x10uLL )        // cmd 1 set max_size
      {
        v23 = (__int64)opaque + 16 * BYTE2(mem_value);
        if ( *(_QWORD *)(v23 + 0x133D8) )
        {
          if ( (unsigned __int16)mem_value <= 0x1000u )
            *(_QWORD *)(v23 + 0x133E0) = (unsigned __int16)mem_value;
        }
      }
    }
  }
}
```

最主要的区别是增加了`0x10000-0x18000`地址空间的处理代码，通过代码可以看到增加的功能为`vs`的处理代码，`opaque->vga.sr[0xCC]`为`cmd`，`opaque->vga.sr[0xCD]`为idx，功能描述如下：

1. cmd为0时，申请value&0xffff空间大小的堆，并放置`vs[vulncnt]`中，同时初始化`max_size`。
2. cmd为1时，设置`idx`所对应的`vs[idx]`的`max_size`为`value&0xffff`。
3. cmd为2时，`printf_chk(1,vs[idx].buff)`。
4. cmd为3时，当`cur_size<max_size`时，`vs[idx].buff[cur_sizee++]=value&0xff`。
5. cmd为4时，`vs[idx].buff[cur_sizee++]=value&0xff`。

漏洞主要有两个地方：

* 一个是堆溢出。cmd为4时，可以设置`max_size`，对`max_size`没有进行检查也没有对堆块进行`realloc`，后续按这个size进行写，导致溢出。
* 另一个是数组越界。idx最多可以为0x10，即最多可以寻址`vs[0x10]`，而`vs`大小只有16，即`vs[0xf]`。vs[0x10]则士后面的`latch[0]`，导致会越界访问到后面的latch数组的第一个元素。

还有要解决的问题就是如何触发漏洞代码。除了`addr`之外，还需要使得`(opaque->vga.sr[7]&1 ==1) `以绕过前面的`if`判断、设置`opaque->vga.sr[0xCC]`来设置cmd以及设置`opaque->vga.sr[0xCD]`设置idx。

在代码中可以找到`cydf_vga_ioport_write`函数中可以设置`opaque->vga.sr`。`addr`为`0x3C4`，`vulue`为`vga.sr`的`index`；当`addr`为`0x3C5`时，`value`为`vga.sr[index]`的值。从而可以通过`cydf_vga_ioport_write`设置`vga.sr[7]`、`vga.sr[0xCC]`以及`vga.sr[0xCD]`。

还需要说明的是可以通过`cydf_vga_mem_read`函数来设置`opaque->latch[0]`，`latch[0]`刚好是`vs`越界访问到的元素。

```c
uint64_t __fastcall cydf_vga_mem_read(CydfVGAState *opaque, hwaddr addr, uint32_t size)
{
  ...
  latch = opaque->latch[0];
  if ( !(_WORD)latch )
  {
    v4 = (opaque->vga.sr[7] & 1) == 0;
    opaque->latch[0] = addr | latch;            // set latch low dword
    if ( !v4 )
      goto LABEL_3;
    return vga_mem_readb(&opaque->vga, addr);
  }
  v4 = (opaque->vga.sr[7] & 1) == 0;
  opaque->latch[0] = (_DWORD)addr << 16;        // set latch high word
  if ( v4 )
    return vga_mem_readb(&opaque->vga, addr);
    ...
```



## 利用

漏洞已经清楚了，利用则可以利用数组越界漏洞来实现任意地址写。具体原理为：可以通过`cydf_vga_mem_read`函数将`opaque->latch[0]`设置成想要写的任意地址；再将`opaque->vga.sr[0xCD]`（idx）设置成0x10，再往`vs[0x10]`写数据时即实现了往任意地址（`latch[0]`中的地址）写数据。

在代码中存在`qemu_log`函数，关键代码如下：

```c
int qemu_log(const char *fmt, ...)
{

  ...
  if ( qemu_logfile )
  {
   ...
    ret = vfprintf(qemu_logfile, fmt, va);
  ...
  }
...
}
```



且因为程序没有开PIE，结合上面的`qemu_log`函数，可以做到只利用任意地址写就能实现任意命令执行。具体利用的步骤则如下：

1. 往bss段数据中写入要执行的命令`cat /root/flag`。
2. 将该bss地址写入到全局变量`qemu_logfile`中。
3. 将`vfprintf`函数got表覆盖为`system`函数的plt表地址。
4. 将`printf_chk`函数got表覆盖为`qemu_log`函数的地址。
5. 利用cmd为2时，触发`printf_chk`，最终实现system函数的调用，同时参数也可控。

最后一个问题，该如何去交互。以往都是用户态打开对应的`resource0`文件进行映射，实现mmio的访问。但是这次`000a0000-000bffff`地址空间不知道该打开哪个文件去映射。访问该地址空间才可以实现对`cydf_vga_mem_write`以及`cydf_vga_mem_read`的访问。

这时我们可以利用`/dev/mem`文件，[`dev/mem`](https://yq.aliyun.com/articles/592075)是物理内存的全映像，可以用来访问物理内存，用mmap来访问物理内存以及外设的IO资源，是实现用户空间驱动的一种方法。具体可以`man mem`去查看详情。

调用`cydf_vga_ioport_write`去设置`opaque->vga.sr[]`以及`opaque->vga.sr_index`，有两种方式（exp中使用的是前者）可以实现对`cydf_vga_ioport_write`函数的调用：

一种是利用访问`febc1000-febc1fff`地址空间，触发`cydf_mmio_write`从而实现对 `cydf_vga_ioport_write`的调用。

```c
void __fastcall cydf_mmio_write(CydfVGAState *opaque, hwaddr addr, uint64_t val, unsigned int size)
{
  if ( addr > 0xFF )
    cydf_mmio_blt_write(opaque, addr - 0x100, val);
  else
    cydf_vga_ioport_write(opaque, addr + 0x10, val, size);
}
```

一种是直接利用PMIO，`out`类指令以及`in`类指令直接对相应的`0x3b0 - 0x3df`端口进行访问，实现对该函数的调用。

## 小结

即使做完了这题，对于vga设备的原理还是不太了解，还是有很多的事值得去做、需要去做。

感觉这部分应该有不少是我理解错误了的或者没考虑到的，欢迎各位师傅对我进行指导。

相关文件与脚本[链接](https://github.com/ray-cp/vm-escape/tree/master/qemu-escape/seccon-2018-q-escape)

## 参考链接

1. [使用 monitor command 监控 QEMU 运行状态](https://www.xuebuyuan.com/3206943.html)
2. [Linux中通过/dev/mem操控物理地址](https://yq.aliyun.com/articles/592075)
3. [Mapping of Display Memory into CPU Address Space](http://www.osdever.net/FreeVGA/vga/vgamem.htm)
4. [SECCON2018_online_CTF/q-escape](https://github.com/SECCON/SECCON2018_online_CTF/tree/master/Pwn/q-escape)
5. [seccon 2018 - q-escape](https://uaf.io/exploitation/2018/11/22/seccon-2018-q-escape.html)
6. [q-escape - SECCON 2018](https://devcraft.io/2018/11/22/q-escape-seccon-2018.html)
7. [cirrus_vga.c](https://github.com/qemu/qemu/blob/master/hw/display/cirrus_vga.c)

文章先发于[先知](https://xz.aliyun.com/t/6869)社区。

