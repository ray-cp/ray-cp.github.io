---
layout: post
title:  "qemu pwn-hitb gesc 2017 babyqemu writeup"
date:   2019-11-15 18:00:00
categories: vm-escape
permalink: /archivers/qemu-pwn-hitb-gesc-2017-babyqemu-writeup
---

## 描述

下载文件，解压后文件结构如下：

```bash
$ ls -l
total 407504
-rwxr-xr-x@  1 raycp  staff        281 Jul 11  2017 launch.sh
drwxr-xr-x@ 59 raycp  staff       1888 Jul 11  2017 pc-bios
-rwxr-xr-x@  1 raycp  staff   39682064 Jul 11  2017 qemu-system-x86_64
-rw-r--r--@  1 raycp  staff    3864064 Jul 11  2017 rootfs.cpio
-rwxr-xr-x@  1 raycp  staff    7308672 Jul 11  2017 vmlinuz-4.8.0-52-generic
```

其中`launch.sh`内容如下：

```bash
#!/bin/sh
./qemu-system-x86_64 \
-initrd ./rootfs.cpio \
-kernel ./vmlinuz-4.8.0-52-generic \
-append 'console=ttyS0 root=/dev/ram oops=panic panic=1' \
-enable-kvm \
-monitor /dev/null \
-m 64M --nographic  -L ./dependency/usr/local/share/qemu \
-L pc-bios \
-device hitb,id=vda
```

## 分析

首先将设备`sudo ./launch.sh`运行起来并将`qemu-system-x86_64`拖到IDA里面进行分析。

运行起来的时候可能会报错如下错误，`sudo apt-get install libcurl3`即可解决。登录用户名为`root`，密码为空。

```bash
./qemu-system-x86_64: /usr/lib/x86_64-linux-gnu/libcurl.so.4: version `CURL_OPENSSL_3' not found (required by ./qemu-system-x86_64)
```

根据命令行参数`-device hitb`，大概知道了要pwn的目标pci设备是`hitb`。在IDA里面搜索hitb相关的函数，相关函数列表如下：

![hitb_device_relative_function](](https://raw.githubusercontent.com/ray-cp/ray-cp.github.io/master/_img/2019-11-15-qemu-pwn-hitb-gesc-2017-babyqemu-writeup/hitb_device_relative_function.png)

查看`pci_hitb_register_types`，知道了该设备所对应的`TypeInfo`。并且它的`class_init`函数为`hitb_class_init`，`instance_init`函数为`hitb_instance_init`。

其对应的结构体为`HitbState`：

```c
00000000 HitbState       struc ; (sizeof=0x1BD0, align=0x10, copyof_1493)
00000000 pdev            PCIDevice_0 ?
000009F0 mmio            MemoryRegion_0 ?
00000AF0 thread          QemuThread_0 ?
00000AF8 thr_mutex       QemuMutex_0 ?
00000B20 thr_cond        QemuCond_0 ?
00000B50 stopping        db ?
00000B51                 db ? ; undefined
00000B52                 db ? ; undefined
00000B53                 db ? ; undefined
00000B54 addr4           dd ?
00000B58 fact            dd ?
00000B5C status          dd ?
00000B60 irq_status      dd ?
00000B64                 db ? ; undefined
00000B65                 db ? ; undefined
00000B66                 db ? ; undefined
00000B67                 db ? ; undefined
00000B68 dma             dma_state ?
00000B88 dma_timer       QEMUTimer_0 ?
00000BB8 dma_buf         db 4096 dup(?)
00001BB8 enc             dq ?                    ; offset
00001BC0 dma_mask        dq ?
00001BC8                 db ? ; undefined
00001BC9                 db ? ; undefined
00001BCA                 db ? ; undefined
00001BCB                 db ? ; undefined
00001BCC                 db ? ; undefined
00001BCD                 db ? ; undefined
00001BCE                 db ? ; undefined
00001BCF                 db ? ; undefined
00001BD0 HitbState       ends
```

先看`hitb_class_init`函数：

```c
void __fastcall hitb_class_init(ObjectClass_0 *a1, void *data)
{
  PCIDeviceClass *v2; // rax

  v2 = (PCIDeviceClass *)object_class_dynamic_cast_assert(
                           a1,
                           "pci-device",
                           "/mnt/hgfs/eadom/workspcae/projects/hitbctf2017/babyqemu/qemu/hw/misc/hitb.c",
                           469,
                           "hitb_class_init");
  v2->revision = 16;
  v2->class_id = 255;
  v2->realize = (void (*)(PCIDevice_0 *, Error_0 **))pci_hitb_realize;
  v2->exit = (PCIUnregisterFunc *)pci_hitb_uninit;
  v2->vendor_id = 0x1234;
  v2->device_id = 0x2333;
}
```

看到它所对应的`device_id`为`0x2333`，`vendor_id`为`0x1234`。在qemu虚拟机里查看相应的pci设备：

```bash
# lspci
00:00.0 Class 0600: 8086:1237
00:01.3 Class 0680: 8086:7113
00:03.0 Class 0200: 8086:100e
00:01.1 Class 0101: 8086:7010
00:02.0 Class 0300: 1234:1111
00:01.0 Class 0601: 8086:7000
00:04.0 Class 00ff: 1234:2333
```

`00:04.0`为相应的`hitb`设备，不知道为啥`lspci`命令没有`-v`选项，要查看I/O信息，查看`resource`文件：

```bash
# cat /sys/devices/pci0000\:00/0000\:00\:04.0/resource
0x00000000fea00000 0x00000000feafffff 0x0000000000040200
0x0000000000000000 0x0000000000000000 0x0000000000000000
```

`resource`文件内容的格式为`start_address end_address flag `，根据`flag`最后一位可知存在一个MMIO的内存空间，地址为`0x00000000fea00000`，大小为`0x100000`

查看`pci_hitb_realize`函数：

```c
void __fastcall pci_hitb_realize(HitbState *pdev, Error_0 **errp)
{
  pdev->pdev.config[61] = 1;
  if ( !msi_init(&pdev->pdev, 0, 1u, 1, 0, errp) )
  {
    timer_init_tl(&pdev->dma_timer, main_loop_tlg.tl[1], 1000000, (QEMUTimerCB *)hitb_dma_timer, pdev);
    qemu_mutex_init(&pdev->thr_mutex);
    qemu_cond_init(&pdev->thr_cond);
    qemu_thread_create(&pdev->thread, "hitb", (void *(*)(void *))hitb_fact_thread, pdev, 0);
    memory_region_init_io(&pdev->mmio, &pdev->pdev.qdev.parent_obj, &hitb_mmio_ops, pdev, "hitb-mmio", 0x100000uLL);
    pci_register_bar(&pdev->pdev, 0, 0, &pdev->mmio);
  }
```

函数首先注册了一个[timer](https://rickylss.github.io/qemu/2019/05/20/qemu-timer.html)，处理回调函数为`hitb_dma_timer`，接着注册了`hitb_mmio_ops`内存操作的结构体，该结构体中包含`hitb_mmio_read`以及`hitb_mmio_write`，同时也看到了`size`大小为`0x100000`。

接下来仔细分析`hitb_mmio_read`以及`hitb_mmio_write`函数。

`hitm_mmio_read`函数没有什么关键的操作，主要就是通过`addr`去读取结构体中的相应字段。

关键的在`hitm_mmio_write`函数中，关键代码部分如下：

```c
void __fastcall hitb_mmio_write(HitbState *opaque, hwaddr addr, uint64_t value, unsigned int size)
{
  uint32_t v4; // er13
  int v5; // edx
  bool v6; // zf
  int64_t v7; // rax

  if ( (addr > 0x7F || size == 4) && (!((size - 4) & 0xFFFFFFFB) || addr <= 0x7F) )
  {
    if ( addr == 0x80 )
    {
      if ( !(opaque->dma.cmd & 1) )
        opaque->dma.src = value;                // 0x80 set src
    }
    else
    {
      v4 = value;
      if ( addr > 128 )
      {
        if ( addr == 140 )
        {
          ...
        }
        else if ( addr > 0x8C )
        {
          if ( addr == 144 )
          {
            if ( !(opaque->dma.cmd & 1) )
              opaque->dma.cnt = value;          // 144 set cnt
          }
          else if ( addr == 152 && value & 1 && !(opaque->dma.cmd & 1) )
          {
            opaque->dma.cmd = value;            // 152 set cmd
            v7 = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL_0);
            timer_mod(
              &opaque->dma_timer,
              ((signed __int64)((unsigned __int128)(0x431BDE82D7B634DBLL * (signed __int128)v7) >> 64) >> 18)      //trigger timer
            - (v7 >> 63)
            + 100);
          }
        }
        ...
        else if ( addr == 136 && !(opaque->dma.cmd & 1) )
        {
          opaque->dma.dst = value;              // 136 set dst
        }
      }
     ...
}
```

关键操作包括：

1. 当`addr`为`0x80`的时候，将`value`赋值给`dma.src`。
2. 当`addr`为`144`的时候，将`value`赋值给`dma.cnt`。
3. 当`addr`为`152`的时候，将`value`赋值给`dma.cmd`，并触发timer。
4. 当`addr`为`136`的时候，将`value`赋值给`dma.dst`。

可以看到`hitb_mmio_write`函数基本上是通过`addr`将设备结构体中的`dma`字段赋值，`dma`的定义为：

```c
00000000 dma_state       struc ; (sizeof=0x20, align=0x8, copyof_1491)
00000000                                         ; XREF: HitbState/r
00000000 src             dq ?
00000008 dst             dq ?
00000010 cnt             dq ?
00000018 cmd             dq ?
00000020 dma_state       ends
```

再去看timer触发之后的操作，即`hitb_dma_timer`函数：

```c
void __fastcall hitb_dma_timer(HitbState *opaque)
{
  dma_addr_t cmd; // rax
  __int64 idx; // rdx
  uint8_t *addr; // rsi
  dma_addr_t v4; // rax
  dma_addr_t v5; // rdx
  uint8_t *v6; // rbp
  uint8_t *v7; // rbp

  cmd = opaque->dma.cmd;
  if ( cmd & 1 )
  {
    if ( cmd & 2 )
    {
      idx = (unsigned int)(LODWORD(opaque->dma.src) - 0x40000);
      if ( cmd & 4 )
      {
        v7 = (uint8_t *)&opaque->dma_buf[idx];
        ((void (__fastcall *)(uint8_t *, _QWORD))opaque->enc)(v7, LODWORD(opaque->dma.cnt));
        addr = v7;
      }
      else
      {
        addr = (uint8_t *)&opaque->dma_buf[idx];
      }
      cpu_physical_memory_rw(opaque->dma.dst, addr, opaque->dma.cnt, 1);
      v4 = opaque->dma.cmd;
      v5 = opaque->dma.cmd & 4;
    }
    else
    {
      v6 = (uint8_t *)&opaque[0xFFFFFFDBLL].dma_buf[(unsigned int)opaque->dma.dst + 0x510];
      LODWORD(addr) = (_DWORD)opaque + opaque->dma.dst - 0x40000 + 0xBB8;
      cpu_physical_memory_rw(opaque->dma.src, v6, opaque->dma.cnt, 0);
      v4 = opaque->dma.cmd;
      v5 = opaque->dma.cmd & 4;
     ...
}
```

可以看到主要操作包含三部分：

1. 当dma.cmd为`2|1`时，会将`dma.src`减`0x40000`作为索引`i`，然后将数据从`dma_buf[i]`拷贝利用函数`cpu_physical_memory_rw`拷贝至物理地址`dma.dst`中，拷贝长度为`dma.cnt`。
2. 当dma.cmd为`4|2|1`时，会将`dma.dst`减`0x40000`作为索引`i`，然后将起始地址为`dma_buf[i]`，长度为`dma.cnt`的数据利用利用`opaque->enc`函数加密后，再调用函数`cpu_physical_memory_rw`拷贝至物理地址`opaque->dma.dst`中。
3. 当dma.cmd为`0|1`时，调用`cpu_physical_memory_rw`将物理地址中为`dma.dst`，长度为`dma.cnt`，拷贝到`dma.dst`减`0x40000`作为索引`i`，目标地址为`dma_buf[i]`的空间中。

到这里基本上可以看出这个设备的功能，主要是实现了一个`dma`机制。DMA(Direct Memory Access，直接内存存取) 是所有现代电脑的重要特色，它允许不同速度的硬件装置来沟通，而不需要依赖于 CPU 的大量中断负载。DMA 传输将数据从一个地址空间复制到另外一个地址空间。当CPU 初始化这个传输动作，传输动作本身是由 DMA 控制器来实行和完成。

即首先通过访问mmio地址与值（`addr`与`value`），在`hitb_mmio_write`函数中设置好`dma`中的相关值（`src`、`dst`以及`cmd`)。当需要`dma`传输数据时，设置`addr`为152，就会触发时钟中断，由另一个线程去处理时钟中断。

时钟中断调用`hitb_dma_timer`，该函数根据`dma.cmd`的不同调用`cpu_physical_memory_rw`函数将数据从物理地址拷贝到`dma_buf`中或从`dma_buf`拷贝到物理地址中。

功能分析完毕，漏洞在哪儿呢？我们可以看到`hitb_dma_timer`中拷贝数据时`dma_buf`中的索引是可控的，且没有限制。因此我们可以通过设置其相应的值导致越界读写，读写的数据长度也是可控的`dma.cnt`。而`dma_buf`的大小是有限的（`4096`），所以当我们的索引大于4096的时候就会发生越界读写，造成非预期结果。

## 利用

整个利用流程包括：

1. 首先是越界读的内容，往`dma_buf`往后看到了`enc`指针，可以读取该指针的值以实现地址泄露。泄露地址后根据偏移，可以得到程序基址，然后计算得到`system plt`地址。
2. 将参数`cat /root/flag`写入到`buf_buf`中。
3. 其次是越界写的内容，我们可以将`system plt`地址写入到`enc`指针，最后触发`enc`函数实现`system`函数的调用，实现`system("cat /root/flag")`。

需要指出的一点是`cpu_physical_memory_rw`是使用的物理地址作为源地址或目标地址，因此我们需要先申请一段内存空间，并将其转换至其物理地址。虚拟地址转换到物理地址转换在前面[文章](https://ray-cp.github.io/archivers/qemu-pwn-basic-knowledge#qemu概述)也描述过，可以通过读取 `/proc/$pid/pagemap`实现转换。

### 动态调试

我一开始也尝试往启动脚本中加入` -netdev user,id=net0,hostfwd=tcp::5555-:22`来实现ssh的端口转发，然后将exp通过scp传上去。但是结果失败了，只能想其它办法。

因为这是使用`cpio`作为文件系统的，所以可以先将该文件系统解压，然后将exp放入其中，最后再启动虚拟机。

首先是解压文件：

```bash
1. gunzip  XXX.cpio.gz
2. cpio -idmv < XXX.cpio
```

然后将`exp.c`编写好，放到解压出来的文件夹里。运行`make`命令，编译exp并重打包cpio，`makefile`内容如下：

```bash
ALL:
    gcc -O0 -static -o exp exp.c
    find . | cpio -o --format=newc > ../rootfs.cpio
```

为了方便调试可以先`sudo gdb ./qemu-system-x86_64`调试进程，下好断点后再用下面的命令启动虚拟机：

```bash
pwndbg> r -initrd ./rootfs.cpio -kernel ./vmlinuz-4.8.0-52-generic -append 'console=ttyS0 root=/dev/ram oops=panic panic=1' -enable-kvm -monitor /dev/null -m 64M --nographic  -L ./dependency/usr/local/share/qemu -L pc-bios -device hitb,id=vda
```

再提一句，直接在gdb里面最后执行system起一个新进程的时候可能会报下面的错误。不要以为exp没写对，要是看到了执行到system并且参数也对了，不用gdb调试，直接起虚拟机，再执行一遍exp，就可以看到成功逃逸了。

```bash
# [New process 4940]
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
process 4940 is executing new program: /bin/dash
/build/gdb-JPMZNV/gdb-8.1/gdb/breakpoint.c:13230: internal-error: void delete_breakpoint(breakpoint*): Assertion `bpt != NULL' failed.
A problem internal to GDB has been detected,
further debugging may prove unreliable.

This is a bug, please report it.  For instructions, see:
<http://www.gnu.org/software/gdb/bugs/>.

[1]    4926 abort      sudo gdb ./qemu-system-x86_64
```

## 小结

其实对于qemu的timer以及dma都还不太清楚，后面也还需要再学习。学习qemu pci设备也可以看qemu的`edu`设备：[edu.c](https://github.com/qemu/qemu/blob/master/hw/misc/edu.c)

相关文件以及脚本[链接](https://github.com/ray-cp/vm-escape/tree/master/qemu-escape/hitb-gsec-2017-babyqemu)

## 参考链接

1. [HITB GSEC 2017: babyqemu](https://kitctf.de/writeups/hitb2017/babyqemu)
2. [DMA（直接存储器访问）](https://baike.baidu.com/item/DMA/2385376?fr=aladdin)
3. [QEMU timer模块分析](https://rickylss.github.io/qemu/2019/05/20/qemu-timer.html)
4. [edu.c](https://github.com/qemu/qemu/blob/master/hw/misc/edu.c)

文章先发于[先知](https://xz.aliyun.com/t/6694)社区。

