---
layout: post
title: qemu-pwn 强网杯2019 两道qemu逃逸题writeup
date: 2020-02-19 20:20:16
categories: vm-escape
permalink: /archivers/qemu-pwn-强网杯2019-两道qemu逃逸题writeup
---

欢迎关注公众号[平凡路上](https://mp.weixin.qq.com/s/TR-JuE2nl3W7ZmufAfpBZA)，平凡路上是一个致力于二进制漏洞分析与利用经验交流的公众号。



终于到了这里，把qwb2019的这两题qemu逃逸题复现之后，qemu pwn的复现到这里就告一段落，接下来将会去分析几个qemu的cve。qwb初赛和决赛各有一道qemu逃逸题，初赛是`qwct`，决赛是`ExecChrome`。

因为通过前面的几题分析，对这类pwn题有了一定的掌握。部分分析过程可以省略，所以此次也是将两题写在了一起。

## qwct

### 描述

文件目录：

```bash
$ ll
-rwxrw-rw-  1 raycp raycp  179 Aug 26 06:01 launch.sh
drwxr-xr-x  6 raycp raycp 4.0K Sep  6  2017 pc-bios
-rwxr-xr-x  1 raycp raycp  53M May 25 18:07 QWCT_qemu-system-x86_64
-rw-rw-r--  1 raycp raycp 3.1M Aug 28 04:42 rootfs.cpio
-r-xr-xr-x  1 raycp raycp 8.2M Jun  3 23:37 vmlinuz-5.0.5-generic

```

launch.sh

```bash
#!/bin/bash
./qemu-system-x86_64 -initrd ./rootfs.cpio -nographic -kernel ./vmlinuz-5.0.5-generic -L pc-bios/  -append "priority=low console=ttyS0" -device qwb -monitor /dev/null
```

漏洞应该会在`qwb`设备中。

### 分析

解压文件：

```bash
mkdir cpio
cd cpio
mv ../rootfs.cpio ./
cpio -idmv < rootfs.cpio
```

把`qemu-system-x86_64`拖到IDA里面，同时`sudo ./launch.sh`运行起来。

程序报错：

```bash
./qemu-system-x86_64: error while loading shared libraries: libncursesw.so.6: cannot open shared object file: No such file or directory
```

解决方法：

```bash
sudo wget -O /tmp/libtinfo6 http://mirrors.kernel.org/ubuntu/pool/main/n/ncurses/libtinfo6_6.1+20180210-4ubuntu1_amd64.deb
sudo dpkg -i /tmp/libtinfo6
sudo rm /tmp/libtinfo6

sudo wget -O /tmp/libncursesw6 http://mirrors.kernel.org/ubuntu/pool/main/n/ncurses/libncursesw6_6.1+20180210-4ubuntu1_amd64.deb 
sudo dpkg -i /tmp/libncursesw6
sudo rm /tmp/libncursesw6
```

又报错：

```bash
./qemu-system-x86_64: error while loading shared libraries: libgfapi.so.0: cannot open shared object file: No such file or directory
```

解决方法：

```bash
sudo wget -O /tmp/glusterfs-common http://mirrors.kernel.org/ubuntu/pool/universe/g/glusterfs/glusterfs-common_3.7.6-1ubuntu1_amd64.deb
sudo dpkg -i /tmp/glusterfs-common 
sudo rm /tmp/glusterfs-common 

sudo apt-get install liblvm2app2.2
sudo apt --fix-broken install
```

IDA分析结束后，搜索`qwb`相关函数。

看`qwb_class_init`函数，知道了它的`vendor_id`、`device_id`以及`realize`为`pci_qwb_realize`。

```c
  k->revision = 0x10;
  k->class_id = 0xFF;
  k->realize = (void (__cdecl *)(PCIDevice_0 *, Error_0 **))pci_qwb_realize;
  k->exit = (PCIUnregisterFunc *)pci_qwb_uninit;
  k->vendor_id = 0x1234;
  k->device_id = 0x8848u;
  v2->categories[0] |= 0x80uLL;
```

去看`pci_qwb_realize`函数，看到它只注册了一个大小为`0x100000`的mmio，结构体为`qwb_mmio_ops`，其对应的IO函数为`qwb_mmio_read`以及`qwb_mmio_write`。

在分析函数前，看下它的`QwbState`相关结构体，后续会分析会使用得到。

```c
00000000 crypto_status   struc ; (sizeof=0x1818, align=0x8, mappedto_4600)
00000000                                         ; XREF: QwbState/r
00000000 statu           dq ?
00000008 crypt_key       db 2048 dup(?)
00000808 input_buf       db 2048 dup(?)
00001008 output_buf      db 2048 dup(?)
00001808 encrypt_function dq ?                   ; offset
00001810 decrypt_function dq ?                   ; offset
00001818 crypto_status   ends
00001818
00000000 ; ---------------------------------------------------------------------------
00000000
00000000 QwbState        struc ; (sizeof=0x2250, align=0x10, copyof_4601)
00000000 pdev            PCIDevice_0 ?
000008E0 mmio            MemoryRegion_0 ?
000009D0 thread          QemuThread_0 ?
000009D8 crypto_statu_mutex QemuMutex_0 ?
00000A08 crypto_buf_mutex QemuMutex_0 ?
00000A38 crypto          crypto_status ?
00002250 QwbState        ends
```

先看`qwb_mmio_write`函数，该函数的主要功能为两个：

* 当addr为0x1000至0x17ff时，且当`opaque->crypto.statu`为3时，设置`opaque->crypto.crypt_key[addr-0x1000]`的值为value。
* 当addr为0x2000至0x27ff时，且当`opaque->crypto.statu`为1时，设置`opaque->crypto.input_buf[addr-0x2000]`的值为value。

可以看到`qwb_mmio_write`函数的主要功能就是设置`input_buf`以及`crypto_key`，且由于缓冲区空间大小都是0x800，输入刚好可以填满，不存在溢出。

接下来看`qwb_mmio_read`函数，该函数功能较复杂，包括：

* 当addr为0时，且当`opaque->crypto.statu`不为5时，初始化所有的缓冲区空间，包括`input_buf`、`output_buf`以及`crypt_key`
* 当addr为1时，且当`opaque->crypto.statu`为2或者0时，设置statu为3。
* 当addr为2时，且当`opaque->crypto.statu`为4或者0时，设置statu为1。
* 当addr为3时，且当`opaque->crypto.statu`为3时，设置statu为4。
* 当addr为4时，且当`opaque->crypto.statu`为1时，设置statu为2。
* 当addr为5时，且当`opaque->crypto.statu`为2或者4时，设置`opaque->crypto.encrypt_function`的值为`aes_encrypt_function`函数。
* 当addr为6时，且当`opaque->crypto.statu`为2或者4时，设置`opaque->crypto.decrypt_function`的值为`aes_decrypto_function`函数。
* 当addr为7时，且当`opaque->crypto.statu`为2或者4时，设置`opaque->crypto.encrypt_function`的值为`stream_encrypto_function`函数。
* 当addr为8时，且当`opaque->crypto.statu`为2或者4时，设置`opaque->crypto.decrypt_function`的值为`stream_decrypto_function`函数。
* 当addr为9时，且当`opaque->crypto.statu`为2或者4时，且当`opaque->crypto.encrypt_function`的值不为空时，创建线程`qwb_encrypt_processing_thread`，并设置statu为5。
* 当addr为10时，且当`opaque->crypto.statu`为2或者4时，且当`opaque->crypto.decrypt_function`的值不为空时，创建线程`qwb_decrypt_processing_thread`，并设置statu为7。
* 其余情况则可以根据addr的值读取`input_buff`、`crypto_key`以及`output_buff`。

`qwb_encrypt_processing_thread`线程以及`qwb_decrypt_processing_thread`，则是在线程中调用相应的`opaque->crypto.encrypt_function`函数以及`opaque->crypto.decrypt_function`去实现加解密。

`stream`相关的加解密函数则是实现了一个简单的异或，而`aes`相关的加解密函数则是对输入进行aes加解密，并在最后附上了一个校验值。

所以整个设备的功能主要是实现了一个加解密功能，算法可以选择是流算法或aes算法，主要基于`crypto_status`结构体来记录关键数据。

经过分析该设备中存在两个漏洞，一个是越界读，一个是越界写。

越界读是在`qwb_mmio_read`函数中，其对于`output_buff`读取的判断条件为：只要小于`strlen(output_buff)`，就可以读取相应数据。乍一看没有问题，可是当加解密的数据长度刚好填满了`output_buff`即长度为0x800时，调用`strlen(output_buff)`时会导致获得的长度大于`0x800`，因为拼接上了后面的`encrypt_function`指针的数据。使得越界读到`encrypt_function`指针的数据，实现程序地址的泄露。

越界写在存在于`aes_decrypto_function`以及`aes_encrypto_function`函数中，两个函数都在对输入数据进行aes加密后，在`output_buff`的末尾拼接了一个8字节的校验值，该校验值导致越界写，关键代码如下：

```c
len = strlen((const char *)input);
...
    *(_QWORD *)crc = 0LL;
    v19 = 0;
    c = 0;
    for ( i = 0LL; ; c = crc[i & 7] )
    {
      c ^= output[i];
      idx = i++;
      crc[idx & 7] = c;
      if ( len == i )
        break;
    }
  }
  else
  {
    *(_QWORD *)crc = 0LL;
  }
  *(_QWORD *)&output[len] = *(_QWORD *)crc;
```

如果`len`长度刚好为0x800，则会导致最后的校验值写入到output_buff[0x800]处，导致越界覆盖了`encrypt_function`指针。

### 利用

如何利用上述的两个漏洞拿到shell呢，大致也是分为四步。

第一步将`input_buff`以及`cyrpto_key`填满，然后调用`stream_encypt_function`将`output_buff`填满，再利用越界读，读出`stream_encypt_function`函数的地址，根据偏移计算出`system plt`的地址。

第二步构造能够得到`system plt`校验值的`input_buff`，因为是异或得到的校验值，所以比较容易构造。然后将输入以及key填进去，调用`aes_encypt_function`函数加密，将`output_buff`读出来保存。

第三步是将上一步保存的`output_buff`数据输入到`input_buff`中，再使用相同的key调用`aes_decypt_function`函数进行解密，这样解密出来的数据的校验值就刚好会是`system plt`，且会覆盖至`encrypt_function`指针。

第四步是将参数赋值到`input_buff`中，最后调用`encrypt_function`，实现`system`函数的调用，拿到flag。

## ExecChrome

qwb 2019 final的题，主办方给了一个虚拟机，虚拟机的用户名是`qwb`，密码是`123456`。进去以后`sudo ./launch.sh`启动虚拟机，qemu虚拟机用户名是`ubuntu`，密码是`123456`，`launch.sh`内容如下：

```bash
#!/bin/bash
while true
	do ./qemu-system-x86_64 -m 1024 -smp 2 -boot c -cpu host -hda ubuntu_server.qcow2 --enable-kvm -drive file=./blknvme,if=none,id=D22 -device nvme,drive=D22,serial=1234 -net user,hostfwd=tcp::2222-:22 -net nic && sleep 5
done
```

### 分析

根据参数`-device nvme`，可以推断应该主要是这个设备的问题，搜相关函数，看到有很多的函数。经过一番搜索以后发现是根据已有的设备改的代码，目录是`hw/block/nvme.c`。

经过对比，发现主要是在`nvme_mmio_read`以及`nvme_mmio_write`里面修改了部分代码，研究相应代码。

先看`nvme_mmio_read`，原来的代码是：

```c
if (addr < sizeof(n->bar)) {
        memcpy(&val, ptr + addr, size);
    }
```

修改后的代码是：

```c
memcpy(&val, &ptr[addr], size);
```

可以看到少了对于`size`的检查，可能会存在越界读。

再看`nvme_mmio_write`中，该函数调用了`nvme_write_bar`函数。经过对比，题目对`nvme_write_bar`函数中添加了部分代码，添加的代码的内容为：

```c
default:
      ...
      if ( size == 2 )
      {
        *(_WORD *)((char *)&n->bar.cap + offset) = data;
      }
      else if ( size > 2 )
      {
        if ( size == 4 )
        {
          *(_DWORD *)((char *)&n->bar.cap + offset) = data;
        }
        else if ( size == 8 )
        {
          *(uint64_t *)((char *)&n->bar.cap + offset) = data;
        }
      }
      else if ( size == 1 )
      {
        *((_BYTE *)&n->bar.cap + offset) = data;
      }
      break;
  }
```

可以看到似乎也存在越界写功能。

再去虚拟机中看mmio空间的大小：

```bash
lspci -vv -s 00:04.0
00:04.0 Non-Volatile memory controller: Intel Corporation QEMU NVM Express Controller (rev 02) (prog-if 02 [NVM Express])
	Subsystem: Red Hat, Inc. QEMU Virtual Machine
	Physical Slot: 4
	Control: I/O+ Mem+ BusMaster+ SpecCycle- MemWINV- VGASnoop- ParErr- Stepping- SERR+ FastB2B- DisINTx+
	Status: Cap+ 66MHz- UDF- FastB2B- ParErr- DEVSEL=fast >TAbort- <TAbort- <MAbort- >SERR- <PERR- INTx-
	Latency: 0
	Interrupt: pin A routed to IRQ 10
	Region 0: Memory at febf0000 (64-bit, non-prefetchable) [size=8K]
	Region 4: Memory at febf3000 (32-bit, non-prefetchable) [size=4K]
```

可以看到mmio大小为8k，而`NvmeCtrl->bar`大小却只有0x40，结合上面的分析，确定该设备存在越界读写漏洞。

```c
NvmeCtrl        struc ; (sizeof=0x1C50, align=0x10, copyof_4151)
00000000 parent_obj      PCIDevice_0 ?
000008E0 iomem           MemoryRegion_0 ?
000009D0 ctrl_mem        MemoryRegion_0 ?
00000AC0 bar             NvmeBar_0 ?
00000B00 conf            BlockConf_0 ?
00000B38 page_size       dd ?
00000B3C page_bits       dw ?
00000B3E max_prp_ents    dw ?
00000B40 cqe_size        dw ?
00000B42 sqe_size        dw ?
00000B44 reg_size        dd ?
00000B48 num_namespaces  dd ?
00000B4C num_queues      dd ?
00000B50 max_q_ents      dd ?
00000B54                 db ? ; undefined
00000B55                 db ? ; undefined
00000B56                 db ? ; undefined
00000B57                 db ? ; undefined
00000B58 ns_size         dq ?
00000B60 cmb_size_mb     dd ?
00000B64 cmbsz           dd ?
00000B68 cmbloc          dd ?
00000B6C                 db ? ; undefined
00000B6D                 db ? ; undefined
00000B6E                 db ? ; undefined
00000B6F                 db ? ; undefined
00000B70 cmbuf           dq ?                    ; offset
00000B78 irq_status      dq ?
00000B80 serial          dq ?                    ; offset
00000B88 namespaces      dq ?                    ; offset
00000B90 sq              dq ?                    ; offset
00000B98 cq              dq ?                    ; offset
00000BA0 admin_sq        NvmeSQueue_0 ?
00000C00 admin_cq        NvmeCQueue_0 ?
00000C50 id_ctrl         NvmeIdCtrl_0 ?
00001C50 NvmeCtrl        ends
```

### 利用

要想成功利用，分为两步：

1. 利用越界读，泄露程序基址与堆地址。
2. 利用越界写覆盖`qemu timer`控制程序执行流

因为程序开启了PIE，所以第一步需要先泄露地址。首先是得到`system`地址，在与`bar`地址偏移`0x1ff0`的地方找到了存在程序地址的地方，利用`mmio_read`越界读出来，然后根据偏移计算出`system`地址。其次是得到`NvmeCtrl->bar`地址的空间以实现可以拿到最终传参的地址，在与bar地址偏移`0x1f98`的地方找到了存在堆地址的地方，根据偏移可以计算出`NvmeCtrl->bar`地址。

关键的是如何控制程序执行流，主要原理是利用了`NvmeCtrl`结构体中的`admin_sq `，`admin_sq`中存在一个`timer`结构体，可以利用它来控制程序执行流。

```c
00000000 NvmeSQueue_0    struc ; (sizeof=0x60, align=0x8, copyof_4154)
00000000                                         ; XREF: NvmeCtrl_0/r
00000000                                         ; NvmeCtrl/r
00000000 ctrl            dq ?                    ; offset
00000008 sqid            dw ?
0000000A cqid            dw ?
0000000C head            dd ?
00000010 tail            dd ?
00000014 size            dd ?
00000018 dma_addr        dq ?
00000020 timer           dq ?                    ; offset
00000028 io_req          dq ?                    ; offset
00000030 req_list        $FE468C6164B384978313660BA47FFEDA ?
00000040 out_req_list    $FE468C6164B384978313660BA47FFEDA ?
00000050 entry           $53C797D9CC370671B1F6BB504B4B2727 ?
00000060 NvmeSQueue_0    ends
00000000 ; ---------------------------------------------------------------------------
00000000 QEMUTimer       struc ; (sizeof=0x30, align=0x8, copyof_729)
00000000 expire_time     dq ?
00000008 timer_list      dq ?                    ; offset
00000010 cb              dq ?                    ; offset
00000018 opaque          dq ?                    ; offset
00000020 next            dq ?                    ; offset
00000028 attributes      dd ?
0000002C scale           dd ?
00000030 QEMUTimer       ends
00000030
```

主要有两种方式：

一种是伪造timer，利用虚拟机重启或关机时会触发时钟`timer`，调用`cb(opaque)`控制程序执行流的方法，关键代码如下所示：

```c
void main_loop_wait(int nonblocking)
{
    ...

    /* CPU thread can infinitely wait for event after
       missing the warp */
    qemu_start_warp_timer();
    qemu_clock_run_all_timers();
}

bool timerlist_run_timers(QEMUTimerList *timer_list)
{
    ...
        timer_list->active_timers = ts->next;
        ts->next = NULL;
        ts->expire_time = -1;
        cb = ts->cb;
        opaque = ts->opaque;

        /* run the callback (the timer list can be modified) */
        qemu_mutex_unlock(&timer_list->active_timers_lock);
        cb(opaque);   // we can hajack the control flow here
        qemu_mutex_lock(&timer_list->active_timers_lock);

        progress = true;
    }
    ...
    return progress;
}
```

可以在堆中伪造好timer结构体，其`cb`为system地址，`opaque`为参数的地址。利用越界将`admin_sq`中的`timer`指针覆盖成该伪造的结构体，当reboot时就可以成功控制程序的执行流。一个关键的点是`timer`结构体中的`timer_list`指针需要正确，因为之前泄露了堆地址，因此可以通过偏移计算得到原来的`timer_list`结构体的值，将它覆盖成原来的就好。但是由于结构体都是堆地址，会导致和泄漏的地址的偏移可能不固定。但是它的地址和堆基址的偏移时一致的，因为我们可以通过计算堆基址来得到`timer_list`的地址，具体可以去看exp中的内容。

另一种方式则是在`nvme_mmio_write`中存在一条调用链：`nvme_mmio_write->nvme_process_db->timer_mod->timer_mod_ns->timerlist_rearm->timerlist_notify->(timer_list->notify_cb)(timer_list->notify_opaque,timer_list->clock->type)`，也可以成功控制程序执行流。

我的exp中使用的是第一种利用方式。

## 小结

qemu ctf pwn题分析到这就暂告一段落，接下来会分析一些qemu cve来进一步了解相关漏洞。

相关脚本以及文件[链接](https://github.com/ray-cp/vm-escape/tree/master/qemu-escape)

