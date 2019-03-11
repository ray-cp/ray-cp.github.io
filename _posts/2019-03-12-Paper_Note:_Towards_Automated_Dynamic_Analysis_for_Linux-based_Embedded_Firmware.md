---
layout: post
title:  "Paper_Note"
date:   2019-03-12 07:30:00
categories: Paper
permalink: /archivers/PAPER-NOTE
---

# Paper Note: Towards Automated Dynamic Analysis for Linux-based Embedded Firmware

(Towards Automated Dynamic Analysis for Linux-based Embedded Firmware：
D. D. Chen, M. Woo, D. Brumley, and M. Egele, “Towards Automated Dynamic Analysis for Linux-based Embedded Firmware,” in Proceed- ings of the 23nd Annual Network and Distributed System Security Symposium (NDSS), San Diego, California, USA, February 21-24, 2016, 2016.)

时间：2019-3-12

## 绪论

嵌入式设备有一些共同特性：如基于ARM或MIPS 处理器的嵌入式片上系统设计；通过以太网或WIFI的网络连接以及各种通信接口，如GPI、I2C或SPI；这些设备都是通过厂商提供的固件以实现功能，且用户很少会去更新。

一个无线路由器通常是用户设备的第一条也是最后一条防线。

FIRMADYNE可以实现自动动态分析，解决了嵌入式设备面临的众多挑战，例如各种硬件专用外设的存在，非易失性存储器（NVRAM）中持久性配置的存储以及动态生成的配置文件。

FIRMADYNE首先自动解压厂商固件，因为目前设备都是基于Linux系统的，所以该框架设计也是基于linux系统的嵌入式设备；使用qemu 系统模式来模拟运行设备；为了更好的分析系统，还提供了爬虫去厂商网站获取数据。

即使模拟全系统，网络接口方面的配置也必须要正确。系统所采取的方法是：在隔离的网络环境中先监控网络交互过程，收集相应的信息；在收集好信息后，FIRMADYNE重新配置网络环境，恢复固件与分析主机之间的联系。

主要有以下贡献：

* 展示了FIRMADYNE，一个自动动态分析基于linux的固件漏洞的系统
* FIRMADYNE，解决了很多模拟嵌入式系统所面临的挑战，例如硬件专用外设的存在，非易失性存储器（NVRAM）的使用以及动态生成文件的创建。
* 从42个不同厂商收集了23,035个固件镜像，其中9,486个固件可以使用FIRMADYNE提取。
* 将系统开源。

## 概述

本章主要描述组成FIRMADYNE的各部分组件以及设计他们的动机。

![Alt text](https://github.com/ray-cp/ray-cp.github.io/tree/master/_img/Paper_Note_Towards_Automated_Dynamic_Analysis_for_Linux-based_Embedded Firmware/1551654384697.png)

**组件**

如上图所示，主要包括以下组件：
* 爬取固件。第一个独立的组件就是爬虫，从厂商去下载相应的固件镜像。
* 提取固件文件系统。基于binwalk的API来踢去文件系统。
* 初始模拟系统。一旦文件系统被提取，FIRMADYNE识别硬件架构，然后使用pre-built好的QEMU系统来运行固件。目前支持此三类目标架构：小端arm、小端mips以及大端mips。
* 动态分析。

**动机**
针对嵌入式系统固件的动态分析解决了嵌入式系统抽象层次结构中的各种设计点，接下来讨论这种分析的潜在优势：

1. 应用层：为更好的支持web页面的运行（web页面很多都需要nvram等信息）。
2. 处理层：解决模拟固件运行过程中遇到的问题。
3. 系统层：修改了内核加入了自定义的NVRAM实现。（但是，这不适用于内核模块; 实际上，我们当前实现的缺点之一是缺少对位于文件系统上的树外内核模块的仿真支持，因此内核版本的差异可能导致系统不稳定。）

## 概念

本章主要提供动态分析框架的概念的总揽。

**系统架构**

根据前面的图所示，系统构建了一个固件仓库用于存储二进制固件且用数据库来存储固件信息。

一组虚拟化的结点用于提取古剑的文件系统和内核（可选），如果提取成功，就缓存进入文件系统；接下来进入学习阶段，为固件分配默认配置并记录网络交互；最后进入分析阶段，此时已经拥有网络模拟环境，再单独对系统进行分析。

**获取**
为了获取固件，我们开发了一个web爬虫。爬取了固件以及相应信息。

**提取**
主要是用binwalk的API来对文件系统进行提取。

**模拟**
一旦文件系统被提取FIRMADYNE就进行一系列分析步骤以推断固件映像所期望的系统配置：
* 首先，检查ELF头来确定目标架构以及大小端；对于每个固件镜像，我们都使用qemu系统模式来模拟。
* 其次，再初步模拟阶段，系统处于一个特殊的“学习”阶段，记录下一些相应的配置信息。
* 最后，在信息收集完成后，进入全真模拟阶段。为了判断是否成功，FIRMADYNE会进入系统尝试较多的交互以检查网络连通性。

**自动分析**
我们实现了三个基础自动分析阶段。

## 实现

**获取**
使用Scrapy来实现网络爬虫，收集各类镜像及其信息包括：摄像头、路由器、智能电视、防火墙等。

部分使用了比较多的动态页面生成技术的产商如D-Link以及合勤等，则是通过爬取FTP镜像网站来实现；还有一些如思科，限制了自动下载的，则是进行手动下载；

**提取**
使用binwalk的递归提取模式“-M”并不能满足我们的需求。特别是存在路径爆炸的情况以及无法保证终止的情况。

论文实现了一个定制的基于binwalk API的提取组件。并实现了一套识别非固件文件的算法以避免资源浪费。

在黑名单验证之后，提取过程使用一组优先级排序的签名，这些签名按置信度顺序依次执行。 

另一个提升的点在于使用第三方组件jefferson以及sasquatch用于JFFS2以及SquashFS文件系统的提取。

提取是一件很难的事，因为工具的更新跟不上发展或是产商实现了自定义的压缩算法。

在这个过程中，我们发现了很多binwalk以及jefferson的bug，帮助他们提升了效能。

虽然能提取很多固件，但是仍然有很多固件无法提取。

**模拟**

 NVRAM：至少52.6%的固件使用libnvram.so来获取NVRAM的信息。我们开发了一个库来拦截相关的调用。通过`LD_PRELOAD`来加载。

我们的NVRAM实现并不对能对所有的固件都起效，原因有很多：调用我们没模拟的程序；调用函数所需的语义与我们模拟的不同等。可以通过检查系统日志以找出原因。

Kernel：我们并不是使用提取出来的内核，而是使用提前变异好的内核。再编译内核的过程中，我们hook来20个系统调用（如创建新进程的调用以看地址等是否被修改为了预期的0xDEADBEEF、0x41414141等。）

system configuration：由于我们对于网络相关的功能比较关心，所以在模拟环境时对具体设备做了相应改变。我们的系统最初会对每个固件进行模拟“学习”60s，先使用默认信息配置，启动过程中收集信息，后面再反馈。

QEMU：除了NVRAM之外，设备可能还依赖一些硬件如看门狗或一些闪存设备（watchdog timers or additional flash storage devices），并且他们不是在内核中实现而是再用户空间中实现。因此我们不能简单的把这些设备抽象掉然后再内核中模拟，我们采取的解决方案是修改QEMU的源码。

**自动分析**
目前我们实现了三个基本分析阶段，每一个都是使用回调函数实现的。如为固件进入到网络配置阶段，注册毁掉函数并触发。具体包括：

1. 网页信息
2. SNMP信息：主要使用snmpwalk工具。
3. 漏洞：使用60个已知的exp进行攻击。

**附加功能**

我们还开发了许多其他功能，以帮助开发和调试我们的仿真框架和漏洞。 其中包括代码执行的动态跟踪，可以导入到现有的逆向工程工具中，例如IDA Pro。 我们修改了自定义内核以禁用context_switch()数的内联，这允许模拟器跟踪给定用户空间进程的执行。 此外，在启动时，我们还在设备节点/ dev / ttyS1上启动一个特殊的控制台应用程序，该应用程序由QEMU转发到主机系统上的临时套接字。 这为我们提供了一种在运行时修改模拟固件映像的便捷机制，尤其是在没有启动默认控制台的情况下。

## 评估

首先测试模拟的效果；其次是展示我们发现的14个未公开漏洞；最后展示使用msf攻击的60个已知漏洞。

** 统计 **

1. 架构：通过检查busybox文件来识别架构，如果busybox不存在的话检查/sbin目录下的文件。79.4%为mips，8.9%为arm。
2. 操作系统：48%为Unix-based系统，3.5%为Vxworks系统。（提取文件系统失败的原因有很多，如合勤使用的ZynOS，ZynOS是ZyXEL书去开发的实时操作系统，使用ThreadX内核和未知的文件系统类型。）
3. 内核模块：根据文件名我们对内核模块进行了一定的分类。58.8%为网络相关的功能，如包过滤（iptables、xtables、netfilter、ebtables）、协议实现（pptp、ppp、adsl）以及接口支持（mii、tun、tap）；12.7%为外围设备，如无线适配器（wl、ath9k、sierra）平台芯片（ar7240、ar7100、bcm963xx）；还包括一些可装载模块，如USB接口（ehci、uhci、xhci）
4. 网络服务：使用nmap扫描来1971个镜像来扫描服务与端口。47.3%支持web管理界面；9.5%支持HTTPS；37.4%支持SSH或telnet；27.2%支持DNS服务；16.4%支持UPnP；
5. 模拟过程：我们可以模拟96.6%（8591）的固件镜像，失败的原因包括缺少init库（/bin/init、/etc/init、/sbin/init）

** 结果 **

1. 命令注入：发现了6个Netgear的未知命令注入漏洞；
2. 溢出：受影响较多的是D-Link
3. 信息泄露：SNMP服务
4. Sercomm Configuration Dump：CVE-2014-0659。
5. MiniUPnPd拒绝服务：CVE-2013-0229
6. OpenSSL ChangeCipherSpec：CVE-2014-0224

** 讨论与局限**
有很多可以提升的地方：提升提取成功率、支持更多的硬件架构、修改模拟错误；

## 相关工作

Heffner与Rapid7致力于提取镜像文件；[Costin et al](A. Costin, J. Zaddach, A. Francillon, and D. Balzarotti, “A large-scale analysis of the security of embedded firmwares,” in Proceedings of the 23rd USENIX Security Symposium. USENIX, 2014, pp. 95–110. Available: https://www.usenix.org/conference/ usenixsecurity14/technical-sessions/presentation/costin)使用静态分析技术，分析来32000个固件镜像发现了38个未知漏洞

[Davidson et al.](D. Davidson, B. Moench, S. Jha, and T. Ristenpart, “FIE on firmware: Finding vulnerabilities in embedded systems using symbolic execution finding vulnerabilities in embedded systems using symbolic execution,” in Proceedings of the 22nd USENIX Security Symposium. USENIX, 2013, pp. 463–478. [Online]. Available: https://www.usenix.org/conference/ usenixsecurity13/technical-sessions/paper/davidson)等人开发了一个基于KLEE的符号执行平台

## 结论与未来工作

1. 支持更多的实时平台操作系统，如VxWorks
2. 获取嵌入式设备源码进一步辅助分析
3. 加入一些静态分析技术来帮助提取文件系统（加解密的系统），如[Buffalo](http://buffalo.nas- central.org/wiki/Firmware_update)以及[QNAP]( http://pastebin.com/KHbX85nG)