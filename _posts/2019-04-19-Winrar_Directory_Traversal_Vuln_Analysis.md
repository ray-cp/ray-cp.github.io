---
layout: post
title:  "winrar 目录穿越漏洞分析"
date:   2019-04-19 15:00:00
categories: Vuln_Analysis
permalink: /archivers/Winrar_Directory_Traversal_Vuln_Analysis
---
文章首发于[先知社区](https://xz.aliyun.com/t/4221)
## 漏洞描述
Check Point团队爆出了一个关于WinRAR存在19年的漏洞，用它来可以获得受害者计算机的控制。攻击者只需利用此漏洞构造恶意的压缩文件，当受害者使用WinRAR解压该恶意文件时便会触发漏洞。

漏洞是由于 WinRAR 所使用的一个06遍编译出来的动态链接库UNACEV2.dll所造成的，动态链接库的作用是处理 ACE 格式文件。而WinRAR解压ACE文件时，由于没有对文件名进行充分过滤，导致其可实现目录穿越，将恶意文件写入任意目录，甚至可以写入文件至开机启动项，导致代码执行。

CVE 编号为CVE-2018-20250，受影响的版本包括winrar <5.70 Beta、BandZip <= 6.2.0.0、好压 <= 5.9.8.10907、360压缩 <4.0.0.1170。

## 漏洞分析

将UNACEV2.dll拖进IDA进行分析。根据[poc](https://research.checkpoint.com/extracting-code-execution-from-winrar/)，直接定位到漏洞代码`0x40CB48`。

可以看到该函数首先是对输入的`relative paht`进行了一遍预处理。![Alt text](https://raw.githubusercontent.com/ray-cp/ray-cp.github.io/master/_img/2019-04-19-Winrar_Directory_Traversal_Vuln_Analysis/1551094233019.png)

如上图所示，称这部分为`Clean_Path`，输入的处理包含以下部分：

1. 当路径以`\\`开头时，且路径中还包含两个`\`，会将中间部分忽略掉。这部分本意可能为处理smb文档的代码，如`\\10.10.10.10\smb_folder_name\some_folder\some_file.txt`路径会被处理为`some_folder\some_file.txt`
2. 当路径以`*:\`开头时，忽略`*:\`。这部分本意可能为忽略盘符，如`C:\some_folder\some_file.txt`会被处理为`some_folder\some_file.txt`。
3. 当路径包含`\..\`时，忽略`\..\`。这部分本意可能为忽略回溯路径，以防止目录穿越。
4. 当路径开头为`*:*`且路径不为`*:\`时，忽略`*:`。这部分本意不知道，感觉可能为某种文件路径格式。
5. 主要为以上四种目录筛选，根据poc中描述，不知什么原因如果路径开头为`C:\C:`也会忽略。

继续往下看，一个名为`GetDevicePathLen`的函数，如果该函数返回非0值，则会将空字符赋值给变量，否则会将文件夹的路径赋值给变量，最终使用`sprintf`函数将文件目录最终形成。
![Alt text](https://raw.githubusercontent.com/ray-cp/ray-cp.github.io/master/_img/2019-04-19-Winrar_Directory_Traversal_Vuln_Analysis/1551094255855.png)
相应的代码为：
```c
if ((GetDevicePathLen(file_path))
    var1=&empty_string
else
    var1=add_slash(&dest_dir_path)
sprintf(final_file_path,"%s%s",var1,file_path)
```
此处便是漏洞的形成点。漏洞的形成原理是如若能伪造文件路径使得`GetDevicePathLen`函数返回非0值，则该文件路径会被当成绝对路径而不是相对路径，从而解压的时候实现任意目录写。

如果`file_path`为`C:\some_folder\1.txt`且使得`GetDevicePathLen`返回非0，则会将txt解压到相应目录`C:\some_folder\1.txt`。

现在的问题就转移至如何构造文件路径使得`GetDevicePathLen`返回非0。跟进该函数查看代码：
```c
_BYTE *__usercall __spoils<ecx> GetDevicePathLen@<eax>(_BYTE *path@<eax>)
{
  _BYTE *path_ptr; // ecx
  _BYTE *slash_pos; // eax
  int v3; // ecx

  path_ptr = path;
  slash_pos = 0;
  if ( *path_ptr == '\\' )
  {
    if ( path_ptr[1] == '\\' )
    {
      slash_pos = strchr(path_ptr + 2, '\\');
      if ( slash_pos )
      {
        slash_pos = strchr(slash_pos + 1, '\\');
        if ( slash_pos )
          slash_pos = &slash_pos[-v3 + 1];  //注释A
      }
    }
    else
    {
      slash_pos = (_BYTE *)1;   //注释B
    }
  }
  else if ( path_ptr[1] == ':' )
  {
    slash_pos = (_BYTE *)2; //注释C
    if ( path_ptr[2] == '\\' )
      slash_pos = (_BYTE *)3; //注释D
  }
  return slash_pos;
}
```
代码总结为：

*  注释A： 如果路径开头为`\\`且路径中仍还包含多的两个`\`则返回第四个斜杆与开头的差距。如`\\LOCALHOST\some\some_folder\some_file.txt`返回值为17。
* 注释B：如果路径以`\`开头，且不以`\\`开头，则返回1。如`\some_folder\some_file.txt`返回值为1。
* 注释C：如果路径以`*:`开头，且不以`*:\`开头，则返回2。如`C:some_folder\some_file.txt`返回值为2。
* 注释D：如果路径以`*:\`开头，则返回3。如如`C:\some_folder\some_file.txt`返回值为3。

至此代码分析完毕，可以看到漏洞原理主要为可构造预期文件路径使得`GetDevicePathLen`返回非0，从而实现目录穿越。

## 漏洞利用

如何利用漏洞，首先要解决的是如何实现任意目录的解压。

具体来说可以使用`C:\some_folder\some_file.txt`文件路径使的`GetDevicePathLen`返回非0。但是，由于函数一开始存在一个`Clean_Path`函数，如目录为`C:\some_folder\some_file.txt`，则会被处理为`some_folder\some_file.txt`。

绕过该处理的方法为将目录更改为：`C:C:\some_folder\some_file.txt`，根据`Clean_Path`处理部分的第四条，该路径会被处理成`C:\some_folder\some_file.txt`，从而实现了目录穿越。

同时也可实现对smb共享文件夹的攻击，如目录`C:\\\10.10.10.10\smb_folder_name\some_folder\some_file.txt => \\10.10.10.10\smb_folder_name\some_folder\some_file.txt`，根据根据`Clean_Path`处理部分的第二条，将会被处理成`\\10.10.10.10\smb_folder_name\some_folder\some_file.txt `，实现共享文件的目录穿越。

到这里目录穿越的原理已经解释清楚，下一个问题是如何利用。实际利用有一个局限性，就是需要知道相应解压目录的具体目录，不能使用回溯路径。利用的方法为主要有两个：

* 一个是将文件解压至开机自启动目录。
* 一个是实现dll劫持。

关于开机自启动目录，主要有两个：
1. C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp
2. C:\Users\$user_name\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
第一个需要管理员权限，路径是固定的，但是实施攻击的条件较高；第二个则不需要管理员权限，但是需要知道相应的用户名称，可能需要爆破。
poc中也提到了唯一一个可以不使用用户名的方式，那就是使用`C:\C:C:../AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\some_file.exe`路径。该路径的主要方式根据`Clean_Path`处理部分的第五条，得到`C:../AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\some_file.exe`，这个目录是假设用户解压的路径一般为`C:\Users\$user_name\Desktop`或者`C:\Users\$user_name\Downloads`，此时的`C:../`便会回溯至`C:\Users\$user_name\`目录，所以可以顺利解压至`C:\Users\$user_name\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`目录。

另一个利用方法是`dll劫持`，覆盖相应dll文件等，具体可搜索了解实现方式。

## 利用实现

python有一个ace文件解析的模块[acefile](https://pypi.org/project/acefile/)，基于该模块源码，了解ace文件格式，即可实现相应的路径修改。

手动实现过程为：
1. 首先使用[WinACE](https://web.archive.org/web/20170714193504/http:/winace.com:80/)创建一个acefile文件，选择store full path。
![Alt text](https://raw.githubusercontent.com/ray-cp/ray-cp.github.io/master/_img/2019-04-19-Winrar_Directory_Traversal_Vuln_Analysis/1551094523721.png)

2. 使用acefile查看该文件头格式。
![Alt text](https://raw.githubusercontent.com/ray-cp/ray-cp.github.io/master/_img/2019-04-19-Winrar_Directory_Traversal_Vuln_Analysis/1551094717415.png)

3. 修改文件路径，我这里使用的是Winhex。把路径修改成了`C:../AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\calc.exe`
![Alt text](https://raw.githubusercontent.com/ray-cp/ray-cp.github.io/master/_img/2019-04-19-Winrar_Directory_Traversal_Vuln_Analysis/1551095544268.png)

4. 修改hdr_size以及hdr_crc以及路径长度。只修改文件名使用acefile去解析是会报错的，整个头部的size也发生了变化，因为文件路径长度发生了变化，也需要修改，由之前的`71-->111`；还需要修改路径长度，因为路径发生了变化，由之前的`0x28->0x50`；在acefile.py检查hdr_crc的地方加打印出crc的代码，可以得到正确crc(crc修改过很多次，图片为最后一次修改的)；
![Alt text](https://raw.githubusercontent.com/ray-cp/ray-cp.github.io/master/_img/2019-04-19-Winrar_Directory_Traversal_Vuln_Analysis/1551097968303.png)

最终修改前与修改后的对比如下，修改前winhex里显示为：
![Alt text](https://raw.githubusercontent.com/ray-cp/ray-cp.github.io/master/_img/2019-04-19-Winrar_Directory_Traversal_Vuln_Analysis/1551097885184.png)

修改后的字节为：
![Alt text](https://raw.githubusercontent.com/ray-cp/ray-cp.github.io/master/_img/2019-04-19-Winrar_Directory_Traversal_Vuln_Analysis/1551097898000.png)

5. 解压实现攻击。
![Alt text](https://raw.githubusercontent.com/ray-cp/ray-cp.github.io/master/_img/2019-04-19-Winrar_Directory_Traversal_Vuln_Analysis/1551097737799.png)

将上述步骤最终实现了一个自动化的脚本，还有相关的脚本也放在了我的[github](https://github.com/ray-cp/Vuln_Analysis/tree/master/CVE-2018-20250-winrar-code-execution)。





## 参考链接

[winace](https://web.archive.org/web/20170714193504/http:/winace.com:80/)
[acefile]( https://pypi.org/project/acefile/#files)
[Extracting a 19 Year Old Code Execution from WinRAR](https://research.checkpoint.com/extracting-code-execution-from-winrar/)