---
layout: post
title:  "Wndows Kernel Debug with VMware Fusion"
date:   2018-08-17 07:00:00
categories: windows-kernel-exploit
permalink: /archivers/Wndows-Kernel-Debug-with-VMware-Fusion
---

For the reason that VMware Fusion doesn't have add port selection. so we need to edit vmx file to add port.

## Environment
- Debugger OS: Windows 7 SP1
- Debuggee OS: Windows 8

## Modify VMX file
It you can see vmx file, just use any text editor to edit it.
If you can only see vmwarevm file, right click and select "show package contents", then edit the vmx file.

## Debugger
then add following lines in the bottom of debugger os's vmx file.

 ```C
 serial1.present = "TRUE"
 serial1.fileType = "pipe"
 serial1.startConnected = "TRUE"
 serial1.fileName = "/private/tmp/serial"
 serial1.tryNoRxLoss = "FALSE"
 serial1.pipe.endPoint = "client"
 ```

start up the debugger VM and open up WinDBG. Click File > Kernel Debug… to bring up the kernel connection dialog box. Click the Serial tab and change COM1 to COM2 and hit OK. 

## Debuggee
then add following lines in the bottom of debuggee os's vmx file.

```C
 serial1.present = "TRUE"
 serial1.fileType = "pipe"
 serial1.fileName = "/private/tmp/serial"
 serial1.tryNoRxLoss = "FALSE"
 serial1.pipe.endPoint = "server"
```

Then before we shut down debugee VM (the Win8 one), we need to do another bcdedit command. Open an administrator command prompt and enter the following:
```C
 bcdedit /copy {current} /d "Debug me"
 bcdedit /debug ON
 bcdedit /bootdebug ON
 bcdedit /dbgsettings
 bcdedit /timeout 10
 bcdedit -set TESTSIGNING on
 bcdedit /dbgsettings SERIAL DEBUGPORT:2 BAUDRATE:115200
```

then restart the debuggee os, we can debug the os.
