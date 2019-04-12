---
layout: post
title:  "Paper Note：Saluki: Finding Taint-style Vulnerabilities with Static Property Checking"
date:   2019-04-12 08:30:00
categories: PAPER_NOTE
permalink: /archivers/Paper_Note_Saluki_Finding_Taint-style_Vulnerabilities_with_Static_Property_Checking
---

2019.4.02-2019.4.12

文章主要还是用符号执行技术来跟踪污点追踪，感觉angr也可以实现这个技术。还有一点就是新的语言用来漏洞建模，感觉如何对漏洞建模也是一个要研究的对象。
## 绪论

Saluki，一个静态污点分析工具。从高层次来看，主要是将属性定义为一个谓词，该谓词包含一组一个或多个唯一路径执行。

如`read(x)`不应该没经过处理直接流向`system(cmd)`，Saluki首先根据`x`生成路径以及环境的数据依赖关系，然后检查`system(cmd)`是否依赖于`x`。

Sqluki的工作原理是：

* 数据依赖生成（Data dependency generation）。提出了`uflux`用于二进制的路径以及环境的数据依赖关系生成。
* 策略规范（Policy specification）。由用户提供策略规范，如`read(x)`不应该流向`system(cmd)`。开发了一个策略语言，抽象出了二进制相关的具体细节。
* 逻辑引擎（A logic engine）。检查各种显示或隐式的数据依赖关系。

一个关键的思路是`uflux`，它可以分部分执行程序来找到数据依赖性。生成并记录程序所需输入。它有两种模式：决定模式（deterministic mode），根据模拟器状态去执行分支；非决定模式，忽略分支条件，执行所有的路径。

主要包括以下贡献：
1. `uflux`一个新的收集路径以及环境数据依赖关系的方法。
2. 一个验证框架。包括一个逻辑系统；一个策略语言；一个求解器。
3. 使用Sluki进行漏洞挖掘的实验评估，发现了6个0day以及Heartbleed等公开漏洞。
4. 源代码公开。

## MODELING AND CHECKING SECURITY PROPERTIES

### saluki operation

用户检查安全策略需要两步。一是用户使用策略语言确定他们的安全策略，主要包括两部分：确定程序感兴趣代码如recv以及system的api；检查程序位置的数据依赖关系。

该设计主要有三个目标：
1. 保持高保真率、低误报率以及覆盖更多的路径。
2. 在提取出的数据依赖流程图中推理出安全策略。
3. 尽可能的不要由于底层的细节而丢弃策略语言。

![Alt text](https://raw.githubusercontent.com/ray-cp/ray-cp.github.io/master/_img/Paper_Note_Saluki_Finding_Taint-style_Vulnerabilities_with_Static_Property_Checking/1554677716232.png)
架构如上如所示，流程包括：
1. 载入规范。
2. 将二进制解释为中间语言。
3. 运行uflux来收集数据执行流。
4. 针对收集的数据以及路径等信息运行求解器。
5. 输出新的路径，路径不是全路径，而是污染数据传播的路径。

saluki的策略语言的目的是为了寻找具有隐式执行流控制依赖关系的污点数据流。

后续使用将使用命令注入漏洞来进行示例，下面的saluki语言规范是使用system函数来对recv接收到的数据进行执行的命令注入漏洞的示例：
```
 prop recv_to_system ::=
   recv(_,*buf,_,_), system(*cmd) |- never
   s.t. cmd/buf
   
   Listing 1: Network input should not reach system
```

上表定义了一个安全性质即命令注入的两个常用api。

安全性质一般都指明了模式，可以用该模式来匹配定义的数据或是执行流等。 用户可以自定义头文件来声明模式。

下面具体说下流程：
* **二进制处理** （binary processing）。saluki将规范以及二进制作为输入。首先使用BAP来将IR转化为中间语言
* **污点种子**（taint seeding）。saluki解析规范以获取约束变量，每个变量都会被链接到程序的相应位置并在后续的过程中被标识为污点种子。在上例中，`cmd`是recv函数中使用的约束变量。saluki会为每个种子使用一个特殊的id来标志该种子。
* **uflux**。后续saluki会使用uflux来收集数据依赖关系，uflux会寻寻找种子并遵循一定的种子生成策略，默认情况下，使用的是随机种子生成策略。并根据解释器的执行状态来决定遇到分支时是否都执行或只选择其中一条。执行过程中解释器根据定义的规则去传播污点，并生成`D(l′, R′, l, R)`传播形式（表示中间语言地址l'处的变量R'由地址l处的R决定）。uflux为每条路径保持着一个执行状态并进行分析当遇到下列条件时会停止执行：
    * 达到与定义的最大执行指令数量。
    * 遇到一个没有模型化的函数调用。
    * 遇到一个间接跳转。
* **saluki 求解器** saluki输入程序IR，程序执行流以及安全策略，试图满足安全策略中的代码。

### 漏洞规范

CWE-78漏洞是一类典型的漏洞包括：
* CWE-89 SQL注入漏洞。
* CWE-337/676伪随机数漏洞。

CWE-252未检查返回值。如`keys = calloc(1, sizeof(int) * sc->files->size);`没有检查keys的返回值而size是用户可控的，导致漏洞。语法规范是
```
prop calloc_maybe_checked ::=
   p := calloc(_) |- when c jmp _ s.t. c/p
```

局限：无法描述内存冲突漏洞，特别是使用计数器拷贝溢出的，虽然无法检测输入的长度，但是可以检测不安全api造成的漏洞，如strcpy：
```
 prop if_strcpy_dst_depends ::=
   recv(_,*p,_,_),strcpy(_,*q) |- never
s.t. q/p
```

## MICROFULX

### 动机
函数间以及上下文数据流分析是不可预测的，任何寻求处理该方式的方法都只能使用类似的方法。

一个可行的方法是静态的枚举路径。第二种方法是考虑现实路径，通过使用fuzzing或符号执行来枚举输入。

uflux与上面的设计不同。uflux首先模拟具体的动态行为；其次执行行为可以通过策略实现参数化。这两种方式弥补了动态技术如fuzzing以及符号执行的不足：只能在运行时检测bug以及必须从程序入口点开始执行程序。

### 设计

分支策略（Branching Policy）：决定与非决定性分支（前者是评估具体走哪条分支后者是走所有的分支）。当使用决定性策略时，会去推断该执行哪条分支以此来避免路径爆炸；而使用非决定性分支时，会忽略分支谓词直接执行所有的分支生成相应的路径。

从任意地方开始执行（Execute Anywhere）：uflux可以从中间语言的任意指令处开始执行。允许我们使用相应的策略规范从感兴趣的地方开始执行。

数据依赖（Data Dependence）：初始的寄存器以及内存状态可以使用种子策略来生成。我们感兴趣的是数据流而不是数据本身的值。

精确度与权衡：为了实现数据依赖关系的高覆盖率、低误报率以及覆盖更多的路径。uflux必须寻找到数据依赖关系并忽略分支的条件，

## saluki逻辑系统以及语言

Saluki逻辑系统以及语言使得可以推理显示的数据依赖事实，引入了安全策略语言（security policy language）用于表达漏洞模式。

### 语法及语义

我们使用特定于域的语言来定义属性，语法允许我们将属性定义为模式序列和一组约束。如果所有模式在给定的约束下匹配成功，那么属性就成立。

语法示例如下图所示：
![Alt text](https://raw.githubusercontent.com/ray-cp/ray-cp.github.io/master/_img/Paper_Note_Saluki_Finding_Taint-style_Vulnerabilities_with_Static_Property_Checking/1554937146298.png)

我们将语义定义为一组公理，如下图所示：
![Alt text](https://raw.githubusercontent.com/ray-cp/ray-cp.github.io/master/_img/Paper_Note_Saluki_Finding_Taint-style_Vulnerabilities_with_Static_Property_Checking/1554937162074.png)

定义1: 函数模型p由三个命题函数组成` PP = (T , D, P)`。命题T表示存在术语t；命题`D(l′, R′, l, R)`表示数据流l标签处的r变量传递到了l'处的变量r'；命题`P(p, l, R)`表示用户定义的谓词p用于表示l标签处的变量R。

定义2: 术语t（program term t）是一个有序的5元组`(Lt, St, Ct, Dt, Ut) `：
* Lt是唯一标识术语的标签。
* St是一组静态后继者。
* Ct是一组影响后继者选择的程序变量。
* Dt是一组程序变量，由一个术语定义。
* Ut是术语中使用的一组程序变量。

现从上至下的给出saluki语言的定义：
* 属性（Property）： 公理（prop）指出，如果属性p⊢p's.t.c成立，则约束c下的模式p的匹配必须意味着在相同约束下匹配串联p，p'。
* 模式（Patterns）：用户定义模式，模式包含逻辑变量，逻辑变量会被绑定到程序的变量，这个过程称之为：模式评估。并用` [p]v =t R`表示，其意义为模式p的逻辑变量v模式评估到术语t中的r变量。
* 约束（Constraints）：模式在一些约束下匹配。

## 实现

由1675行OCaml代码组成，基于BAP框架实现。支持x86、x86-64以及ARM架构，saluki是开源的。

## 评估

主要评估以下问题：
1. 可以检测哪些实际漏洞？检测了5类漏洞发现了6类漏洞。
2. 速度如何，路径覆盖率如何？对于Coreutils软件平均每54s检测一个，覆盖率约为96%。

### 实验设计

在ubuntu 14.4 intel i7 2.2Ghz CPU 以及6GB 内存上运行实验。

挑选了5个不同厂商的soho路由器作为目标，攻击面为网络输入，厂商为cisco、Linksys、Belkin、Airlink、以及Buffalo。同时检测已知的漏洞包括linux内核、openssl（心脏滴血）、Pidgin以及C++编译的程序，最后一个用于展示saluki额外的能力。

对于性能则使用100个coreuntils程序。

### 0day 漏洞
下表展示了发现的6个0day漏洞以及5个已知漏洞。
![Alt text](https://raw.githubusercontent.com/ray-cp/ray-cp.github.io/master/_img/Paper_Note_Saluki_Finding_Taint-style_Vulnerabilities_with_Static_Property_Checking/1555023948693.png)

1. admin.cgi。一个命令注入漏洞（sprintf）；一个伪随机化种子漏洞。
2. pathload2。strcpy栈溢出漏洞。
3. easyconf。通过sprintf实现命令注入。
4. cm.cgi。通过rev以及getenv的QUETY_STRING，调用strcpy实现栈溢出。
5. Lighttpd。75个calloc未检查返回值。

### C++ 测试以及SQL注入测试
C++的虚表以及面向对象给构建CFG构建了不晓得困难。

saliku可以适应C++编译的程序，可以检查SQL注入等漏洞。

### 速度及覆盖率

速度：平均每54s一个coreutils程序，82分钟可评估150万条IR指令。
覆盖率：对于漏洞样本测试，覆盖率可达79%；对于coreutil组件，覆盖率可达96%。

## 相关工作
污点分析是一个相关工作。

Shankar用静态污点分析来检查格式化字符串漏洞(Detecting Format String Vulnerabilities with Type Quali-
fiers)。

uflux 和MicoroX（Micro execution,” International Conference on Software Engineering）相关类似，用于解决数据依赖关系。它是一个虚拟机，从用户给定的函数或代码处开始动态执行程序。我们与它不同的是我们使用IR。

还包括一些源码审计方式工具。

## 结论
Saluki一个污点啊数据安全分析工具。Saluki包括：
* 一个新颖的逻辑分析系统一个用于表达漏洞模式的属性语言。
* 一个新的技术uflux，用于提取路径以及上下文依赖关系。

对于描述漏洞以及发现漏洞具有一定的帮助。
















