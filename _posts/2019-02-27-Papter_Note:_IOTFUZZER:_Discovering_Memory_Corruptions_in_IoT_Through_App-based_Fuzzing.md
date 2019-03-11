---
layout: post
title:  "Papter Note: IOTFUZZER: Discovering Memory Corruptions in IoT Through App-based Fuzzing"
date:   2019-02-27 07:30:00
categories: Paper
permalink: /archivers/PAPER-NOTE
---

# Papter Note: IOTFUZZER: Discovering Memory Corruptions in IoT Through App-based Fuzzing
(Jiongyi Chen∗, Wenrui Diao, Qingchuan Zhao, Chaoshun Zuo, Zhiqiang Lin, XiaoFeng Wang, Wing Cheong Lau, Menghan Sun, Ronghai Yang, and Kehuan Zhang, The Chinese University of Hong Kong)

##  设计细节
从大的方面来说，设计包括两部分：app分析阶段及fuzz阶段。在app分析阶段，将iot app作为输入，分析它的UI并寻找网络触发事件，同时跟踪应用网络协议相关字段。经过以上步骤，协议记录下了所有的协议字段以及用于生成它们的相应函数。在fuzz阶段，我们对app进行动态插桩对感兴趣的字段进行变异，并对iot设备进行监控。最后fuzzer生成相应的结果。

具体来说，有以下四步：

1. UI分析阶段。分析整个UI，找到触发网络事件的控件，以使得可触发网络事件，方便后续的数据流分析以及fuzz。
2. 数据流分析阶段。记录跟踪一系列元素以实现找到网络消息字段。
3. 运行时变异。对相应的字段进行变异。
4. 运行监控。对iot设备进行监控，对于TCP连接，crash表示为TCP连接突然中断；UDP则是使用心跳机制来进行检测。

UI 分析：调用路径构建（使用Androguard以及EdgeMiner框架）--》 Activity转换图构造（使用Activity Transition Graph Construction）

数据流分析（主要是识别协议字段以及相关函数）使用修改后的污点分析框架TaintDroid，变异字段通过变异相关函数的参数来实现。对于TaintDroid做的改变主要有以下：

1. 污点源。包括IoT应用程序中的所有字符串、消息中经常使用的系统API以及来自UI的用户输入。
2. 污点传播。
3. 污点沉没。添加了在加密函数时沉没。

加密相关函数识别：首先，选择包含算术和按位运算的函数。 尽管可能存在许多候选加密函数，但在执行消息传递期间很少会调用它们。 然后，我们记录消息发送事件的执行跟踪，并根据相对于网络功能的位置细化候选函数。

运行时变异：主要是动态hook相应函数，并对相应函数字段进行变异。有两个好处：协议字段在加密或编码前被fuzz；无需逆向工程即可对未知协议进行fuzz。

函数hook-》Fuzz调度
fuzz算法：
```c
Input: c: number of identified fields in message M F: set of hooked functions
Output: T: number of mutations for each protocol field parameter of F
1 P = {p1, p2, ..., pn} = extract_param(F) ; // get parameter set
2 n = count(P) ; // get the number of parameters
3 s = random_gen(c) ; // randomly generate s,
(0<s<c)
4 T = {t1, t2, ..., tn} = get_solution(t1 + t2 + ...+ tn = s) ; // calculate one group of solutions
5 output T
```

fuzz策略：
1. 更改字符串长度以触发栈溢出或堆溢出以及越界访问。
2. 改变整数、double以及浮点数以触发整数溢出或越界。
3. 更改类型或提供空值，以触发混淆漏洞或未初始化漏洞。

运行监控：由于无法监控设备状态，所以只有通过设备的响应来推断设备的状态。

响应可能包括下面几部分：
1. 期望的响应。
2. 不期待的响应。错误处理消息
3. 无响应。
4. 断开连接。

对于TCP连接，主要是看连接是否中断或查看连接状态。
对于UDP连接，提取原有测试连接设备的心跳包，用于测试IoT设备。

## 实现及评估

### 实现
包括9100行java代码以及1400行python代码。

app分析阶段主要使用Androguard 、 EdgeMiner以及Monkeyrunner来获取调用图以及活动传递信息；依靠Xposed Module以及Monkeyrunner来进行污点分析以及信息传递的操作；使用TaintDroid模块来进行污点追踪；最后污点追踪信息写到了配置文件中以进一步使用。

fuzz阶段核心功能是基于Xposed框架实现的。

### 实验设置

选择了17款IoT设备。

测试环境：Ubuntu 14.4，i7内核，2.81Ghz，8G内存；在Google’s Nexus 4进行污点追踪。

性能：在9个设备中发现了15个严重漏洞（17款每款跑24小时）：5个栈溢出、2个堆溢出、4个空指针引用以及4个crash。

效率：与sulley以及BED进行对比。

准确度：一些物联网设备实际设计不佳，无法完全保证网络可靠性，使得心跳响应消失以及TCP连接断开，使得误报率存在的主要原因。为解决该问题，解决方法是将payload重新发送以确定是否真的造成崩溃。

## 讨论及缺陷

主要有以下不足：

* 测试范围：固件的覆盖率以及攻击面的覆盖率是不足的。
* 连接模式：目前只支持wifi，对于蓝牙等连接不支持。
* 云依赖：没有考虑提供云服务的设备。
* 结果评估：没有进行crash评估。
* 准确性：误报率以及错误率较高。


## 相关工作

基于污点的fuzz：TaintScope

对android的fuzz：AuthScope、SmartGen、AppsPlayground、IntentFuzzer、Buzzer、Droid- Fuzzer

嵌入式设备安全：RPFuzzer、DrE、FIE、Avatar 



