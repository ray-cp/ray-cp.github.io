---
layout: post
title:  "Paper Note: Internet of Things: A survey on the security of IoT frameworks"
date:   2019-04-01 07:30:00
categories: PAPER_NOTE
permalink: /archivers/Paper_Note_Internet_of_Things_A_survey_on_the_security_of_IoT_frameworks
---

2019.3.13-2019.4.01

感觉这篇文章看的意义不大，但是由于已经开头了，所以还是看完了。文章的主要内容为介绍了一些IoT开发框架以及这些框架的架构、应用规范、硬件规范以及一些安全特色，作用算是帮助了解了一些框架吧。
## 绪论

物联网的普及极大的方便了人们的生活，但是它的安全问题也是需要注意的。

开发IoT程序具有以下挑战，使得开发者需要实现各种软硬件功能：
1. 分布式计算的高度复杂性
2. 缺乏处理低级别通信和简化高级实现的一般准则或框架
3. 多种编程语言
4. 各种通信协议。

近来，出现了一些IoT框架，本文比较了最近比较流行的IoT框架的安全特点包括：
* Amazon的AWS IoT
* ARM Bed
* 微软的Azure IoT组件
* 谷歌的Brillo/Weave
* Ericsson的Calvin
* 苹果的HomeKit
* Eclipse的Kura
* 以及Samsung的SmartThing

主要贡献有：
* 提供当前最先进的物联网平台的总结图，并确定此类平台当前设计的趋势。
* 提供各种框架的不同架构之间的高级别比较。
* 专注于为确保这些框架中的安全性和隐私而设计的模型和方法。
* 说明每个框架在满足安全要求和满足标准指南方面的优缺点。
* 探索设计缺陷并打开大门，对潜在威胁进行更深入的安全分析。

## 背景知识

所有IoT设备的相似之处在于连接网络并交换数据。

关系的IoT框架主要涉及物理实体以及协议实现。物理试题包括：智能设备（传感器等）、服务器（作为路由存储的云端服务器）、终端（接入IoT设备的应用）；协议是指不同层以及端到端通信的协议。

目前还没有标准的IoT框架。我们考虑一个三层的架构：应用层（Application）、网络层（Network）以及感知层（Perception）。
![Alt text](https://raw.githubusercontent.com/ray-cp/ray-cp.github.io/master/_img/Paper_Note_Internet_of_Things_A_survey_on_the_security_of_IoT_frameworks/1552432461802.png)

IoT设备的模型如图所示。IoT框架的意义在于隐藏了开发应用的复杂性，简化了响应的过程。框架提供了感知计算以及传递与处理数据的过程。

IoT框架的设计过程主要会产生以下问题：
* 如何处理设备与云端、云端与终端的通信？
* 每个框架中的硬件和软件依赖是什么？
* 框架使用的安全标准是什么
* 框架中每层提供的安全相关功能是什么？
* 如何解决在相关方中保护安全和隐私的问题？ 用于提供身份验证，授权，访问控制，加密和其他安全功能的技术是什么？

## 相关工作

IoT领域已经发表了一些综述。

Al-Fuqaha等人查了物联网，提到物联网领域的各种物联网架构、市场机会、物联网元素、通信技术、标准应用协议、主要挑战和开放研究问题
```
Al-Fuqaha A, Guizani M, Mohammadi M, Aledhari M, Ayyash M. Internet of
things: a survey on enabling technologies, protocols, and applications. IEEE
Commun Surveys Tutorials 2015;17(4):2347–76.
```

Derhamy等人提出了许多商业物联网框架，并提供了基于利用方法、支持的协议、工业用途、硬件要求和应用程序开发的比较分析。 
```
Derhamy H, Eliasson J, Delsing J, Priller P. A survey of commercial frame- works for the internet of things. In: 2015 IEEE 20th conference on emerging technologies & factory automation (ETFA). IEEE; 2015. p. 1–8.
```

安全相关的有：

一篇论文从四个方面调查了IoT遇到的安全与隐私问题。
```
Yang Y, Wu L, Yin G, Li L, Zhao H. A survey on security and privacy issues in
internet-of-things. IEEE Internet Things J 2017. 
```
两篇论文主要描述了IoT三层架构中的安全与隐私问题
```
Kumar JS, Patel DR. A survey on internet of things: security and privacy is-
sues. Int J Comput Appl 2014;90(11).
Vikas B. Internet of things (iot): A survey on privacy issues and security 2015.
```

据调查，本综述是第一个通过评估商业化物联网框架安全特性来解决编程层面的物联网安全问题。

## IoT 框架

### AWS IoT 

AWS （Amazon Web Services）IoT是亚马逊发布的云平台。

**架构**

![Alt text](https://raw.githubusercontent.com/ray-cp/ray-cp.github.io/master/_img/Paper_Note_Internet_of_Things_A_survey_on_the_security_of_IoT_frameworks/1552603757601.png)
如图是AWS的框架，由四个组件构成：
* 设备网关：设备网关充当连接设备和云服务之间的中介，允许这些设备通过MQTT协议进行通信和交互。
* 规则引擎：规则引擎处理传入的已收集消息，然后通过AWS Lambda将其转换并传送到其他订阅设备或AWS云服务以及非AWS服务，以进行进一步处理或分析。
* 注册表：为每个连接的设备分配一个单独的ID。
* Device Shadows：AWS IoT通过创建名为Device Shadow的虚拟映像来实例化每个连接的设备。它可以表示设备在线时的最后的状态。
AWS提供了`Device SDK`来使得开发更加的便捷。

** 智能应用规范**
没有平台或编程语言的限制。

** 硬件规范 **
AWS IoT提供了一个开源客户端库和设备SDK使框架可用于多个嵌入式操作系统和微控制器平台。

** 安全特色 **
使用多层安全架构，如图所示：
 ![Alt text](https://raw.githubusercontent.com/ray-cp/ray-cp.github.io/master/_img/Paper_Note_Internet_of_Things_A_survey_on_the_security_of_IoT_frameworks/1552605094343.png)

认证：要连接一个新的设备，设备需要经过认证。AWS IoT提供了三种验证身份的方法：X.509证书[34]、AWS IAM用户组和角色以及AWS Cognito认证。

授权和访问控制：AWS IoT中的授权过程基于策略。为每个证书或者是认证的用户授予相应的规则和策略。

安全通信：所有的流量都是通过SSL/TLS协议加密的。支持许多的加密组件如：ECDHE- ECDSA-AES128-GCM-SHA256、AES128-GCM-SHA256,、AES256- GCM-SHA384等，AWS IoT云为每个合法用户分配一个私有主目录。 使用对称密钥密码加密存储所有私有数据。

### ARM mbed IOT

ARM mbed IoT是一个基于ARM微控制器开发物联网应用程序的平台。它的优势在于提供一个通用操作系统以及支持设备与端的通信。

** 架构 **
ARM mbed IoT平台的关键构建链是mbed操作系统、mbed客户端库、mbed云、mbed设备连接器和基于ARM微控制器的硬件设备。 mbed OS代表了该平台的支柱。 因此我们首先讨论该OS，该OS架构如图所示。
![Alt text](https://raw.githubusercontent.com/ray-cp/ray-cp.github.io/master/_img/Paper_Note_Internet_of_Things_A_survey_on_the_security_of_IoT_frameworks/1552606095338.png)
该框架是开源的框架。

** 智能应用规范**
IoT是被需使用C++语言进行开发，而对于用户端没有要求，只要支持REST API即可。

** 硬件规范 **
主要是支持基于ARM Cortex-M 32位的处理器，支持RISC指令结构。

** 安全特色 **
mbed IoT平台的安全机制主要在以下三个层次实施：
* 设备本身（作为硬件和mbed OS）。
* 通信渠道。
* 开发嵌入式和智能应用程序的生命周期。

![Alt text](https://raw.githubusercontent.com/ray-cp/ray-cp.github.io/master/_img/Paper_Note_Internet_of_Things_A_survey_on_the_security_of_IoT_frameworks/1553036384551.png)
安全架构如上图所示，核心组件包括：
* mbed uVisor：设备端安全解决方案，能够将各种软件与其他软件以及操作系统隔离开来。
* mbed TLS：主要用于安全通信以及认证授权。

这些组件提供系统的认证、授权与访问控制（多道程序设计，进程内存互相隔离）、安全通信。

### Azure IoT 组件
该组件是微软实现的平台。

**架构**

架构如下图所示：
![Alt text](https://raw.githubusercontent.com/ray-cp/ray-cp.github.io/master/_img/Paper_Note_Internet_of_Things_A_survey_on_the_security_of_IoT_frameworks/1553036932742.png)
设备通过一个预定义的云网关与Azure通信。

Azure IoT Hub 是一种Web服务，它支持设备和云后端服务之间的双向通信，同时考虑到所有安全要求。

主要有两类IoT设备：IP-capable（支持IP）、PAN。IP-capable主要通过支持的通信协议（AMQPs、MQTT、HTTP等）以IP与Hub进行交流。

Field 网关是PAN（个人局域网）设备的聚合点。因为这些设备无法支持安全的HTTP会话，所以他们将数据发送至网关，再通过网关去通信。

IoT solution 后端层表示一系列的Azure云服务（机器学习等）

**智能应用规范**
该框架提供了不同的SDK以支持不同的设备及平台，支持C、Node.js、Java、Python以及.Net等语言。

**硬件规范**
该框架支持一系列的操作系统以及硬件设备，满足一下条件的设备均可与云端通信：
* 支持TLS：用于安全通信。
* 支持SHA-256：用于认证
* memory footprint
* 实时时钟：用于建立安全TLS连接等。

**安全特色**
安全架构如图所示。
![Alt text](https://raw.githubusercontent.com/ray-cp/ray-cp.github.io/master/_img/Paper_Note_Internet_of_Things_A_survey_on_the_security_of_IoT_frameworks/1553037994227.png)

包括一下功能：
* 认证。TLS以及使用X.509证书。
* 授权与访问控制。使用AAD（Azure Active Directory）提供基于策略的授权模型，隔离设备数据。
* 安全通信。

### Brillo/Weave

由谷歌开发的IoT框架，主要由Brillo及Weave两个部分组成。前者是一个基于安卓的操作系统，用于开发嵌入式设备；后者用于通信。

**架构**
下图提供了该框架的一个基本架构。
![Alt text](https://raw.githubusercontent.com/ray-cp/ray-cp.github.io/master/_img/Paper_Note_Internet_of_Things_A_survey_on_the_security_of_IoT_frameworks/1553727110495.png)

Brillo是一个C/C++编写的基于安卓的操作系统。

OTA是更新组件，Metrics组件用于收集信息。

Weave提供通信，主要提供的服务包括认证、发现以及交流等。使用JSON数据格式。有一套SDK用于开发。

**智能应用规范**

支持iOS以及安卓。

**硬件规范**

Brillo操作系统只与Microprocessor（MPU）设备兼容，要求至少有35M内存，只支持ARM、Intel(x86)以及MIPS架构。

**安全特色**

安全在该框架的优先级很高。

认证：主要由Weave提供，支持OAuth 2.0。

授权与访问控制：由内核确保访问控制，提供沙箱为每个用户提供独立的空间。

安全通信：主要通过支持SSL/TLS协议实现。

### Calvin

Calvin是由Ericsson发布的开源IoT框架。

**架构**
下图提供了该框架的一个基本架构。
![Alt text](https://raw.githubusercontent.com/ray-cp/ray-cp.github.io/master/_img/Paper_Note_Internet_of_Things_A_survey_on_the_security_of_IoT_frameworks/1553728215373.png)


下面的两部分组成了运行环境的基础。再往上是一个`platform dependent runtim`层，它提供不同环境下所有的通信方式，同时也提供了硬件的抽象接口。`platform independent runtime`层则是提供给Actors的接口。

Proxy Actors是Calvin实现的一个特色，使用该属性，基于Calvin的应用程序可以使用非Calvin应用程序进行扩展和运行。 Proxy Actors通过处理通信和执行将数据转换为两个系统都能理解的消息或令牌的任务，帮助将不同系统集成为一个系统。

**智能应用规范**

该框架将一个应用的开发分成了四步：

Describe：编写actor，描述任务，定义端口。
Connect：使用CalvinScript连接actor
Deploy：为actor提供接入点
Manage：监控应用的生命周期

**硬件规范**

Calvin支持不同的平台，从感应器到数据中心。支持分布式云环境。硬件中唯一需要的是支持其中一种兼容的通信协议。

**安全特色**

认证：三种模式。本地认证；认证服务器；使用RADIUS服务器。
认证与访问控制：只支持本地认证或者是使用认证服务器。
安全通信：下图是通信模型，使用TLS通信，支持ECC算法加密以及提供数字证书。
![Alt text](https://raw.githubusercontent.com/ray-cp/ray-cp.github.io/master/_img/Paper_Note_Internet_of_Things_A_survey_on_the_security_of_IoT_frameworks/1553813416683.png)

### HomeKit

HomeKit是苹果支持的IoT框架，支持用户通过智能app控制设备。

**架构**
核心组件包括：配置数据库、附件协议（Accessory Protocol）、API以及设备

![Alt text](https://raw.githubusercontent.com/ray-cp/ray-cp.github.io/master/_img/Paper_Note_Internet_of_Things_A_survey_on_the_security_of_IoT_frameworks/1553813827470.png)


**智能应用规范**
主要是为家用设计的平台框架。它提供了简单的接口，同时也允许用户远程访问。


**硬件规范**
该框架只与支持HomKit的设备兼容，也支持使用苹果MFi授权的第三方硬件。


**安全特色**
利用了iOS的很多特性来实现安全。

认证：使用公私钥签名算法Ed25519来实现认证。蜜月存储在iCloud的Keychain中。

授权与访问控制：应用要访问home数据需经过用户允许，app使用沙箱技术隔离。实现了ASLR技术来防止溢出等漏洞攻击。

安全通信：由于集成了iOS系统的安全组件，所以只有可信任的代码可以在设备中运行。

### Kura
Kura是一个Eclipse的IoT工程，致力于为MM应用提供一个基于Java/OSGi-based的框架。

**架构**
架构如图所示，只支持基于linux的设备。
![Alt text](https://raw.githubusercontent.com/ray-cp/ray-cp.github.io/master/_img/Paper_Note_Internet_of_Things_A_survey_on_the_security_of_IoT_frameworks/1553815176954.png)



**智能应用规范**
Java是主要开发语言，一个应用被当作一个OSGi模块并被容器包装。提供一个web管理界面允许开发者远程管理应用。


**硬件规范**
有两个硬性要求：基于linux系统；Java7以后的版本。


**安全特色**

认证：使用java运行时环境所提供的安全socket。

授权与访问控制：有安全管理组件确保文件不被恶意访问，提供api来管理安全策略。

安全通信：支持SSL协议，所有的通信都使用该协议。

### SmartThings

该框架由Samsung开发。

**架构**
架构如图所示，主要由以下几部分组成：云后端、hub/home控制器、客户端app、IoT设备。
![Alt text](https://raw.githubusercontent.com/ray-cp/ray-cp.github.io/master/_img/Paper_Note_Internet_of_Things_A_survey_on_the_security_of_IoT_frameworks/1554073723629.png)





**智能应用规范**
app应该是使用一个基于web的IDE实现，编程语言为Groovy。由五部分构成：definition、preferences、predefined callbacks、event handlers以及mappings。


** 硬件规范 **
支持很多设备，唯一的要求是需要支持一个兼容的协议。


**安全特色**

认证：使用OAuth/OAuth2协议来认证。

安全通信：使用128位-aes通信，也支持SSL/TLS。

## 总结

总的如下表所示：
![Alt text](https://raw.githubusercontent.com/ray-cp/ray-cp.github.io/master/_img/Paper_Note_Internet_of_Things_A_survey_on_the_security_of_IoT_frameworks/1554074185947.png)














