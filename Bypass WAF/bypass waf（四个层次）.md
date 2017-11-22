原文 by [破-见](https://weibo.com/ttarticle/p/show?id=2309404007261092631700&sudaref=www.google.com.hk&display=0&retcode=6102)  
  

  
绕过WAF的相关技术研究是WAF攻防研究非常重要的一部分，也是最有趣的部分，所以我在写WAF攻防时先写攻击部分。还是那句老话“不知攻焉知防”，如果连绕过WAF方法都不知道，怎么保证WAF能保护后端服务的安全。在我看来，WAF的绕过技术的研究将不断驱动防御水平提高。
  
以前一些WAF bypass的文章更像CASE的整理，都把焦点放在了规则对抗层面。绕过WAF规则，更像是正面对抗，属于下策。一直关注规则层面的绕过，太局限视野，看不到WAF在其他方面问题。木桶原理，防御能力并不会有本质的提高。本文将从4个层次讲解bypass WAF的技术，全方位提升WAF的防御能力。 讲完相关攻击技术后，以后再探讨WAF的设计架构、防御策略，这样显得每一处的考虑都是有意义的。
  

  
* 从架构层Bypass WAF 。
  
* 从资源限角度bypass WAF。
  
* 从协议层面bypass WAF。
  
* 从规则缺陷bypass WAF。
  

  
## 1. 架构层绕过WAF
  
### 1.1  寻找源站
  
如果流量都没有经过WAF，WAF当然无法拦截攻击请求。当前多数云WAF架构，例如百度云加速、360安全卫士等，通过更改DNS解析，把流量引入WAF集群，流量经过检测后转发请求到源站。如图，liusscs.com接入接入WAF后，liusscs.comd的DNS解析结果指向WAF集群，用户的请求将发送给WAF集群，WAF集群经过检测认为非攻击请求再转发给源站。
  

  
云WAF流量路径
  
![waf1](../pictures/waf1.png)
  

  
假设我们是攻击者，如何绕过WAF的安全检测呢？ 从云WAF架构考虑，如果HTTP请求都没有经过WAF集群直接到达源站，顺理成章bypass WAF。所以关键在于发现源站的IP地址。常用方法如下，可能还有很多很多思路，欢迎补充：
  
1)   信息泄露发现源站IP。信息泄露的途径很多，细心留意往往能发现。我常用的方法如下：
  

  
* 网站页面注销是否包含源站IP。
  
* GIHUB源代码泄露是否包含源站IP。
  
* 未接入WAF前，真实IP地址是否被搜索引擎等服务收录。
  

  
2)   穷举IP地址，根据特征发现服务器真实IP地址。对于国内的服务器，穷举国内的IP，访问每个IP的HTTP服务，根据页面特征检测响应页面，判断IP是否为源站IP地址。曾经乌云有人分享过，完成一次国内IP扫描只需要8-9小时，可是现在找不到那篇文章。
  

  
### 1.2  利用同网段
  
一些在云服务商的站点，同时使用云服务商提供的WAF服务。当流量不是通过DNS解析引流到WAF，流量必须经过WAF的检测，这是不能通过发行源站进行绕过。可以考虑在云服务商买一台VPS，通过VPS攻击目标站点，因为流量是局域网，可能不经过WAF检测，实现绕过。能不能成功，关键在于云服务商的网络配置。
  
![waf2](../pictures/waf2.png)
  
攻击机器与目标机器在同一局域网
  

  
### 1.3 利用边界漏洞
  
如果未能发现源站IP，可以尝试寻找子站的SSRF漏洞。如果子站访问目标站不经过WAF集群，可以利用SSRF漏洞来绕过WAF。
  

  
## 2. 资源限制角度绕过WAF
  
这是众所周知、而又难以解决的问题。如果HTTP请求POST BODY太大，检测所有的内容，WAF集群消耗太大的CPU、内存资源。因此许多WAF只检测前面的几K字节、1M、或2M。对于攻击者而然，只需要在POST BODY前面添加许多无用数据，把攻击payload放在最后即可绕过WAF检测。
  

  
## 3. 协议层面绕过WAF的检测    
  
即使流量都确保经过WAF，如果WAF的防御策略根本就没有检测payload，那么也就能绕过WAF。协议层面绕过WAF，利用WAF解析协议的问题，使得payload被认为不是请求的HTTP请求的内容。从个人经验总结出WAF解析协议的常出现问题的三个方向。
  

  
* 协议覆盖不全。
  
* 协议解析不正确。
  
* 协议解析后与WEB容器的协议解析不一致。
  

  
以下以实例说明利用协议绕过WAF的方法。通过CASE解析什么是协议覆盖不全、协议解析不正确、协议解析不一致。
  
### 3.1 协议未覆盖绕过WAF    
  
POST 请求常用有2种参数提交方式：
  

  
*     Content-Type: application/x-www-form-urlencoded;
  
*     Content-Type: multipart/form-data;
  

  
Waf未能覆盖Content-Type: multipart/form-data从而导致被绕过。或者WAF会认为它是文件上传请求，从而只检测文件上传，导致被绕过。如图，加速乐的WAF就存在被绕过的情况，是典型的协议未覆盖。
  

  
![waf3](../pictures/waf3.png)
  
普通攻击请求被拦截
  

  
![waf4](../pictures/waf4.png)
  
协议未覆盖导致绕过
  

  
### 3.2 利用协议解析不一致绕过WAF的典型例子
  
如图中的payload，WAF解析出来上传的文件名是test3.jpg，而PHP解析到的文件名是”test3.jpg\nf/shell.php”，因为”/”是目录分隔符，上传的文件名变为shell.php，从而绕过WAF的防御。当时这个方法几乎通杀所有WAF，可见利用协议层绕过WAF的威力。就文件上传而言，还有更多因为协议解析导致绕过，见3.3节。
  
![waf5](../pictures/waf5.png)
  
WAF与PHP解析文件上传协议不一致导致绕过
  

  
### 3.3  利用协议解析问题绕过WAF文件上传    
  
WAF的文件上传规则使用正则表达式匹配上传的文件名是否包含“0x00”等，所以正面绕过正则表达式匹配几乎不可能。如果不从规则角度考虑，利用协议解析问题让WAF无法匹配到正确的文件名，就能绕过WAF实现文件上传。
  
3.3.1 协议解析不正确-文件名覆盖(一)    
  
在multipart协议中，一个文件上传块存在多个Content-Disposition，将以最后一个Content-Disposition的filename值作为上传的文件名。许多WAF解析到第一个Content-Disposition就认为协议解析完毕，获得上传的文件名，从而导致被绕过。如图，加速乐的WAF解析得到文件名是”sp.pho”，但PHP解析结果是”sp.php”，导致被绕过。
  
![waf6](../pictures/waf6.png)
  

  
​3.3.2 协议解析不正确-文件名覆盖（二）    
  
在一个Content-Disposition 中，存在多个filename ，协议解析应该使用最后的filename值作为文件名。如果WAF解析到filename="p3.txt"认为解析到文件名，结束解析，将导致被绕过。因为后端容器解析到的文件名是t3.jsp。
  
Content-Disposition: form-data;name="myfile"; filename="p3.txt";filename="t3.jsp"
  

  
3.3.3 协议解析不正确-遗漏文件名    
  
当WAF遇到“name=”myfile";;”时，认为没有解析到filename。而后端容器继续解析到的文件名是t3.jsp，导致WAF被绕过。
  
Content-Disposition: form-data;name="myfile";; filename="t3.jsp"。
  

  
3.3.4 协议解析不正确-未解析所有文件    
  
multipart协议中，一个POST请求可以同时上传多个文件。如图，许多WAF只检查第一个上传文件，没有检查上传的所有文件，而实际后端容器会解析所有上传的文件名，攻击者只需把paylaod放在后面的文件PART，即可绕过。
  
![waf7](../pictures/waf7.png)
  

  
![waf8](../pictures/waf8.png)
  
​
  
​3.3.5 协议解析不一致-文件名解析兼容性    
  
multipart协议中，文件名的形式为“filename="abc.php"”。但是Tomcat、PHP等容器解析协议时会做一些兼容，能正确解析 ”filename="abc.php”、”filename=abc.php”、 ”filename='abc.php'”。而WAF只按照协议标准去解析，无法解析文件名，但是后端容器能正确获得文件名，从而导致被绕过。场景的绕过形式：
  

  
* Content-Disposition: form-data; name="file"; filename=abc.php
  
* Content-Disposition: form-data; name="file"; filename="abc.php
  
* Content-Disposition: form-data; name="file"; filename='abc.php'
  

  
### 3.4    参数污染    
  
请求中包含2个参数名相同的参数typeid，第一个是正常参数的值，第二个参数才是payload。如果WAF解析参数使用第一个值，没检查第二个值，将导致绕过。这是很久很久的一个CASE，现在几乎没有WAF存在这个问题。
  
`/forum.php?typeid=644&typeid=if(now()%3dsysdate()%2csleep(19.844)%2c0)/*'XOR(if(now()%3dsysdate()%2csleep(19.844)%2c0))OR'%22XOR(if(now()%3dsysdate()%2csleep(19.844)%2c0))OR%22*/`
  

  
### 3.5 小结    
  
当想到利用协议解析绕过WAF检测时，并不敢确定效果，经过实践检验，协议解析绕过WAF的思路可行且有效。在研究利用协议绕过WAF时，需要大胆地猜测WAF解析协议时容易犯什么错误，科学地一点点验证。通过分析PHP、tomcat的协议解析源码，找出它们与HTTP标准协议的差异是发现绕过WAF的快速有效方法。
  
本节利用multipart/form-data协议解析过问题文件上传的思路，思路同样可用于绕过multipart/form-data协议POST FROM表单提交参数的检测。
  

  
## 4. 规则层面的绕过    
  
对基于正则表达式的WAF，绕过WAF规则主要思考安全工程师写WAF规则时在想什么，容易忽略什么，推断一些可能绕过的方式，然后多次尝试进行验证。比起完整罗列绕过CASE，我更喜欢分析绕过思路。这次以最受关注的SQL注入、文件包含为例，分析一下绕过思路。
  

  
### 4.1. SQL注入绕过    
  
绕过SQL注入规则主要利用WAF规则本身的问题、未考虑到SQL语法变形、及后端数据库SQL语句语法特性。不同的数据库虽然遵守SQL标准，但是通常会加入特有的语法。WAF的防御策略要兼顾各种数据库的特殊语法，容易遗漏，从而被利用绕过WAF。以下MySQL为例，分析绕过SQL注入的一些思路。
  

  
4.1.1   注释符绕过    
  
`/*xxx*/`是注释，也可以充当空白符。因为 `/**/`可使得MySQL对sql语句(`union/**/select`)词法解析成功。事实上许多WAF都考虑到`/**/`可以作为空白分，但是waf检测 `/\*.*\*/`很消耗性能，工程师会折中，可能在检测中间引入一些特殊字符，例如：`/*\w+*/`。或者，WAF可能只中间检查n个字符`/\*.{,n}\*/`。根据以上想法，可以逐步测试绕过方法：
  

  
* 先测试最基本的：`union/**/select`
  
* 再测试中间引入特殊字：`union/*aaaa%01bbs*/select`
  
* 最后测试注释长度：`union/*aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa*/select`
  

  
同理，对于`/*!xxx*/`，可以采取类似的思路绕过WAF。
  

  
4.1.2   空白符绕过    
  
基于正则表达式的WAF， SQL注入规则使用正则表达式的“\s”匹配空格，例如”select\s+union”。利用正则表达式的空白符与MySQL空白符的不同可绕过WAF规则。如何这些MySQL的特性？通过fuzz,每次更改正常SQL语句的某部分，替换为其他字符，判断语法是否正确，即可判断出来MySQL语法特性。当然，也可以通过分析MySQL词法来发现语法特性，从而找到绕过方法。
  
利用空白符进行绕过，测试WAF时尽可能减少其他原因的影响，例如”union select”被拦截，只需把中间空白符替换为”%250C”, “%25A0”进行绕过测试。
  

  
* union%250Cselect
  
* union%25A0select
  
 
  
![waf9](../pictures/waf9.jpg)
  

  
4.1.3 函数分隔符    
  
对基于正则表达式的WAF，我们猜测安全工程师写WAF规则时，可能不知道函数名与左括号之间可以存在特殊字符，或者遗漏可以存在特殊字符。例如匹配函数”concat()”的规则写法，“concat(”或者”concat\s*(”，就没有考虑到一些特殊字符。相应的绕过方法，在特殊位置引入特殊的分隔符，逐个测试。这些特殊分隔符发现也是通过Fuzz出来的。
  
* concat%2520(
  
* concat/**/(
  
* concat%250c(
  
* concat%25a0(
  

  
举一反三，寻找类似的关键位置，Fuzz特殊字符，发现更多的绕过新方法。猜测工程师们写规则因为各种原因容易遗漏的点，进行绕过WAF检测。
  

  
4.1.4   浮点数词法解析    
  
利用MySQL解析浮点数的特点，正则表达式无法匹配出单词union，但是MySQL词法解析成功解析出浮点数、sql关键字union。
  

  
* select * from users where id=8E0union select 1,2,3,4,5,6,7,8,9,0
  
* select * from users where id=8.0union select 1,2,3,4,5,6,7,8,9,0
  
* select * from users where id=\Nunion select 1,2,3,4,5,6,7,8,9,0
  

  
4.1.5   利用error-based进行SQL注入    
  
Error-based的SQL注入函数非常容易被忽略，导致WAF规则过滤不完整。随着对MySQL研究越来越深，被发现可用于error-based SQL注入的函数越来越多，同时也给绕过WAF造就了更多机会。常见的函数：
  

  
* extractvalue(1, concat(0x5c,md5(3)));
  
* updatexml(1, concat(0x5d,md5(3)),1);
  
* GeometryCollection((select*from(select*from(select@@version)f)x))
  
* polygon((select*from(select name_const(version(),1))x))
  
* linestring() 
  
* multipoint() 
  
* multilinestring() 
  
* multipolygon() 
  

  
利用Error-based的SQL注入函数进行绕过时，可以结合函数分隔符，或其他方法灵活运用。
  

  
4.1.6   Mysql特殊语法    
  
最有效的发现手段，还是去读读MySQL词法分析源代码。和协议绕过类似，挖掘SQL标准与MySQL的词法分析差异是发现WAF SQL注入绕过的有效手段。以下是MySQL语法的一个特写(ps:不是我发现的)：
  
select{x table_name}from{x information_schema.tables};
  

  
4.1.7 综合利用实例    以上都是SQL注入绕过中的技术点，在实际渗透测试中，需要灵活综合利用才能达到完整绕过，读取数据数据。以下给出完整绕过WAF SQ注入检测的实例。如图，本例中综合多个绕过技术点，最终实现完整绕过实现读取数据。
  

  
* 利用浮点数词法解析，绕过union select 的检测。
  
* 同样，函数分隔符思想集和浮点数词法解析，绕过关键字from的检测。
  
* 最后空白分分割绕过INFORMATION_SCHEMA.TABLES的检查
  

![waf11](../pictures/waf11.png)  
  

  
### 4.2 文件包含    
  
文件包含分为相对路径、绝对路径文件包含。在相对路径文件包含中，最终根据Linux虚拟文件系统(vfs)的规则查找文件，通过分析vfs的文件路径解析规则，提取其中规则特点，用这些特点去绕过WAF。在绝对文件路径包含中，主要是根据攻击场景，WAF未过滤一些协议、未过滤某些特殊路径。
  
4.2.1          相对路径的绕过
  
写WAF文件包含规则时，如果检测单一的”../”，误报会非常多，所以WAF文件包含规则通常会检测连续的“../"。根据vfs解析路径的语法，解析到“//”文件路径不变，解析到“/./”文件路径依然。 通过避免连续的"../"，从而绕过WAF文件包含规则。Eg: `././..///./.././/../etc//passwd`，它等价于`../../../etc/passwd`。如图，一个实际的绕过WAF文件包含的 CASE
  
  
![waf13](../pictures/waf13.png)
  

  

  
​4.2.2 绝对路径的绕过（一）
  
* WAF没有考虑到路径中插入“/./”、“//”对于vfs解析路径是等价的，导致可被绕过。例如 /etc/./passwd 与 /etc/passwd 是等价的。还可以通过组合“/./”、“//”进行绕过，eg. /etc///.//././/passwd。
  
  
![waf15](../pictures/waf15.png)
  

  

  
* ​对于绝对路径文件包含，WAF一般会拦截常见路径，而不会防御所有的绝对路径。因此，在渗透测试中，可以包含其他的路径下一些文件，例如/usr/local/nginx/conf/nginx.conf。
  
![waf17](../pictures/waf17.png)

  
* 如果WAF只检测连续的../，检查开始路径为Linux的目录名，可以采用/wtt/../绕过WAF文件包含检测。 例如，“/wtt/../etc/passwd”， wtt不是Linux标准目录，不会被规则匹配。WAF只检测连续的../，但是只使用一个../，不被拦截。最终读取/etc/passwd文件。
  

  
4.2.2 绝对路径的绕过（二）    
  
利用WAF未检测的协议。PHP 文件包含支持的协议，在渗透测试中，看环境选择可行的方法
  

  
* file:// — Accessing local filesystem 
  
* http:// — Accessing HTTP(s) URLs 
  
* ftp:// — Accessing FTP(s) URLs 
  
* php:// — Accessing various I/O streams 
  
* zlib:// — Compression Streams data:// — Data (RFC 2397) 
  
* glob:// — Find pathnames matching pattern 
  
* phar:// — PHP Archive 
  
* ssh2:// — Secure Shell 2 
  
* rar:// — RAR 
  
* ogg:// — Audio streams 
  
* expect:// — Process Interaction Streams
  

  
## 5.     总结    
  
一个好WAF不是吹出来的，是实践检验出来的。研究WAF的绕过手段，是为了更好的提升WAF的防御能力。在研究突破的过程中，不要仅仅停留在正则表达式，基本漏洞原理，需要对涉及并深入更多的领域，例如HTTP协议理解和PHP、Tomcat对HTTP协议源码分析，MySQL词法分析，和Fuzz的思路等。在此过程中，会有许多乐趣，也会有各方面能力的提升。
  
