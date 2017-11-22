原文 by [tsrc博客](https://security.tencent.com/index.php/blog/msg/65)  

## 背景

对于腾讯的业务来说，有两个方面决定着WAF能否发挥效果，一个是合适处理海量流量的架构，另一个关键因素则是规则系统。架构决定着WAF能否承受住海量流量的挑战，这个在之前的篇章中简单介绍过（详情见[主流WAF架构分析与探索](http://security.tencent.com/index.php/blog/msg/56) 、[WAF应用层实现的架构漫谈](http://security.tencent.com/index.php/blog/msg/63)）。而规则系统则决定着WAF能否发挥完善的防护功能。    

SQL注入是由于开发人员没有对用户的输入进行相关的过滤，而使用户的输入可以被带入到SQL语句中执行，所引发的一种高危漏洞。可能造成信息泄露，数据库数据泄露，入侵等重大影响的后果。腾讯WAF对此种类型漏洞的防护目标就是确保不造成上述重大影响。    

本文介绍腾讯WAF如何针对SQL注入这种攻击进行防护。同时，最近TSRC与白帽子小伙伴们举办了一场SQL注入绕过挑战赛，发现了WAF规则系统一些不足之处，这里将详细介绍。    

感谢各位参与的白帽子小伙伴的大力支持。   

## 关键字防护

SQL注入最简单、粗暴但实用的方式就是检测一些关键字，通过把这些能造成影响的关键字加入黑名单，可以阻断大部分的利用代码。这类关键字主要包含几种：  

1、 SQL语句的关键保留字，如select from，union select，drop table，into outfile等。  

2、 MySQL等DBMS的内建函数，如version(),load_file()，sleep()，benchmark()等  

3、 MySQL等DBMS内建变量，如@@version等。  

4、 MySQL所识别的内联注释，如 `/*!union*/` `/*!select*/` 或 `/*!50000union*/`等 

## 真假条件防护

上述的关键字方法能过滤掉很多的利用代码，但还不全。SQL注入技术中有一种是通过利用注入条件的真假的方式来获取相关信息的，例如CGI：  `http://host/SQLi.php?id=1`对应的SQL语句为 `select * from t_table where id=1` 

`http://host/SQLi.php?id=1 or 1=1   => select* from t_table where id=1 or 1=1`    

`http://host/SQLi.php?id=1 and 1=2  =>select *from t_table where id=1 and 1=2`  

通过判断真假来获取MySQL的相关信息。对于这种方式如果通过简单的添加关键字会造成误报而影响业务的情况。这种情况下我们需要分析此类型的应用，例如：  

op a = b  
1、 op可以是and，or，<，>=，||，&&等  
2、 分隔符可以是空格，/**/注释等  
3、 a与b可以是数字，字符串，表名，函数，sql语句结果等等  

通过穷举此类应用方式来阻断相关的利用  


## 绕过防护

### URL编码

浏览器中输入URL是会由浏览器进行一次URL编码，而攻击可能会通过多次编码来对WAF进行绕过，例如：  
`Id.php?id=1%2520union/**/select 解码后实际为Id.php?id=1 union/**/select`  

如果只经过一次解码，则变成 `Id.php?id=1%20union/**/select`  

可能绕过正则表达式的检测  

通过循环多次URL解码解决此类问题  
 
### 特殊字符
      
% 00（%和00之间没有空格，编辑需要）如果直接URL解码，结果是C语言中的NULL字符。如果WAF使用string等数据结构来存储用户的请求，则解码之后会截断字符串，造成后面的内容不经过检测。例如  
`Id.php?id=1%20union/**/select`  

解码后可能变成：  

`Id.php?id=1[NULL]%20union/**/select`  

后面的%20union/**/select就躲过了WAF的检查，从而绕过WAF。解决方式：  

1、对% 00进行特殊处理  
2、不要使用string等存储用户的请求内容  
 
%a0是不换行空格，用于在字处理程序中标示禁止自动换行。使用正则表达式的\s无法匹配到这个字符，但在mysql中%a0与普通的空格一样，可以当成分隔符来使用。即对于Mysql来说，如下请求经过URL解码之后是一样的  
`Id.php?id=1%20union/**/select`  
`Id.php?id=1/**/union/**/select`  
`Id.php?id=1%a0union/**/select`  
对于这种字符，可以进行特殊处理后再进行匹配  
 
% 0b（%和0b之间没有空格，编辑需要）是垂直制表符，%09是水平制表符。在正则表达式中，\s与\t 均可匹配%09水平制表符，但匹配不了% 0b（%和0b之间没有空格，编辑需要）垂直制表符，需要使用\v匹配。如果正则表达式中，mysql的分隔符没有考虑到这种情况，也存在绕过的风险。    

半个中文字符。RE2等正则引擎默认使用UTF8编码，UTF8编码是3-4字符的编码，如果出现%e4等半个中文，即1个字符的时候，UTF8解码不出，用正则表达式的任意匹配符（.）是匹配不出来的。针对这种字符，可以考虑特殊处理或者变更引擎的编码。  
 
### 畸形HTTP请求
       
当向Web服务器发送畸形的，非RFC2616标准的HTTP请求时，Web服务器出于兼容的目的，会尽可能解析畸形HTTP请求。而如果Web服务器的兼容方式与WAF不一致，则可能会出现绕过的情况。例如  
`GET id.php?id=1%20union/**/select`  
这个请求没有协议字段，没有Host字段。但apache对这个请求的处理，默认会设置协议为HTTP/0.9，Host则默认使用Apache默认的servername
在这种情况下，可以选择：  
1、尽可能与Web服务器保持一致  
2、拒绝非标准的HTTP请求（在后端防护的Web服务器有多种类型时，如apache，nginx，lighthttpd等，由于每种web服务器的兼容性不一致，所以要实现1的WAF尽可能与Web服务器保持一致存在一定的困难）  

 
## 其他 

由于WAF实现的复杂性，与所防护的Web服务器的不一致性等原因，绕过的方式有很多种。以上所介绍的也仅是我们所遇到的绕过中比较典型的部分，特别与大家分享。期待与各位大牛交流相关技术，共同提高。  

再次感谢各位白帽子的参与与支持。  