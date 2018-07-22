# MiscSecNotes
此系列文章是本人关于学习 Web/Cloud/Docker 安全、渗透测试、安全建设等时记录的一些笔记，部分原创，部分是对网上文章的理解整理。如果可以找到原始参考链接时则会在文末贴出（如 乌云很多链接已失效，或者记不起当时存档时的链接），或者在文章开头写上 by xx，如有侵权请联系我（dameng34 at 163.com）删除或加上reference，感谢在网上共享知识的师傅们。 

### 捐赠链接
如果觉得以下内容对您有一定帮助，不妨小额赞助我，以鼓励我更好地完善内容列表。    
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<img src="./pictures/weixinzhifu.jpg" width=200>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<img src="./pictures/zhifubao.jpg" width=174>  


## 文章目录
### Web 安全
* Web服务基础
    * [HTTP协议](Web服务基础/HTTP协议.md)
    * [同源策略](Web服务基础/同源策略.md)
    * [前端基础](Web服务基础/前端基础.md)
    * [JS 跨域](Web服务基础/JS跨域.md)
	* [后端基础](Web服务基础/后端基础.md)
	* [常见函数](Web服务基础/常见函数.md)
	* [nginx安全配置](Web服务基础/nginx安全配置.md)
	* [apache安全配置](Web服务基础/apache安全配置.md)
	* [htaccess文件利用](Web服务基础/htaccess文件利用.md)

* 跨站脚本
	* [解码顺序](跨站脚本/解码顺序.md)
	* [反射XSS](跨站脚本/反射XSS.md)
	* [DOMXSS](跨站脚本/DOMXSS.md)
	* [存储XSS](跨站脚本/存储XSS.md)
	
* 跨站请求伪造
	* [CSRF](跨站请求伪造/CSRF.md)

* SQL 注入
	* [MYSQL注入](SQL%20注入/MYSQL注入.md)
	* [sqlmap tips](SQL%20注入/sqlmap%20tips.md)
	* [sqlmap 进阶](SQL%20注入/sqlmap%20进阶.md)

* Flash安全
	* [Flash xss](Flash安全/Flash%20XSS.md)
	* [Flash csrf](Flash安全/Flash%20CSRF.md)

* PHP安全
	* [php filter](PHP安全/php%20filter.md)
	* [php open_basedir](PHP安全/php%20open_basedir.md)
	* [php 安全编码](PHP安全/php%20安全编码.md)
	* [php 弱类型问题](PHP安全/php%20弱类型问题.md)
	* [php 代码审计入门](PHP安全/php%20代码审计入门.md)
	* [php 高级代码审计](PHP安全/php%20高级代码审计.md)
	* [php 框架审计](PHP安全/php%20框架审计.md)
	* [php 版本特点](PHP安全/php%20版本特点.md)
	* [php 防getshell思路](PHP安全/php%20防getshell思路.md)
	* [php 变形shell检测](PHP安全/php%20变形shell检测.md)
	* [php rasp实现](PHP安全/php%20rasp%20实现.md)  

* URL跳转
	* [url跳转](URL跳转/url跳转.md)

* XML注入
	* [XXE漏洞](XML注入/XXE漏洞.md)

* 点击劫持
	* [clickjacking](点击劫持/clickjacking.md)

* 服务端请求伪造
	* [SSRF 基础](服务端请求伪造/SSRF%20基础.md)
	* [SSRF 利用](服务端请求伪造/SSRF%20利用.md)

* 逻辑漏洞
	* [业务安全](逻辑漏洞/业务安全.md)
	* [支付安全](逻辑漏洞/支付安全.md)


* 命令执行
	* [命令执行](命令执行/命令执行.md)

* 文件包含
	* [文件包含](文件包含/文件包含.md)

* 文件解析
	* [文件解析](文件解析/文件解析.md)

* 文件上传
	* [文件上传](文件上传/文件上传.md)

* 信息泄露
	* [信息泄露](信息泄露/信息泄露.md)

* Bypass WAF
	* [bypass cdn find ip](Bypass%20WAF/bypass%20cdn%20find%20ip.md)  
	* [bypass sqli](Bypass%20WAF/bypass%20sqli.md)
	* [bypass xss](Bypass%20WAF/XSS_Bypass_Cookbook_ver_3.0.pdf)
	* [bypass waf（四个层次）](Bypass%20WAF/bypass%20waf（四个层次）.md)
	* [bypass waf Cookbook](Bypass%20WAF/bypass%20waf%20Cookbook.md)
	* [waf 之SQL注入防御思路分享](Bypass%20WAF/waf%20之SQL注入防御思路分享.md)

* 工具与思路
	* [漏洞检测思路](工具与思路/漏洞检测思路.md)
	* [漏洞挖掘与工具](工具与思路/漏洞挖掘与工具.md)
	* [子域名爆破](工具与思路/子域名爆破.md)  
	* [暴力破解](工具与思路/暴力破解.md)   
	
* 协议相关
	* [IPv6协议相关](协议相关/IPv6协议相关.md)   
	* [IPv6协议安全](协议相关/IPv6协议安全.md)  

* 漏洞修复
	* [漏洞修复指南](漏洞修复/漏洞修复指南.md)
	
### 渗透测试
* Linux渗透
	* [Linux执行命令监控](Linux渗透/Linux执行命令监控.md)  
	* [Linux 入侵检测](Linux渗透/Linux%20入侵检测.md)
	* [Linux 提权](Linux渗透/Linux%20提权.md)
	* [Rootkit 综合教程](Linux渗透/Rootkit%20综合教程.md)

* 端口转发
	* [代理知识](端口转发/代理知识.md)  
	* [渗透测试之代理](端口转发/渗透测试之代理.md)
	* [内网端口转发及穿透](端口转发/内网端口转发及穿透.md)  

* Windows渗透
	* [Windows 入侵检测](Windows渗透/Windows%20入侵检测.md)
	* [Windows 入侵排查](Windows渗透/Windows%20入侵排查.md)
	* [Windows 渗透测试](Windows渗透/Windows%20渗透测试.md)  

### 安全建设
* 安全建设
	* [Google基础设施安全设计概述翻译和导读](安全建设/Google基础设施安全设计概述翻译和导读.md)  
	* [中小企业网络安全建设指引](安全建设/中小企业网络安全建设指引.md)  
	* [大型互联网企业安全实践](安全建设/大型互联网企业安全实践.md)
	* [从Google白皮书看企业安全最佳实践](安全建设/从Google白皮书看企业安全最佳实践.md)
	* [安全产品的自我修养](安全建设/安全产品的自我修养.md)  
	* [产品经理眼中比较理想的WEB扫描器](安全建设/产品经理眼中比较理想的WEB扫描器.md)
	* [产品经理眼中未来两年的完美WAF](安全建设/产品经理眼中未来两年的完美WAF.md) 
	* [如何建立有效的安全策略](安全建设/如何建立有效的安全策略.md)
	* [大型网络入侵体系建设](安全建设/大型网络入侵体系建设.md)
	* [非即时反馈策略和随机噪音在业务安全中的应用](安全建设/非即时反馈策略和随机噪音在业务安全中的应用.md)  
	* [初探 下一代网络隔离和访问限制](安全建设/初探%20下一代网络隔离和访问限制.md)
	* [互联网企业安全之端口扫描监控](安全建设/互联网企业安全之端口扫描监控.md)
	* [谷歌的零信任安全架构实践](安全建设/谷歌的零信任安全架构实践.md)  
	* [互联网企业如何建设数据安全体系](安全建设/互联网企业如何建设数据安全体系.md)  
	* [我理解的安全运营](安全建设/我理解的安全运营.md)  
	

### docker 安全
* Docker安全
	* [docker安全杂谈](Docker安全/docker安全杂谈.md)  
	* [从自身漏洞和架构缺陷，谈docker安全建设](Docker安全/从自身漏洞和架构缺陷，谈docker安全建设.md) 
	* [关于docker的几点安全解析](Docker安全/关于docker的几点安全解析.md)
	* [绝不避谈docker安全](Docker安全/绝不避谈docker安全.md) 
	* [浅谈docker安全合规建设](Docker安全/浅谈docker安全合规建设.md)
	* [如何打造安全的容器云平台](Docker安全/如何打造安全的容器云平台.md)  

### 云计算安全
* 云计算安全
	* [经典网络与VPC](云计算安全/经典网络与VPC.md)
	* [浅析云计算环境下的安全风险](云计算安全/浅析云计算环境下的安全风险.md)
	* [云安全审计（评估）](云计算安全/云安全审计（评估）.md)
	* [从云消费者的角度谈云安全架构](云计算安全/从云消费者的角度谈云安全架构.md)  
