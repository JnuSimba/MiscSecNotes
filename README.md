# MiscSecNotes
此系列文章是本人关于学习 Web安全、渗透测试等时记录的一些笔记，部分原创，部分是对网上文章的理解整理。如果可以找到原始参考链接时则会在文末贴出（如 乌云很多链接已失效，或者记不起当时存档时的链接），或者在文章开头写上 by xx，如有侵权请联系我（dameng34 at 163.com）删除或加上reference，感谢在网上共享知识的师傅们，觉得内容不错的朋友请不要吝啬您的 **star**。 

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
  * [bypass sqli](Bypass%20WAF/bypass%20sqli.md)
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

* 漏洞科普

  * [fastjson远程命令执行漏洞原理](漏洞科普/fastjson远程命令执行漏洞原理.md)
  * [PHP-FPM 远程命令执行漏洞](漏洞科普/PHP-FPM%20远程命令执行漏洞.md)
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
	* [Windows 应急响应](Windows渗透/Windows%20应急响应.md)  

