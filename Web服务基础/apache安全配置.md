原文 by wooyun  

## 0x00 测试环境

centos6.5+apache2.2.15+php5.3.3  

## 0x01 php的运行模式介绍

php的运行模式分四种：  

1. CGI通用网关接口 
2. fast-cgi常驻型的CGI 
3. cli命令行运行 
4. web模块模式 

一般情况下，apache使用web模块模式运行php  

## 0x02 Apache运行原理介绍

Apache是基于模块化设计的，各个模块在系统启动的时候按需载入。Apache对于php的解析，就是通过众多Module中的php Module来完成的。  
![](../pictures/apacheconf1.png)  

所以，php加载成为了apache的一个模块，可以把apache和php当成一个整体看待。    

当浏览器请求一个php文件时，我们可以理解为apache直接处理返回给浏览器结果，服务器上也只会有httpd进程，而不会有php进程。    

apache的一些配置主要是通过httpd.conf来实现的，但是可以在httpd.conf中开启对.htaccess的支持，然后在.htaccess中进行配置。不过一般情况下，不应该使用.htaccess文件，除非你对主配置文件没有访问权限。.htaccess文件应该被用在内容提供者需要针对特定目录改变服务器的配置而又没有root权限的情况下。如果服务器管理员不愿意频繁修改配置，则可以允许用户通过.htaccess文件自己修改配置。    

## 0x03 Apache安全配置方案

1. 选择漏洞较少的apache版本，并打上安全补丁  
查看apache版本号：httpd -v    
然后在sebug上搜索该版本号有什么漏洞，可根据提示提升版本或者打上补丁      

2. 关闭一些不使用的模块及功能  
可在LoadModule前加#，来注释掉一些不使用的模块      

3. 隐藏banner信息  
`ServerTokens OS`　 修改为：`ServerTokens Prod` （在出现错误页的时候不显示服务器操作系统的名称）      
`ServerSignature On` 修改为：`ServerSignature Off`（不回显apache版本信息）    

4. 删除默认网站及页面  
删除默认的页面，防止泄露服务器信息    

5. 可修改banner信息  

6. 配置httpd.conf禁止目录浏览    
将`Options Indexes FollowSymLinks` 改为 `Options -Indexes FollowSymLinks`   

7. 配置httpd.conf设置默认文档  
`DirectoryIndex index.html`  

8. 合理配置apache的运行账户  
为apache单独建立一个运行账户及账户组，并在httpd.conf配置    
```
User apache
Group apache
```
9. 合理控制apache运行账户对磁盘的写入，执行权限  
取消apache运行账户对网站目录的写入权限，上传目录除外，其他非网站目录尽量不给权限    

10. 合理控制apache运行账户对sh等的执行权限  
取消掉了运行账户对sh等的执行权限后能够防止webshell通过默认的sh执行命令    

11. 配置httpd.conf取消对上传目录的php执行权限    
```
<Directory "/var/www/html/aaa">     
    <FilesMatch ".(php|php5)$">     
        Deny from all     
    </FilesMatch> 
</Directory> 
```
12. 配置httpd.conf限制禁止访问的文件夹，例如后台目录  
```
<Directory "/var/www/html/aaa">     
        Deny from all     
</Directory> 
```
13. 配置httpd.conf限制一些特殊目录的特定ip访问，如内部接口等。  
```
<Directory "/var/www/html/aaa">     
    Order Deny,Allow
    Deny from all
    Allow from 192.168.1.111    
</Directory> 
```
14. 配置httpd.conf限制一些文件类型的访问，如txt的日志
```
<Files ~ ".txt$"> 
    Order allow,deny 
    Deny from all 
</Files>
``` 
15.配置httpd.conf修改修改监听端口来防止一些内部系统被扫描  
这样可以防止一些直接扫描80端口的黑客    
```
Listen 12345 
```
16. 关闭对.htaccess的支持
`AllowOverride All` 
改为
`AllowOverride None` 
17. 配置httpd.conf记录访问日志    

## 0x04 .htaccess常见配置方法参考

首先，不建议使用.htaccess,其次，使用.htaccess需要在httpd.conf中开启，最后，开始.htaccess支持后需要在httpd.conf中配置防止.htaccess文件被下载，下面介绍几个基本配置方法不全，更多的可以参考其他网站专门针对.htaccess 的配置方法。    

1. 定制目录的默认文档  
`DirectoryIndex index.html index.php index.htm `  
2. 定制错误页面  
`ErrorDocument 404 errors/404.html `  
3. 控制访问文件和目录的级别  
```
order deny,allow  
deny from all  
allow from 192.168.0.0/24 
```
4. 防止列目录  
`Options -Indexes`  
 
## 0x05 总结

其实一个web服务器的保护是分几个层次的（暂不考虑程序的漏洞）：  

1. 隐藏自己  
要保护一个web服务器首先得学会隐藏自己，对于一些内部系统，如后台，内部接口等，我们可以通过改端口，限制ip等方式来不让黑客发现。    

2. 隐藏身份  
对于多数web系统来说，都是提供给外面的访问的，所以想隐藏自己其实是很难的。但是我们还是要学会隐藏身份，可以通过改banner，该返回信息来隐藏身份来加大黑客攻击的难度。    

3. 选用安全的版本及修补一些已知的漏洞  
其实前面两步都是很容易突破，然后获知一个web系统所使用的web服务器版本的，此时我们能做的就是选择一个少漏洞的版本，及打上安全补丁。    

4. 做好安全配置  
做好基础的安全配置，禁止目录浏览，设定默认文档，上传目录限制php执行等等，来阻挡黑客的入侵。    

5. 合理配置web服务进程账户的权限  
当黑客已经通过程序漏洞上传了一个webshell并且已经成功执行了，此时，就只能很好的配置服务进程的账户权限，包括磁盘的读取写入，特殊程序如sh的执行，等等，这样可以讲危害降到最低。    

6. 记录日志  
最后，当黑客已经光顾之后，我们也只能通过日志来分析，看问题出在哪里了。     