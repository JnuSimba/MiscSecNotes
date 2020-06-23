## 一、定义

SSRF(Server-Side Request Forgery:服务器端请求伪造) 是一种由攻击者构造形成由服务端发起请求的一个安全漏洞。一般情况下，SSRF攻击的目标是从外网无法访问的内部系统。（正是因为它是由服务端发起的，所以它能够请求到与它相连而与外网隔离的内部系统）

SSRF 形成的原因大都是由于服务端提供了从其他服务器应用获取数据的功能且没有对目标地址做过滤与限制。比如从指定URL地址获取网页文本内容，加载指定地址的图片，下载等等。注意：除了http/https等方式可以造成ssrf，类似tcp connect 方式也可以探测内网一些ip 的端口是否开发服务，只不过危害比较小而已。



## 二、SSRF 漏洞的寻找



### SSRF寻找方式----WEB功能上寻找

1. 分享：通过url 地址分享网页内容

http://share.v.t.qq.com/index.php?c=share&a=index&title=&url=http://www.baidu.com

通过目标URL地址获取了title标签和相关文本内容。而如果在此功能中没有对目标地址的范围做过滤与限制则就存在着SSRF漏洞。



2. 转码服务：通过URL地址把原地址的网页内容调优使其适合手机屏幕浏览

由于手机屏幕大小的关系，直接浏览网页内容的时候会造成许多不便，因此有些公司提供了转码功能，把网页内容通过相关手段转为适合手机屏幕浏览的样式。例如百度、腾讯、搜狗等公司都有提供在线转码服务。



3. 在线翻译：通过URL地址翻译对应文本的内容。例如有道词典、UC、QQ浏览器等。

http://b2.wap.soso.com/sweb/detail.jsp?icfa=1327068&sid=AaEj1UgdrgdWthTwdJnvPeTI&g_ut=2&url=http://admin.soso.com



4. 图片加载与下载：通过URL地址加载或下载图片

http://read.html5.qq.com/image?imageUrl=http://10.156.52.13/favicon.ico

http://img.store.sogou.com/net/a/08/link?appid=100520033&url=http://10.12.139.10/favicon.ico

图片加载远程图片地址此功能用到的地方很多，但大多都是比较隐秘，比如在有些公司中的加载自家图片服务器上的图片用于展示。（此处可能会有人有疑问，为什么加载图片服务器上的图片也会有问题，直接使用img标签不就好了？ 没错是这样，但是开发者为了有更好的用户体验通常对图片做些微小调整例如加水印、压缩等，所以就可能造成SSRF问题）。

​     

5. 图片、文章收藏功能

此处的图片、文章收藏中的文章收藏就类似于功能一、分享功能中获取URL地址中title以及文本的内容作为显示，目的还是为了更好的用户体验，而图片收藏就类似于功能四、图片加载。



6. 未公开的api实现以及其他扩展调用URL的功能

此处类似的功能有360提供的网站评分，以及有些网站通过api获取远程地址xml文件来加载内容。

http://visopen.vipshop.com/doc/sdk/php/aj_interface.php?api_name=e&api_url=http://内网WEB路径&callback=jQuery191011010590475052595_1432854159288&o=json&_=1432854159289



### SSRF寻找方式----URL关键字中寻找

关键字：share、wap、url、link、src、source、target、u、3g、display、sourceURl、imageURL、domain

利用google 语法加上这些关键字去寻找SSRF漏洞

http://share.renren.com/share/buttonshare.do?link=http://t.cn/RwbLKDx

http://qing.blog.sina.com.cn/blog/controllers/share.php?url=10.210.75.3

​     

## 三、SSRF 验证方式

1. 用抓包工具看请求由客户端发起还是服务端发起（漏洞），如果不是客户端发出的请求，则有可能是，接着找存在HTTP服务的内网地址

--从漏洞平台中的历史漏洞寻找泄漏的存在web应用内网地址

--通过二级域名暴力猜解工具模糊猜测内网地址

3. 直接返回的Banner、title、content等信息
  
3. 利用file协议 读取本地文件等
  
4. bool型SSRF
  
5. 关于盲打ssrf的用例，可以在盲打后台用例中将当前准备请求的uri 和参数编码成base64，这样盲打后台解码后就知道是哪台机器哪个cgi触发的请求。





## 四、SSRF 绕过方式

1）http://www.baidu.com@10.153.138.81 与 http://10.153.138.81 请求是相同的

2) 短网址 http://t.cn/RwbLKDx

3）ip地址转换成进制来访问

4）xxx.10.153.138.81.xip.io  10.153.138.81 (xxx 任意）

指向任意ip的域名：xip.io(37signals开发实现的定制DNS服务)

5）例如 http://10.153.138.81/ts.php , 修复时容易出现的获取host时以/分割来确定host，

但这样可以用 http://abc@10.153.138.81/ 绕过

6）限制了子网段，可以加 :80 端口绕过。http://tieba.baidu.com/f/commit/share/openShareApi?url=http://10.42.7.78:80

7）探测内网域名，或者将自己的域名解析到内网ip

8) [DNS rebinding](https://paper.seebug.org/390/) 绕过





## 五、如何修复

1. 过滤返回信息，验证远程服务器对请求的响应是比较容易的方法。如果web应用是去获取某一种类型的文件。那么在把返回结果展示给用户之前先验证返回的信息是否符合标准。
2. 统一错误信息，避免用户可以根据错误信息来判断远端服务器的端口状态。
3. 白名单内网ip。避免应用被用来获取获取内网数据，攻击内网。
4. 禁用不需要的协议。仅仅允许http和https请求。可以防止类似于file:///, gopher://, ftp:// 等引起的问题。
5. 限制请求的端口为http常用的端口，比如 80、443、8080、8090。
6. 对于DNS rebinding 绕过，需要在底层进行hook，即在每次发起socket 连接前进行判断目标ip地址的合法性，比如go 语言可以借助net.Dialer包 提供的能力来实现，参考[Preventing Server Side Request Forgery in Golang](https://www.agwa.name/blog/post/preventing_server_side_request_forgery_in_golang)

