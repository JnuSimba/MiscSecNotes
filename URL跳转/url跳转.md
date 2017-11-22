原文 by wooyun wiki

## 1、相关背景介绍
  
由于应用越来越多的需要和其他的第三方应用交互，以及在自身应用内部根据不同的逻辑将用户引向到不同的页面，譬如一个典型的登录接口就经常需要在认证成功之后将用户引导到登录之前的页面，整个过程中如果实现不好就可能导致一些安全问题，特定条件下可能引起严重的安全漏洞。
  
## 2、成因
  
对于URL跳转的实现一般会有几种实现方式：
  

  
* META标签内跳转（`<meta http-equiv="refresh" content="0;URL='http://thetudors.example.com/'" /> `）
  
* javascript跳转（`<script>self.location=target</script>`）
  
* header头跳转（`Location:url`）
  

  

  
通过以GET或者POST的方式接收将要跳转的URL，然后通过上面的几种方式的其中一种来跳转到目标URL。一方面，由于用户的输入会进入Meta，javascript，http头所以都可能发生相应上下文的漏洞，如xss等等，但是同时，即使只是对于URL跳转本身功能方面就存在一个缺陷，因为会将用户浏览器从可信的站点导向到不可信的站点，同时如果跳转的时候带有敏感数据一样可能将敏感数据泄漏给不可信的第三方。
  
譬如一个典型的登录跳转如下：
  
```
  
<?php
  
      $url=$_GET['jumpto'];
  
      header("Location: $url");
  
?>
  
```
  
如果jumpto没有任何限制，所以恶意用户可以提交 `http://wiki.wooyun.org/login.php?jumpto=http://www.evil.com`
  
来生成自己的恶意链接，安全意识较低的用户很可能会以为该链接展现的内容是wiki.wooyun.org从而可能产生欺诈行为，同时由于QQ，淘宝旺旺等在线IM都是基于URL的过滤，同时对一些站点会以白名单的方式放过，所以导致恶意URL在IM里可以传播，从而产生危害，譬如这里IM会认为wiki.wooyun.org都是可信的，但是通过在IM里点击上述链接将导致用户最终访问evil.com。
  

  
对于自动化扫描来看，如果是header 方式跳转可以读取Location 字段得知是否存在漏洞；如果是 js 类跳转，用 http://diaoyu.test.com  append/replace 在get, post 参数，经过 dom 解析后检测 iframe-src, script-src, location.href, location.replace 等位置是否出现。
  

  
## 3、测试点
  
 
  
get/post 参数 url/jump/from/back/site 等关键字。
  
有时跳转的参数没有验证，或者只验证了一些关键字，可以绕过，甚至由其他参数来控制是否马上跳转还是让用户选择下一步，如 delay 等字眼。
  
或者一些js 判断逻辑没有写好，也会有一些绕过姿势。

  
## 4、登录验证、登录跳转
  

  
一般网站登录前的验证可能是这样实现的：
  
`<form action="processs.php", id="login" method="post" onsubmit="return validate();">`
  
在用户填完信息后会先调用validate() 函数进行验证，如果返回true 才会真正提交表单。
  
在validate() 里类似 `if(document.forms.login.agreement.value != checked) { return false;}  `
  
在不想重载页面，也就是不提交，可以 `onsubmit="quote(); return false;"` 在quote()里面可以 `xhr= new XMLHttpRequest();` 
  
即ajax的方式来做一些操作。
  
现在很多提交的实现不再使用 form 表单，比如只要监听某 button 标签事件，点击触发时执行事件，里面用 ajax 方式提交请求。
  
``` javascript
  
$(".submit").on('click', function ()
  
{
  
    var msg = "";
  

  
    if ($(".user_name").val().trim() && $(".mail").val().trim() && $(".phone").val().trim())
  
    {
  
        submitUserInfo();
  
    }
  
    else
  
    {
  
    }
  
});
  
```
  

  
一般的网站登录跳转实现方式之一是：在login.php 对表单post 过来的user&pwd&email 验证，如果对则设置一个键值如 `$_SESSION["auth"]=true`，设置response 的Location Header : home.php，本程序exit。浏览器接收到rsp，看到Location 头部，于是跳转请求至home.php。home.php 可以对`$_SESSION["auth"]` 继续判断一次，若true 则显示登录后的页面。当然这一切的前提是login.php开启了session_start()，这样第二次访问home.php 也会带上`Cookie:PHPSESSID=xxx`，这样server 通过 $_COOKIE 获取sessionId就知道是同个用户的请求，通过sessionId就可以知道 $_SESSION 结构体中原本存放的数据，比如 `auth=True` 之类。
  
superglobals : $_COOKIE  $_ENV  $_FILES  $_GET  $_POST $_REQUEST $_SERVER $_SESSION 
