作者：c0d3p1ut0s & s1m0n  https://paper.seebug.org/449/  

## RASP概念

RASP（Runtime Application self-protection）是一种在运行时检测攻击并且进行自我保护的一种技术。早在2012年，Gartner就开始关注RASP，惠普、WhiteHat Security等多家国外安全公司陆续推出RASP产品，时至今日，惠普企业的软件部门出售给了Micro Focus，RASP产品Application Defender随之易主。而在国内，去年知道创宇KCon大会兵器谱展示了JavaRASP，前一段时间，百度开源了OpenRASP，去年年底，360的0kee团队开始测试Skywolf，虽然没有看到源码和文档，但它的设计思路或许跟RASP类似。而商业化的RASP产品有OneAPM的OneRASP和青藤云的自适应安全产品。在国内，这两家做商业化RASP产品做得比较早。  

那么RASP到底是什么呢？它到底是怎样工作的呢？  

## 我的WAF世界观

为了表述方便，暂且把RASP归为WAF的一类。从WAF所在的拓扑结构，可以简单将WAF分为如下三类，如下图所示：  
![](../pictures/phprasp1.png)  


* 以阿里云为代表的云WAF以中间人的形式，在HTTP请求到达目标服务器之前进行检查拦截。
* 以ModSecurity为代表的传统WAF在HTTP请求到达HTTP服务器后，被Web后端容器解释/执行之前检查拦截HTTP请求。
* RASP工作在Web后端解释器/编译器中，在漏洞代码执行前阻断执行流。

从上图中WAF所处的位置可以看出，云WAF和传统WAF的检查拦截HTTP请求的主要依据是HTTP Request，其实，如果站在一个非安全从业者的角度来看，这种检测方式是奇怪的。我们可以把Web服务看做是一个接受输入-处理-输出结果的程序，那么它的输入是HTTP请求，它的输出是HTTP响应。靠检测一个程序的输入和输出来判断这个程序的运行过程是否有害，这不奇怪吗？然而它又是可行且有效的，大多数的Web攻击都能从HTTP请求中找到蛛丝马迹。这种检测思路是云WAF和传统WAF能有效工作的原因，也是它们的缺点。  

笔者一直认为，问题发生的地方是监控问题、解决问题的最好位置。Web攻击发生在Web后端代码执行时，最好的防护方法就是在Web后端代码执行之前推测可能发生的问题，然后阻断代码的执行。这里的推测并没有这么难，就好像云WAF在检查包含攻击payload的HTTP请求时推测它会危害Web服务一样。这就是RASP的设计思路。  

好了，上面谈了一下笔者个人的一些看法，下面开始谈一谈PHP RASP的实现。  

RASP在后端代码运行时做安全监测，但又不侵入后端代码，就得切入Web后端解释器。以Java为例，Java支持以JavaAgent的方式，在class文件加载时修改字节码，在关键位置插入安全检查代码，实现RASP功能。同样，PHP也支持对PHP内核做类似的操作，PHP支持PHP扩展，实现这方面的需求。你可能对JavaAgent和PHP扩展比较陌生，实际上，在开发过程中，JavaAgent和PHP扩展与你接触的次数比你意识到的多得多。  

## PHP扩展简介

有必要介绍一下PHP解释的简单工作流程，根据PHP解释器所处的环境不同，PHP有不同的工作模式，例如常驻CGI，命令行、Web Server模块、通用网关接口等多个模式。在不同的模式下，PHP解释器以不同的方式运行，包括单线程、多线程、多进程等。  

为了满足不同的工作模式，PHP开发者设计了Server API即SAPI来抹平这些差异，方便PHP内部与外部进行通信。  

虽然PHP运行模式各不相同，但是，PHP的任何扩展模块，都会依次执行模块初始化（MINIT）、请求初始化（RINIT）、请求结束（RSHUTDOWN）、模块结束（MSHUTDOWN）四个过程。如下图所示：  
![](../pictures/phprasp2.png)    


在PHP实例启动时，PHP解释器会依次加载每个PHP扩展模块，调用每个扩展模块的MINIT函数，初始化该模块。当HTTP请求来临时，PHP解释器会调用每个扩展模块的RINIT函数，请求处理完毕时，PHP会启动回收程序，倒序调用各个模块的RSHUTDOWN方法，一个HTTP请求处理就此完成。由于PHP解释器运行的方式不同，RINIT-RSHUTDOWN这个过程重复的次数也不同。当PHP解释器运行结束时，PHP调用每个MSHUTDOWN函数，结束生命周期。
  
PHP核心由两部分组成，一部分是PHP core，主要负责请求管理，文件和网络操作，另一部分是Zend引擎，Zend引擎负责编译和执行，以及内存资源的分配。Zend引擎将PHP源代码进行词法分析和语法分析之后，生成抽象语法树，然后编译成Zend字节码，即Zend opcode。即`PHP源码->AST->opcode` 。opcode就是Zend虚拟机中的指令。使用VLD扩展可以看到Zend opcode，这个扩展读者应该比较熟悉了。下面代码的opcode如图所示  
``` php
<?php
$a=1;
$b=2;
print $a+$b;
>
```
![](../pictures/phprasp3.png)    

Zend引擎的所有opcode在http://php.net/manual/en/internals2.opcodes.list.php 中可以查到，在PHP的内部实现中，每一个opcode都由一个函数具体实现，opcode数据结构如下  
``` c
struct _zend_op {
    opcode_handler_t handler;//执行opcode时调用的处理函数
    znode result;
    znode op1;
    znode op2;
    ulong extended_value;
    uint lineno;
    zend_uchar opcode; 
};
```
如结构体所示，具体实现函数的指针保存在类型为opcode_handler_t的handler中。  

## 设计思路

PHP RASP的设计思路很直接，安全圈有一句名言叫一切输入都是有害的，我们就跟踪这些有害变量，看它们是否对系统造成了危害。我们跟踪了HTTP请求中的所有参数、HTTP Header等一切client端可控的变量，随着这些变量被使用、被复制，信息随之流动，我们也跟踪了这些信息的流动。我们还选取了一些敏感函数，这些函数都是引发漏洞的函数，例如require函数能引发文件包含漏洞，mysqli->query方法能引发SQL注入漏洞。简单来说，这些函数都是大家在代码审计时关注的函数。我们利用某些方法为这些函数添加安全检查代码。当跟踪的信息流流入敏感函数时，触发安全检查代码，如果通过安全检查，开始执行敏感函数，如果没通过安全检查，阻断执行，通过SAPI向HTTP Server发送403 Forbidden信息。当然，这一切都在PHP代码运行过程中完成。  

这里主要有两个技术问题，一个是如何跟踪信息流，另一个是如何安全检查到底是怎样实现的。  

我们使用了两个技术思路来解决两个问题，第一个是动态污点跟踪，另一个是基于词法分析的漏洞检测。  

## 动态污点跟踪

对PHP内核有一些了解的人应该都知道鸟哥，鸟哥有一个项目taint，做的就是动态污点跟踪。动态污点跟踪技术在白盒的调试和分析中应用比较广泛。它的主要思路就是先认定一些数据源是可能有害的，被污染的，在这里，我们认为所有的HTTP输入都是被污染的，所有的HTTP输入都是污染源。随着这些被污染变量的复制、拼接等一系列操作，其他变量也会被污染，污染会扩大，这就是污染的传播。这些经过污染的变量作为参数传入敏感函数以后，可能导致安全问题，这些敏感函数就是沉降点。  

做动态污点跟踪主要是定好污染源、污染传播策略和沉降点。在PHP RASP中，污染源和沉降点显而易见，而污染传播策略的制定影响对RASP的准确性有很大的影响。传播策略过于严格会导致漏报，传播策略过于宽松会增加系统开销。PHP RASP的污染传播策略是变量的复制、赋值和大部分的字符串处理等操作传播污染。  

动态污点跟踪的一个小小好处是如果一些敏感函数的参数没有被污染，那么我们就无需对它进行安全检查。当然，这只是它的副产物，它的大作用在漏洞检测方面。  

动态污点跟踪的实现比较复杂，有兴趣的可以去看看鸟哥的taint，鸟哥的taint也是以PHP扩展的方式做动态污点跟踪。PHP RASP中，这部分是基于鸟哥的taint修改、线程安全优化、适配不同PHP版本实现的。在发行过程中，我们也将遵守taint的License。  

在PHP解释器中，全局变量都保存在一个HashTable类型的符号表symbol_table中，包括预定义变量$GLOBALS、$_GET、$_POST等。我们利用变量结构体中的flag中未被使用的一位来标识这个变量是否被污染。在RINIT过程中，我们通过这个方法首先将$_GET,$_POST,$_SERVER等数组中的值标记为污染，这样，我们就完成了污染源的标记。  

污染的传播过程其实就是hook对应的函数，在PHP中，可以从两个层面hook函数，一是通过修改zend_internal_function的handler来hook PHP中的内部函数，handler指向的函数用C或者C++编写，可以直接执行。zend_internal_function的结构体如下：  
``` c
//zend_complie.h
typedef struct _zend_internal_function {
    /* Common elements */
    zend_uchar type;
    zend_uchar arg_flags[3]; /* bitset of arg_info.pass_by_reference */
    uint32_t fn_flags;
    zend_string* function_name;
    zend_class_entry *scope;
    zend_function *prototype;
    uint32_t num_args;
    uint32_t required_num_args;
    zend_internal_arg_info *arg_info;
    /* END of common elements */

    void (*handler)(INTERNAL_FUNCTION_PARAMETERS); //函数指针，展开：void (*handler)(zend_execute_data *execute_data, zval *return_value)
    struct _zend_module_entry *module;
    void *reserved[ZEND_MAX_RESERVED_RESOURCES];
} zend_internal_function;
```
我们可以通过修改zend_internal_function结构体中handler的指向，待完成我们需要的操作后再调用原来的处理函数即可完成hook。 另一种是hook opcode，需要使用zend提供的API zend_set_user_opcode_handler来修改opcode的handler来实现。  

我们在MINIT函数中用这两种方法来hook传播污染的函数，如下图所示  
![](../pictures/phprasp4.png)   

![](../pictures/phprasp5.png)    


当传播污染的函数被调用时，如果这个函数的参数是被污染的，那么把它的返回值也标记成污染。以hook内部函数str_replace函数为例，hook后的`rasp_str_replace`  如下所示  
``` c
PHP_FUNCTION(rasp_str_replace)
{
    zval *str, *from, *len, *repl;
    int tainted = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zzz|z", &str, &repl, &from, &len) == FAILURE) {
        return;
    }//取参

    if (IS_STRING == Z_TYPE_P(repl) && PHP_RASP_POSSIBLE(repl)) {
        tainted = 1;
    } else if (IS_STRING == Z_TYPE_P(from) && PHP_RASP_POSSIBLE(from)) {
        tainted = 1;
    }//判断

    RASP_O_FUNC(str_replace)(INTERNAL_FUNCTION_PARAM_PASSTHRU);//调用原函数执行

    if (tainted && IS_STRING == Z_TYPE_P(return_value) && Z_STRLEN_P(return_value)) {
        TAINT_MARK(Z_STR_P(return_value));
    }//污染标记
}
```
首先获取参数，判断参数from和repl是否被污染，如果被污染，将返回值标记为污染，这样就完成污染传播过程。  

当被污染的变量作为参数被传入关键函数时，触发关键函数的安全检查代码，这里的实现其实跟上面的类似。PHP的中函数调用都是由三个Zend opcode：ZEND_DO_FCALL,ZEND_DO_ICALL 和 ZEND_DO_FCALL_BY_NAME中某一个opcode来进行的。每个函数的调用都会运行这三个 opcode 中的一个。通过劫持三个 opcode来hook函数调用,就能获取调用的函数和参数。这里我们只需要hook opcode，就是上面第二幅图示意的部分，为了让读者更加清晰，我把它复制下来。  
![](../pictures/phprasp6.png)   


如图，在MINIT方法中，我们利用 Zend API `zend_set_user_opcode_handler` 来hook这三个opcode，监控敏感函数。在PHP内核中，当一个函数通过上述opcode调用时，Zend引擎会在函数表中查找函数，然后返回一个zend_function类型的指针，zend_function的结构如下所示  
``` c
union _zend_function {
    zend_uchar type;    /* MUST be the first element of this struct! */

    struct {
        zend_uchar type;  /* never used */
        zend_uchar arg_flags[3]; /* bitset of arg_info.pass_by_reference */
        uint32_t fn_flags;
        zend_string *function_name;
        zend_class_entry *scope;
        union _zend_function *prototype;
        uint32_t num_args;
        uint32_t required_num_args;
        zend_arg_info *arg_info;
    } common;

    zend_op_array op_array;
    zend_internal_function internal_function;
};
```
其中，common.function_name 指向这个函数的函数名，common.scope指向这个方法所在的类，如果一个函数不属于某个类，例如PHP中的fopen函数，那么这个scope的值是null。这样，我们就获取了当前函数的函数名和类名。  

以上的行文逻辑是以RASP的角度来看的，先hook opcode和内部函数，来实现动态污点跟踪，然后通过hook函数调用时运行的三个opcode来对监控函数调用。实际上，在PHP内核中，一个函数的调用过程跟以上的行文逻辑是相反的。  

当一个函数被调用时，如上文所述，根据这个函数调用的方式不同，例如直接调用或者通过函数名调用，由Zend opcode，  ZEND_DO_FCALL,ZEND_DO_ICALL 和 ZEND_DO_FCALL_BY_NAME中的某一个opcode来进行。Zend引擎会在函数表中搜索该函数，返回一个zend_function指针，然后判断zend_function结构体中的type，如果它是内部函数，则通过zend_internal_function.handler来执行这个函数，如果handler已被上述hook方法替换，则调用被修改的handler；如果它不是内部函数，那么这个函数就是用户定义的函数，就调用zend_execute来执行这个函数包含的zend_op_array。  

现在我们从RASP的角度和PHP内核中函数执行的角度来看了动态污点跟踪和函数的hook，接下来，我们需要对不同类型的关键函数进行安全检测。  

## 基于词法分析的攻击检测

传统WAF和云WAF在针对HTTP Request检测时有哪些方法呢？常见的有正则匹配、规则打分、机器学习等，那么，处于PHP解释器内部的PHP RASP如何检测攻击呢？  

首先，我们可以看PHP RASP可以获取哪些数据作为攻击检测的依据。与其他WAF一样，PHP RASP可以获取HTTP请求的Request。不同的是，它还能获取当前执行函数的函数名和参数，以及哪些参数是被污染的。当然，像传统WAF一样，利用正则表达式来作为规则来匹配被污染的函数参数也是PHP RASP检测的一种方法。不过，对于大多数的漏洞，我们采用的是利用词法分析来检测漏洞。准确的来说，对于大多数代码注入漏洞，我们使用词法分析来检测漏洞。  

代码注入漏洞，是指攻击者可以通过HTTP请求将payload注入某种代码中，导致payload被当做代码执行的漏洞。例如SQL注入漏洞，攻击者将SQL注入payload插入SQL语句中，并且被SQL引擎解析成SQL代码，影响原SQL语句的逻辑，形成注入。同样，文件包含漏洞、命令执行漏洞、代码执行漏洞的原理也类似，也可以看做代码注入漏洞。  

对于代码注入漏洞，攻击者如果需要成功利用，必须通过注入代码来实现，这些代码一旦被注入，必然修改了代码的语法树的结构。而追根到底，语法树改变的原因是词法分析结果的改变，因此，只需要对代码部分做词法分析，判断HTTP请求中的输入是否在词法分析的结果中占据了多个token，就可以判断是否形成了代码注入。  

在PHP RASP中，我们通过编写有限状态机来完成词法分析。有限状态机分为确定有限状态机DFA和非确定有限状态机NFA，大多数的词法分析器，例如lex生成的词法分析器，都使用DFA，，因为它简单、快速、易实现。同样，在PHP RASP中，我们也使用DFA来做词法分析。  

词法分析的核心是有限状态机，而有限状态机的构建过程比较繁琐，在此不赘述，与编译器中的词法分析不同的是，PHP RASP中词法分析的规则并不一定与这门语言的词法定义一致，因为词法分析器的输出并不需要作为语法分析器的输入来构造语法树，甚至有的时候不必区分该语言的保留字与变量名。  

在经过词法分析之后，我们可以得到一串token，每个token都反映了对应的代码片段的性质，以SQL语句  

`select username from users where id='1'or'1'='1'`  
为例,它对应的token串如下  
```
select <reserve word>
username <identifier>
from <reserve word>
users    <identifier>
where <reserve word>
id  <identifier>
=   <sign>
'1' <string>
or  <reserve word>
'1' <string>
=   <sign>
'1' <string>
```
而如果这个SQL语句是被污染的（只有SQL语句被污染才会进入安全监测这一步），而且HTTP请求中某个参数的值是1'or'1'='1，对比上述token串可以发现，HTTP请求中参数横跨了多个token，这很可能是SQL注入攻击。那么，PHP RASP会将这条HTTP请求判定成攻击，直接阻止执行SQL语句的函数继续运行。如果上述两个条件任一不成立，则通过安全检查，执行SQL语句的函数继续运行。这样就完成了一次HTTP请求的安全检查。其他代码注入类似，当然，不同的代码注入使用的DFA是不一样的，命令注入的DFA是基于shell语法构建的，文件包含的DFA是基于文件路径的词法构建的。  

在开发过程中有几个问题需要注意，一个是\0的问题，在C语言中，\0代表一个字符串的结束，因此，在做词法分析或者其他字符串操作过程中，需要重新封装字符串，重写一些字符串的处理函数，否则攻击者可能通过\0截断字符串，绕过RASP的安全检查。  

另一个问题是有限状态自动机的DoS问题。在一些非确定有限状态机中，如果这个自动机不接受某个输入，那么需要否定所有的可能性，而这个过程的复杂度可能是2^n。比较常见的例子是正则表达式DoS。在这里不做深入展开，有兴趣的朋友可以多了解一下。  

## 讨论

在做完这个RASP之后，我们回头来看看，一些问题值得我们思考和讨论。  

RASP有哪些优点呢？作为纵深防御中的一层，它加深了纵深防御的维度，在Web请求发生时，从HTTP Server、Web解释器/编译器到数据库，甚至是操作系统，每一层都有自己的职责，每一层也都是防护攻击的阵地，每一层也都有对应的安全产品，每一层的防护侧重点也都不同。  

RASP还有一些比较明显的优点，一是对规则依赖很低，如果使用词法分析做安全检测的话基本不需要维护规则。二是减少了HTTP Server这层攻击面，绕过比较困难，绝大多数基于HTTP Server特性的绕过对RASP无效。例如HPP、HPF、畸形HTTP请求、各种编码、拆分关键字降低评分等。三是误报率比较低。从比较理想的角度来说，如果我的后端代码写得非常安全，WAF看到一个包含攻击payload的请求就拦截，这也属于误报吧。  

RASP的缺点也很明显，一是部署问题，需要在每个服务器上部署。二是无法像云WAF这样，可以通过机器学习进化检验规则。三是对服务器性能有影响，但是影响不大。根据我们对PHP RASP做的性能测试结果来看，一般来说，处理一个HTTP请求所消耗的性能中，PHP RASP消耗的占3%左右。  

其实，跳出RASP，动态污点跟踪和hook这套技术方案在能做的事情很多，比如性能监控、自动化Fuzz、入侵检测系统、Webshell识别等等。如果各位有什么想法，欢迎和我们交流。  

## 参考文献

鸟哥taint https://github.com/laruence/taint  
Thinking In PHP Internals  
http://php.net  
PHP Complier Internals  
自动机理论、语言和计算导论  

## 关于作者

两位作者水平有限，如文章有错误疏漏，或者有任何想讨论交流的，请随时联系  

c0d3p1ut0s c0d3p1ut0s@gmail.com  
s1m0n simonfoxcat@gmail.com  

## License

在PHP RASP中，我们使用了一部分taint和PHP内核的代码。两者的License都是PHP License。因此，在软件发行过程中，我们将遵守PHP License的相关限制。  

