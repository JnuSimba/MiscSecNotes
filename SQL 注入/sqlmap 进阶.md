原文 by MayIKissYou 

## 0x02 自定义payload脚本
### 2.1 需求
我们先写一个比较全的select语句：  
`select * from users where user_id in(1,2,3,[4]) and first_name like '%[t]%' and second_name=['b'] group by [first_name] order by [1] [desc] limit [1]`  
语句中[] 中的内容都是查询中可能存在的注入点。  
那么问题来了：  
1）：这些注入点里面哪些是sqlmap在默认level下就能够识别的？   
2）：不能够在默认级别下识别的注入点，sqlmap在level=多少的时候能否识别？   
3）：sqlmap识别不了的时候怎么办？  

以order by 类型的注入来看，order by [1] 这个参数在设置level=3的时候会被sqlmap 检测出来(这里需要注意的在01_boolean_blind.xml文件中，如果level字段设置的是2，在测试的时候需要设置比level高的才可以被识别，如rlike order by 注入设置的level 值为2，我在命令行使用sqlmap参数的时候需要设置level=3)  
但是order by 1 [desc]，在设置level=3 的时候也无法识别，也许你会说添加suffix 和prefix 就可以了，确实是这样，但是现在的选手一般都会选择开web代理，然后调用sqlmap接口去检查，因此这里对于sqlmap的要求就高了.  
第一：sqlmap要能够检测出url的参数存在注入点；  
第二：测试的效率要高[不能够将level设置的很高]；设置level高的情况下，会有更多的请求。  

现在看来自己将payload 编写为sqlmap可用的payload 即可。  
### 2.2 说明

Sqlmap在运行之后会加载读取xml 文件，并且将结果保存到conf.tests 中，如下图：  
![sqlmap1](../pictures/sqlmap1.png)  

这部分payload 会在会在checkSqlInjection 中使用：  
![sqlmap2](../pictures/sqlmap2.png)  

接下来只要知道如何使用这部分payload 以及xml 中各个字段是什么意思即可。  
首先详细看一下payload 中字段：  
title 字段：payload test 起的名字； 譬如我们给自己的payload 起的名字为：  
`MySQL boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause (desc-mayikissu)`
style 字段：sql 注入的类型  
类型1：盲注 我们order by类型属于盲注，因此我们添加stype的值为1.   
类型2：错误类型注入   
类型3：内联注入   
类型4：多语句查询注入   
类型5：时间注入   
类型6：联合查询注入  


level字段：sqlmap对于每一个payload都有一个level 级别，level 级别越高表示检查的payload 个数就越多。 譬如我们自定义个level 设计的为2，因此只有在使用在命令行使用level>2 的时候，才会使用我们的payload进行检测。  
risk 字段：风险等级，有多大几率获取破坏数据。值有1,2,3，分别表示低中高。默认的risk 为1，默认检测所有风险级别的payload。 该字段影响不大。  
clause 字段：payload在哪个语句里生效，差不多意思就是这个payload用在sql语句的哪个位置。可用的值：  
0: Always  
1: WHERE / HAVING  
2: GROUP BY  
3: ORDER BY  
4: LIMIT  
5: OFFSET  
6: TOP  
7: Table name  
8: Column name  

我们这里测试的是order by，此处clause的字段设置为3，经过测试这里的值可以混用的，关键看sql 语法。  
where字段： where字段我理解的意思是，以什么样的方式将我们的payload添加进去。  
1：表示将我们的payload直接添加在值的后面[此处指的应该是检测的参数的值] 如我们写的参数是id=1，设置<where>值为1的话，会出现1后面跟payload；  
2：表示将检测的参数的值更换为一个整数，然后将payload添加在这个整数的后面。 如我们写的参数是id=1，设置<where>值为2的话，会出现[数字]后面跟payload；  
3：表示将检测的参数的值直接更换成我们的payload。 如我们写的参数是id=1，设置<where>值为3的话，会出现值1直接被替换成了我们的payload。  
我们的场景是order by 1 [desc]，此处我们直接将desc 更换成我们的payload 即可。  
vector字段： vector 字段表示的是payload 向量，类似于一个模型的感觉。  
`,IF([INFERENCE],[ORIGVALUE],(select 1 from information_schema.tables))`  
此处为我设置的vector，INFERENCE 为条件，ORIGVALUE 为参数原始的值，如我传入的id=1 或者desc，1和desc 即为原始值，此处无所谓，在我的场景里只要为一个值即可。  
request 和response 理解为请求的时候payload 值，以及请求的值与什么样的值进行对比。  
请求的payload为：  
`,IF([RANDNUM]=[RANDNUM],[ORIGVALUE],(select 1 from information_schema.tables))`  
响应的对比payload为：  
`,IF([RANDNUM]=[RANDNUM1],[ORIGVALUE],(select 1 from information_schema.tables))`  
大致理解就是对比if 条件不等和相等，如此来进行盲注。  
了解这些参数之后，接下来我们需要知道sqlmap如何将这样自定义的payload 组合起来即可。于是我们跟踪一下checksqlinjection 这个函数，即可知道sqlmap是如何将payload组合起来的了。  
在函数中有一个重要的参数，boundary参数，这个参数是从xml目录下的boundaries.xml文件中读取出来的。每个boundary的格式如下图内容：  
![sqlmap3](../pictures/sqlmap3.png)  

其中level，clause以及where 表达的意思和payload 中相关标签表达的意思是一样的。 标签ptype 表示参数的类型，prefix 表示添加内容的前缀，suffix 表示添加内容的后缀。  
核心的部分是获取payloads.xml 中的每一个payload，然后获取payload 中的参数与boundary.xml 中获取的参数进行比较。大致流程如下：
获取payload.xml文件中的每一个payload。  
获取boundary.xml文件中的每一个boundary。  
比较判断payload中的clause是否包含在boundary的clause中，如果有就继续，如果没有就直接跳出。  
比较判断payload中的where是否包含在boundary的clause中，如果有就继续，如果没有就直接跳出。  
将prefix和suffix与payload中的request标签的内容拼接起来保存到boundpayload中。  
最后就是发送请求，然后将结果进行比较了。  

PS.因此我们在设计自定义脚本的时候需要注意的几个地方，payload 中的clause 标签，level 标签，where 标签，vector 标签以及reqeust 和response 标签。基本上理解并设计好这些标签，就能够自定义脚本了。  

## 2.3 实现
Sqlmap 的相关payload 在目录./sqmap/xml/payloads/ 目录下，新版目录下会有一个payloads 的目录，里面有各种类型的sql注入的payload，选取盲注的xml，在其中编写一个test节点，内容如下图：    
![sqlmap4](../pictures/sqlmap4.png)  
 
（相关参数的解释在后面描述）  
然后自己创建一个存在order by 1 [desc]这种类型sql 注入的php 页面：  
![sqlmap5](../pictures/sqlmap5.png)  

这时候用我们修改过的sqlmap去发送，查看结果：  
![sqlmap6](../pictures/sqlmap6.png)  

## 0x03 自定义bypass脚本
### 3.1 需求
在./sqlmap/tamper目录下，设计了很多的脚本，这些脚本是用来对于请求的payload 进行修改的，但是往往有一些情况这些预定义的脚本不能够满足我们的需求，例如有一些waf 对于逗号进行了过滤，  
又如有时候我们需要使用%a0 去替换payload 中的空格等等情况。这时候就需要我们自己添加脚本来完成工作了。  
### 3.2 说明
要知道如何添加自定义脚本，我们需要了解的是  
第一：tamper脚本是什么时候被sqlmap载入的；   
第二：tamper脚本是什么时候被sqlmap调用的；   
第三：tamper脚本的里的内容有什么样的规范；  

问题一：tamper脚本是什么时候被sqlmap载入的  
我们去看一下sqlmap 的源码，大致逻辑是这样  
main()->init()->_setTamperingFunctions()  

在_setTamperingFunctions函数中加载了我们配置的tamper函数。然后会把tamper 函数添加到了kb.tamperFunctions里面以被后续使用。
这样看来要自定义的话这个脚本中得有个tamper 函数，然后就是编写tamper 函数的内容  
![sqlmap7](../pictures/sqlmap7.png)  

问题二：tamper脚本是什么时候被sqlmap调用的  
tamper 脚本在queryPage 函数中被调用，queryPage 函数是用来请求页面内容，在每次发送请求之前，先会将payload 进行tamper 函数处理。  下图为调用between.py 的脚本。  
![sqlmap8](../pictures/sqlmap8.png)

问题三：tamper脚本的里的内容有什么样的规范  
我们随机选择一个脚本，该脚本为base64encode.py，查看脚本中的tamper 内容：  
![sqlmap9](../pictures/sqlmap9.png)  

可以看到内容非常简单，将payload 的内容内容做了base64 编码然后直接返回。Tamper 有两个参数，第一个参数payload 即为传入的实际要操作的payload，第二个参数**kwargs为相关httpheader，譬如你想插入或则修改header 的时候可以用到。  
逻辑流程弄清楚之后，就很容易编写自己的tamper 脚本了。  

### 3.3 实现
以使用%a0 替换空格的脚本为例，在tamper 目录下创建space2ao.py 脚本，稍微修改下脚本：  
![sqlmap10](../pictures/sqlmap10.png)  

使用sqlmap 发送请求，去查看下web 日志：  

![sqlmap10](../pictures/sqlmap10_1.png)  


PS.感觉很容易的样子，这里不演示如何bypass 逗号的情况，下面换一个方式来使sqlmap bypass 逗号被过滤的情况。  

## 0x04 自定义query函数
在做测试的时候往往还会有一些情况，如mid 函数被过滤了，逗号被过滤了等等。Sqlmap是机器操作，如果被过滤了一些函数，脚本肯定就无法走后面的流程了。  
此时我们可以直接修改相关的querystring（xml中的相关内容），如我们可以将substr(expression,start,length)替换成substr(expression from start for length)。  
这些内容在sqlmap/xml目录下的queries.xml目录中。截图下mysql标签中的一些内容：  
![sqlmap11](../pictures/sqlmap11.png)  

这个inference 看起来就是用来猜字段用的，而且之前我们在第一篇自定义过这个[inference字段的]，是不是我们将  
ord(mid((%s),%d,1))>%d  

更换为  
ord(mid((%s) from %d for 1))>%d  

就可以了呢。  
我们修改之后，跟踪下payload的值是否更改了：  
![sqlmap12](../pictures/sqlmap12.png)  

查看下是否能够爆出密码：  
![sqlmap13](../pictures/sqlmap13.png)  

查看下web 日志，是否是发送的那样，解码之后结果可以看到mid 的逗号已经被修改。  
![sqlmap14](../pictures/sqlmap14.png)  

这样我们就可以让mid 函数没有逗号了。其他的可以参考去修改queries 中的相关内容就可以了。  

## 0x05 防御sqlmap
经过一番折腾，sqlmap 可以比想象中更厉害了呢，目前为止很多选手都会用着sqlmap 的插件，或者是原版的sqlmap，亦或是修改过的sqlmap。
那如何防御sqlmap呢：  
1）：大众的防御方法，sqlmap在发送请求的时候，http的user-agent 都会自带sqlmap 字样的，可以做协议解析之后，获取user-agent，然后来判断。  
不过很多测试选手都会使用sqlmap 的参数对其进行修改。  
2）：之前调试程序的时候看到过如下内容： 
`http://127.0.0.1?id=1..]"')[.]" `  

于是就跑去看了看sqlmap 的源码：  
发现在checks.py 的文件里面有一个函数名称为heuristicCheckSqlInjection()  里面有段代码：  
```
while '\'' not in randStr:
        randStr = randomStr(length=10, alphabet=HEURISTIC_CHECK_ALPHABET)
```
然后我们去查看randomStr，此函数在common.py 下，相关代码如下：  
``` python
def randomStr(length=4, lowercase=False, alphabet=None):
    """
    Returns random string value with provided number of characters
 
    >>> random.seed(0)
    >>> randomStr(6)
    'RNvnAv'
    """
 
    if alphabet:
        retVal = "".join(random.choice(alphabet) for _ in xrange(0, length))
    elif lowercase:
        retVal = "".join(random.choice(string.ascii_lowercase) for _ in xrange(0, length))
    else:
        retVal = "".join(random.choice(string.ascii_letters) for _ in xrange(0, length))
 
    return retVal
```
然后去查看了HEURISTIC_CHECK_ALPHABET，值为`('"', "'", ')', '(', '[', ']', ',', '.')`  
因此得到这样的结论，这串randStr 的值为一个十个随机字符的长度字符串，其中至少包含`'` ，随机字符串的内容在`('"', "'", ')', '(', '[', ']', ',', '.')` 里。这样的规律是可以使用正则表达式写出规则的，而且重复的概率应该不高，可以起到一定的防御效果。  

