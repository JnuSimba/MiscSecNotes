原文 by PHITH0N 

## php5.2以前

1、__autoload加载类文件，但只能调用一次这个函数，所以可以用spl_autoload_register加载类  

## php5.3

1、新增了glob://和phar://流包装  
glob用来列目录，绕过open_basedir  
http://php.net/manual/zh/wrappers.phar.php  

phar在文件包含中可以用来绕过一些后缀的限制  
http://php.net/manual/zh/wrappers.phar.php  

2、新的全局变量__DIR__  
3、默认开启<?= $xxoo;?>，5.4也可用  

## php5.4

1、移除安全模式、魔术引号  
2、register_globals 和 register_long_arrays php.ini 指令被移除。  
3、php.ini新增session.upload_progress.enabled，默认为1，可用来文件包含  
http://php.net/manual/zh/session.configuration.php  
http://php.net/manual/zh/session.upload-progress.php  
4、如果编译的时候没有加--disable-short-tags，则PHP默认开启短标签。在PHP5.4以后，即使php.ini中设置了short_open_tag=false，短标签 <?=..?> 也不受影响，永远可用。   ​​​​

## php5.5

1、废除preg_replace的/e模式(不是移除)  
当使用被弃用的 e 修饰符时, 这个函数会转义一些字符(即：'、"、 \ 和 NULL) 然后进行后向引用替换。  
http://php.net/manual/zh/function.preg-replace.php  

## php5.6

1、使用 ... 运算符定义变长参数函数  
http://php.net/manual/zh/functions.arguments.php#functions.variable-arg-list  

## php7.0

1、十六进制字符串不再是认为是数字  
2、移除asp和script php标签  

<% %>  
<%= %>  
<script language="php"></script>  

## php7.1

http://php.net/manual/zh/migration71.new-features.php  
1、废除mb_ereg_replace()和mb_eregi_replace()的Eval选项  