# pydbg主要功能
* 进程查看和控制功能
	1. 启动进程
	2. 通过pid附加`attach`进程
	3. 分离`detach`进程
	4. 多进程管理
* 断点功能
	1. 实现三种类型断点：软件断点，硬件断点，内存断点
	2. 插入删除断点，断点触发后恢复
	3. 断点触发回调函数
* 寄存器，内存查看修改
	1. 寄存器查看修改
	2. 内存查看修改
* 代码注入和钩子功能
	1. 代码注入
	2. DLL注入
	3. 函数钩子

## 由其他模块实现的功能
* 通过应用名和其他条件获得pid
	`psutils`模块
	```python
	import psutils
	[(p.name(), p.pid) for p in psutil.process_iter()]
	```
* 反汇编代码
	`capstone`模块
	```python
	from capstone import *
	
	CODE = b"\x55\x48\x8b\x05\xb8\x13\x00\x00"
	md = Cs(CS_ARCH_X86, CS_MODE_64)
	for i in md.disasm(CODE, 0x1000):
	    print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
	```

# 实际应用
## 调试器debugger
## 注入器injector
