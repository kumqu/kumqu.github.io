---
layout: post
title: "API钩取--DLL注入实现IAT钩取"
author: "kumqu"
---

## IAT 钩取工作原理

​	IAT钩取是通过修改IAT中保存的API地址来钩取某个API, 即需要将要钩取的API在用户注入的DLL中重定义, 然后再注入目标进程. 这种方法的缺点是, 如果想要钩取的API不在目标进程的IAT中, 那么就无法使用该技术进行钩取操作. 换言之, 如果要钩取的API是由程序代码动态加载DLL文件而得以使用的, 那么将无法使用这项技术钩取它.

​	例如, 先向目标进程 (`calc.exe`) 注入用户DLL (`hookiat.dll`), 然后在 `calc.exe`进程的IAT区域`SetWindowTextW`对应的地址更改为`hookiat.dll`中用户自定义的`Hook`函数地址. 这样当 `calc.exe`调用`SetWindowTextW`时, 就会跳转至`hookiat.dll`中的`Hook`函数, `Hook`函数执行到最后时调用`SetWindowTextW`API, 即可完成在该API功能正常的情况下监控API的参数和返回结果.

## 修改 IAT 实现计算器 SetWindowsTextW() API 钩取

> 实验环境为 Windows 7 (32位) 系统环境.

### 源代码分析

​	这个实验的目标是实现在计算器的显示框中用中文数字替代原来的阿拉伯数字显示.

​	实现这个目标的主要程序是 `hookiat.dll`, 其各部分源代码如下:

1. `DLLMain()`:

```c
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	switch( fdwReason )
	{
		case DLL_PROCESS_ATTACH : 
            // 保存原始API地址
           	g_pOrgFunc = GetProcAddress(GetModuleHandle(L"user32.dll"), 
                                        "SetWindowTextW");
            // # hook
            //   用 hookiat!MySetWindowText() 钩取 user32!SetWindowTextW() 
			hook_iat("user32.dll", g_pOrgFunc, (PROC)MySetWindowTextW);
			break;

		case DLL_PROCESS_DETACH :
            // # unhook
            //   将calc.exe的 IAT 恢复原值
            hook_iat("user32.dll", (PROC)MySetWindowTextW, g_pOrgFunc);
			break;
	}
	return TRUE;
}
```

2. `MySetWindowsTextW()`:

```c
BOOL WINAPI MySetWindowTextW(HWND hWnd, LPWSTR lpString)
{
    wchar_t* pNum = L"零一二三四五六七八九";
    wchar_t temp[2] = {0,};
    int i = 0, nLen = 0, nIndex = 0;

    nLen = wcslen(lpString);
    for(i = 0; i < nLen; i++)
    {
        // 将阿拉伯数字转换为中文数字
        if( L'0' <= lpString[i] && lpString[i] <= L'9' )
        {
            temp[0] = lpString[i];
            nIndex = _wtoi(temp);
            lpString[i] = pNum[nIndex];
        }
    }

    // 调用 user32!SetWindowTextW() API
    // (修改 lpString 缓冲区中的内容)
    return ((PFSETWINDOWTEXTW)g_pOrgFunc)(hWnd, lpString);
}
```

3. `hook_iat()`

```c
BOOL hook_iat(LPCSTR szDllName, PROC pfnOrg, PROC pfnNew)
{
	HMODULE hMod;
	LPCSTR szLibName;
	PIMAGE_IMPORT_DESCRIPTOR pImportDesc; 
	PIMAGE_THUNK_DATA pThunk;
	DWORD dwOldProtect, dwRVA;
	PBYTE pAddr;

    // hMod, pAddr = ImageBase of calc.exe
    //             = VA to MZ signature (IMAGE_DOS_HEADER)
	hMod = GetModuleHandle(NULL);
	pAddr = (PBYTE)hMod;

    // pAddr = VA to PE signature (IMAGE_NT_HEADERS)
	pAddr += *((DWORD*)&pAddr[0x3C]);

    // dwRVA = RVA to IMAGE_IMPORT_DESCRIPTOR Table
	dwRVA = *((DWORD*)&pAddr[0x80]);

    // pImportDesc = VA to IMAGE_IMPORT_DESCRIPTOR Table
	pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)hMod+dwRVA);

	for( ; pImportDesc->Name; pImportDesc++ )
	{
        // szLibName = VA to IMAGE_IMPORT_DESCRIPTOR.Name
		szLibName = (LPCSTR)((DWORD)hMod + pImportDesc->Name);
		if( !_stricmp(szLibName, szDllName) )
		{
            // pThunk = IMAGE_IMPORT_DESCRIPTOR.FirstThunk
            //        = VA to IAT(Import Address Table)
			pThunk = (PIMAGE_THUNK_DATA)((DWORD)hMod + 
                                         pImportDesc->FirstThunk);

            // pThunk->u1.Function = VA to API
			for( ; pThunk->u1.Function; pThunk++ )
			{
				if( pThunk->u1.Function == (DWORD)pfnOrg )
				{
                    // 更改内存属性为E/R/W
					VirtualProtect((LPVOID)&pThunk->u1.Function, 
                                   4, 
                                   PAGE_EXECUTE_READWRITE, 
                                   &dwOldProtect);

                    // 修改IAT值, 钩取
                    pThunk->u1.Function = (DWORD)pfnNew;
					
                    // 恢复内存属性
                    VirtualProtect((LPVOID)&pThunk->u1.Function, 
                                   4, 
                                   dwOldProtect, 
                                   &dwOldProtect);					
					return TRUE;
				}
			}
		}
	}
	return FALSE;
}
```

​	`hook_iat()`函数首先从`ImageBase`开始, 经由PE签名找到`IDT`. 然后通过for循环比较`pImportDesc->name`与`szDllName("user32.dll")`, 通过比较查找到`user32.dll`的`IMAGE_IMPORT_DESCRIPTOR`结构体地址. `pImportDesc->FirstThunk`成员所指的就是IAT. 之后通过for循环比较`pThunk->u1.Function`与`pfnOrg`, 查找得到`SetWindowTextW`的地址.  因为进程的IAT内存区域是只读的, 所以需要将这部分修改为 "可读写" 模式. 最后将`SetWindowTextW`地址修改为`MySetWindowTextW()`函数地址.

### 调试  hookiat.dll 文件

> 实验环境为 Windows 7 (32位) 系统环境.

1. 首先, 运行计算器, 用`Process Explorer`查看计算器进程的PID为`1604`, 如图所示:

<img src="{{https://github.com/kumqu/kumqu.github.io/blob/master}}/assets/2019-08-13\1.PNG" alt="1" style="zoom:67%;" />

2. 将`calc.exe`附加到`OllyDbg`, 附加成功后F9运行`calc.exe`进程, 然后设置`OllyDbg`选项`中断于新模块(DLL)`. 如下图所示. 这样, 注入DLL文件时, 控制权就会转给调试器.

<img src="{{https://github.com/kumqu/kumqu.github.io/blob/master}}/assets/2019-08-13\2.PNG" alt="2" style="zoom:60%;" />

3. 在命令行窗口中输入相应参数, 运行`InjectDll.exe`, 将`hookiat.dll`注入计算器进程, 如下图所示:

<img src="{{https://github.com/kumqu/kumqu.github.io/blob/master}}/assets/2019-08-13\3.PNG" alt="3" style="zoom: 67%;" />

4. 由于`calc.exe`进程发生DLL加载事件, `Ollydbg`会在可执行模块窗口的`hookiat.dll`处中断, 如下图所示:

<img src="{{https://github.com/kumqu/kumqu.github.io/blob/master}}/assets/2019-08-13\4.PNG" alt="4" style="zoom:60%;" />

5. 取消之前复选的`中断于新模块(DLL)`选项, 查找`DLLMain()`代码. 因为`DLLMain()`函数中使用了`SetWindowTextW`字符串, 所以在`Ollydbg`的代码窗口中右键选择`查找->所有参考文本字串`, 如下图所示:

<img src="{{https://github.com/kumqu/kumqu.github.io/blob/master}}/assets/2019-08-13\5.PNG" alt="5" style="zoom:60%;" />

6. 进入`SetWindowTextW`字符串的代码地址`73AC113E`处, 经过分析, 可以得知这一部分`73AC1130~  `即为`DLLMain()`函数, 如下图所示:

<img src="{{https://github.com/kumqu/kumqu.github.io/blob/master}}/assets/2019-08-13\6.PNG" alt="6" style="zoom:60%;" />

7. 调试`DLLMain()`函数, 运行到地址`72EA1160`处, 比较代码与参数输入, 可以得知这里是调用了`hook_iat()`函数, 如下图所示:

<img src="{{https://github.com/kumqu/kumqu.github.io/blob/master}}/assets/2019-08-13\7.PNG" alt="7" style="zoom:60%;" />

8. F7进入`hook_iat()`函数, 运行到如下部分, 其含义是从PE文件头查找`IMAGE_IMPORT_DESCRIPTION (IID Table)`的过程:

<img src="{{https://github.com/kumqu/kumqu.github.io/blob/master}}/assets/2019-08-13\8.PNG" alt="8" style="zoom:60%;" />

9. 继续调试, 到达如下代码部分, 其含义是在IAT中查找`SetWindowTextW API`的位置. `73AC10E0`地址处的指令, `ESI`的值为`user32.dll`的IAT起始地址`010010B4`, `EBP`的值为`SetWindowTextW`的地址`7562612B`.这部分代码运行循环进入IAT, 查找位于`01001110`的``SetWindowsTextW`的地址值`7562612B`:

<img src="{{https://github.com/kumqu/kumqu.github.io/blob/master}}/assets/2019-08-13\9.PNG" alt="9" style="zoom:60%;" />

10. 继续调试, `73AC1117`地址处的指令将`MySetWindowTextW (hook函数)`的地址`73AC1117`覆写到前面从IAT中获取的`SetWindowTextW`地址`01001110`, 即实现了IAT中`SetWindowTextW API`的钩取:

<img src="{{https://github.com/kumqu/kumqu.github.io/blob/master}}/assets/2019-08-13\10.PNG" alt="10" style="zoom:60%;" />

11. 完成上述IAT钩取后, 在`Ollydbg`中按F9正常运行运行`calc.exe`进程. 用户在计算器界面输入数字, `calc.exe`会调用IAT中保存的`hookiat.MySetWindowTextW()`地址. `MySetWindowsTextW()`函数会先将阿拉伯数字转换为中文数字, 再调用`user32.SetWindowTextW()`, 测试结果如下:

<img src="{{https://github.com/kumqu/kumqu.github.io/blob/master}}/assets/2019-08-13\11.PNG" alt="11" style="zoom:67%;" />

​	最终, 通过调试与测试, 使用DLL注入技术实现了对计算器IAT的修改, 进而对计算器的` SetWindowsTextW() API `进行钩取与利用.