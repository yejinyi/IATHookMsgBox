#include <windows.h>
#include <stdio.h>
#include <iostream>
#include <imagehlp.h>                          // 添加 <imagehlp.h> 头文件，为了使用 imagehlp.lib 库文件
using namespace std;

#pragma comment(lib,"imagehlp.lib")           // 使用 #pragma 指令来指定需要链接的库文件，因为要使用ImageDirectoryEntryToData（）函数
#pragma warning(disable:4996)


// 创建一个新的数据类型，就是声明一个函数指针，这里必须要进行声明这个MessageBox，因为后续需要获取到相应的地址
typedef int
(WINAPI* PFN_MessageBoxA)(
	HWND hWnd,                               // handle of owner window
	LPCTSTR lpText,                          // address of text in message box
	LPCTSTR lpCaption,                       // address of title of message box
	UINT uType                               // style of message box
	);        

//保存原始MessageBoxA的地址
PFN_MessageBoxA OldMessageBox = NULL;
//指向IAT中pThunk的地址
PULONG_PTR g_PointerToIATThunk = NULL;

VOID ShowMsgBox(char* szMsg)
{
	MessageBoxA(NULL, szMsg, "Test", MB_OK);
}

// 为指定模块安装IAT Hook
BOOL InstallModuleIATHook(
	HMODULE hModToHook,                     // IN,   待Hook的模块基址
	char* szModuleName,                     // IN，  目标函数所在模块的名字
	char* szFuncName,                       // IN，    目标函数的名字
	PVOID DetourFunc,                       // IN，    Detour函数地址
	PULONG_PTR* pThunkPointer,              //OUT，  用于接收指向修改的位置的指针
	ULONG_PTR* pOriginalFuncAddr            //OUT，用于接收原始函数地址
)
{
	HMODULE hModule = LoadLibrary(szModuleName);      // 加载目标模块
	ULONG ulSize;
	PIMAGE_IMPORT_DESCRIPTOR  pImportDescriptor;      // 输入表结构体
	char* szModeName;
	PIMAGE_THUNK_DATA pThunkData;                     // 导入表的一条记录,结构体一般都是定义为指针
	PULONG_PTR lpAddr; 
	MEMORY_BASIC_INFORMATION mbi;
	BOOL bRetn;
	BOOL result = FALSE;
	DWORD dwOldProtect;

	ULONG_PTR TargetFunAddr = (ULONG_PTR)GetProcAddress(hModule, szFuncName);             // 获取目标模块中的目标函数地址
	printf("[*]Address of %s:0x%p\n", szFuncName, TargetFunAddr);                         // 输出目标函数名字以及地址
	printf("[*]Module To Hook at Base:0x%p\n", hModToHook);                               // 输出待 Hook 的模块基址

	// 获取对图像特定数据的访问，将获得值返回给输入表结构体
	pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(hModToHook,           // 图片的基地址
		TRUE,                                 // 该标志为TRUE，代表系统文件映射为图像，此标志为 FALSE，则将文件映射为数据
		IMAGE_DIRECTORY_ENTRY_IMPORT,         // 导入目录
		&ulSize);                             // 用于接收所定位目录项的数据大小   
	printf("[*]Find ImportTable,Address:0x%p\n", pImportDescriptor);  // 输出输入表的首地址

	while (pImportDescriptor->FirstThunk)
	{

		// 获取当前待 hook 的模块的名字, 因为pImportDescriptor->Name是DWORD类型，hModToHook 是一个模块代表一个地址，需要转换成PBYTE指针类型进行操作
		szModeName = (char*)((PBYTE)hModToHook + pImportDescriptor->Name);          // PBYTE 是一个指针，一个指针加上一个 DWORD 类型，代表这个指针向后移动的距离		
		printf("[*] Cur Module Name:%s\n", szModeName);
		
		if (stricmp(szModeName, szModuleName) != 0)      // 如果待Hook的模块名字与要求hook的模块名字不一致
		{
			
			printf("[*] Module Name does not match,search next...\n");
			pImportDescriptor++;
			continue;
		} 

		// 程序的导入表处理完毕后 OriginalFirstThunk（指向输入名称表）可能是无效的，不能再根据名称来查找，而是遍历 FirstThunk（指向输入地址表）直接根据地址判断
		pThunkData = (PIMAGE_THUNK_DATA)((PBYTE)hModToHook + pImportDescriptor->FirstThunk);
		while (pThunkData->u1.Function)                // 当输入表的函数的内存地址为真时
		{

			lpAddr = (ULONG_PTR*)pThunkData;           // 将目标模块中的函数赋值给lpAddr,为了后面便于直接使用 lpAddr操作
			if (TargetFunAddr == *lpAddr)              // 找到了目标模块中的目标函数地址
			{
				printf("[*] Find target address!\n");
				// 通常情况下导入表所在内存页都是只读的，因此需要先修改内存页的属性为可写
				VirtualQuery(lpAddr, &mbi, sizeof(mbi));      // 检索有关调用进程的虚拟地址空间中的一系列页面的信息，获取目标函数的内存信息
				bRetn = VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &dwOldProtect);  // 要修改上述目标函数的内存信息，注意时内存信息
				if (bRetn)
				{
					// 内存页属性修改成功，继续下一步操作，先保存原始数据
					if (pThunkPointer != NULL)              // pThunkPointer 用于接收指向修改的位置的指针
					{
						*pThunkPointer = lpAddr;
					}
					if (pOriginalFuncAddr != NULL)
					{
						*pOriginalFuncAddr = *lpAddr;
					}
					// 修改地址
					//lpAddr = (PULONG_PTR)DetourFunc;       // Detour函数地址,我们的病毒文件关键函数地址替换目标函数的地址
					*lpAddr = (ULONG_PTR)DetourFunc;         // 地址修改，传递的是指针，上面的写法不对
					result = TRUE;
					// 恢复内存页的属性
					VirtualProtect(mbi.BaseAddress, mbi.RegionSize, dwOldProtect, 0);
					printf("[*] Hook ok.\n");
				}
				break;
			}
			pThunkData++;
		}
		pImportDescriptor++;
	}
	FreeLibrary(hModule);     // 释放目标模块内存

	return result;
}

// 定义自己的MessageBox函数，替换原始的MessageBox
int My_MessageBoxA(HWND hWnd,          // handle of owner window
	LPCTSTR lpText,                    // address of text in message box
	LPCTSTR lpCaption,                 // address of title of message box
	UINT uType)                        // style of message box
{
	char newText[1024] = { 0 };
	char newCaption[256] = "pediy.com";

	// 自己定义的MessageBox,我们可以在这里写任意功能，替换原始的 MessageBox
	printf("有人调用原始MessageBox, 我是自定义的My_MessageBox,我要准备替换原始的MessageBox了\n");
	//为防止原函数提供的缓冲区不够，这里复制到我们自己的一个缓冲区中再进行操作
	lstrcpy(newText, lpText);
	lstrcat(newText, "\n\tMessageBox Hacked by pediy.com!");//篡改消息框内容
	uType |= MB_ICONERROR;//增加一个错误图标
	int ret;
	// 此时自定义的My_MessageBox,仍然要借助MessageBox完成功能，此时的My_MessageBox函数能够替换原始的MessageBox 函数显示
	ret = OldMessageBox(hWnd, newText, newCaption, uType);

	return ret;
}

BOOL IAT_InstallHook()
{
	BOOL bReasult = NULL;
	PULONG_PTR pt;               // 用于接收指向修改的位置的指针
	ULONG_PTR OrginalAddr;       // 用于接收原始函数地址，可以理解为为了保存环境
	BOOL bResult;

	HMODULE hCurExe = GetModuleHandle(NULL);      // 检索指定模块的句柄，如果此参数为NULL，代表用于返回创建调用进程的文件句柄，就是返回自身程序的文件句柄
	bReasult = InstallModuleIATHook(hCurExe, "user32.dll", "MessageBoxA", (PVOID)My_MessageBoxA, &pt, &OrginalAddr);     // 自定义函数，为指定模块安装 IAT Hook
	if (bReasult)
	{
		printf("[*] Hook 安装完毕！pThunk = 0x%p  OriginalAddr = 0x%p\n", pt, OrginalAddr);   // 输出修改的模块的地址以及函数地址
		g_PointerToIATThunk = pt;                         // 将指向IAT中pThunk的地址，进行保存，便于后续卸载Hook的使用
		OldMessageBox = (PFN_MessageBoxA)OrginalAddr;     // 保存初始时MessageBox 函数
	}
	return bReasult;


}


void IAT_UnInstallHook()
{
	MEMORY_BASIC_INFORMATION mbi;
	DWORD dwOLD;

	if (g_PointerToIATThunk)     // 获取到了修改的 指向IAT中pThunk的地址
	{
		// 查询并修改内存属性
		VirtualQuery((LPCVOID)g_PointerToIATThunk, &mbi, sizeof(mbi));
		VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &dwOLD);     // dwOLD用于接收该页面区域中第一页的先前访问保护值
		// 将原始的 MessageBoxA 地址填入 IAT 中
		*g_PointerToIATThunk = (ULONG)OldMessageBox;

		// 恢复内存页的属性
		VirtualProtect(mbi.BaseAddress, mbi.RegionSize, dwOLD, 0);
	}
	cout << "Hook卸载成功";

}

int main()
{
	ShowMsgBox("Before IAT Hook");
	IAT_InstallHook();
	ShowMsgBox("After IAT Hook");
	IAT_UnInstallHook();
	ShowMsgBox("After IAT Hook UnHooked");

	return 0;
}