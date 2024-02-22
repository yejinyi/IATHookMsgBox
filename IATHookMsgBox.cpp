#include <windows.h>
#include <stdio.h>
#include <iostream>
#include <imagehlp.h>                          // ��� <imagehlp.h> ͷ�ļ���Ϊ��ʹ�� imagehlp.lib ���ļ�
using namespace std;

#pragma comment(lib,"imagehlp.lib")           // ʹ�� #pragma ָ����ָ����Ҫ���ӵĿ��ļ�����ΪҪʹ��ImageDirectoryEntryToData��������
#pragma warning(disable:4996)


// ����һ���µ��������ͣ���������һ������ָ�룬�������Ҫ�����������MessageBox����Ϊ������Ҫ��ȡ����Ӧ�ĵ�ַ
typedef int
(WINAPI* PFN_MessageBoxA)(
	HWND hWnd,                               // handle of owner window
	LPCTSTR lpText,                          // address of text in message box
	LPCTSTR lpCaption,                       // address of title of message box
	UINT uType                               // style of message box
	);        

//����ԭʼMessageBoxA�ĵ�ַ
PFN_MessageBoxA OldMessageBox = NULL;
//ָ��IAT��pThunk�ĵ�ַ
PULONG_PTR g_PointerToIATThunk = NULL;

VOID ShowMsgBox(char* szMsg)
{
	MessageBoxA(NULL, szMsg, "Test", MB_OK);
}

// Ϊָ��ģ�鰲װIAT Hook
BOOL InstallModuleIATHook(
	HMODULE hModToHook,                     // IN,   ��Hook��ģ���ַ
	char* szModuleName,                     // IN��  Ŀ�꺯������ģ�������
	char* szFuncName,                       // IN��    Ŀ�꺯��������
	PVOID DetourFunc,                       // IN��    Detour������ַ
	PULONG_PTR* pThunkPointer,              //OUT��  ���ڽ���ָ���޸ĵ�λ�õ�ָ��
	ULONG_PTR* pOriginalFuncAddr            //OUT�����ڽ���ԭʼ������ַ
)
{
	HMODULE hModule = LoadLibrary(szModuleName);      // ����Ŀ��ģ��
	ULONG ulSize;
	PIMAGE_IMPORT_DESCRIPTOR  pImportDescriptor;      // �����ṹ��
	char* szModeName;
	PIMAGE_THUNK_DATA pThunkData;                     // ������һ����¼,�ṹ��һ�㶼�Ƕ���Ϊָ��
	PULONG_PTR lpAddr; 
	MEMORY_BASIC_INFORMATION mbi;
	BOOL bRetn;
	BOOL result = FALSE;
	DWORD dwOldProtect;

	ULONG_PTR TargetFunAddr = (ULONG_PTR)GetProcAddress(hModule, szFuncName);             // ��ȡĿ��ģ���е�Ŀ�꺯����ַ
	printf("[*]Address of %s:0x%p\n", szFuncName, TargetFunAddr);                         // ���Ŀ�꺯�������Լ���ַ
	printf("[*]Module To Hook at Base:0x%p\n", hModToHook);                               // ����� Hook ��ģ���ַ

	// ��ȡ��ͼ���ض����ݵķ��ʣ������ֵ���ظ������ṹ��
	pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(hModToHook,           // ͼƬ�Ļ���ַ
		TRUE,                                 // �ñ�־ΪTRUE������ϵͳ�ļ�ӳ��Ϊͼ�񣬴˱�־Ϊ FALSE�����ļ�ӳ��Ϊ����
		IMAGE_DIRECTORY_ENTRY_IMPORT,         // ����Ŀ¼
		&ulSize);                             // ���ڽ�������λĿ¼������ݴ�С   
	printf("[*]Find ImportTable,Address:0x%p\n", pImportDescriptor);  // ����������׵�ַ

	while (pImportDescriptor->FirstThunk)
	{

		// ��ȡ��ǰ�� hook ��ģ�������, ��ΪpImportDescriptor->Name��DWORD���ͣ�hModToHook ��һ��ģ�����һ����ַ����Ҫת����PBYTEָ�����ͽ��в���
		szModeName = (char*)((PBYTE)hModToHook + pImportDescriptor->Name);          // PBYTE ��һ��ָ�룬һ��ָ�����һ�� DWORD ���ͣ��������ָ������ƶ��ľ���		
		printf("[*] Cur Module Name:%s\n", szModeName);
		
		if (stricmp(szModeName, szModuleName) != 0)      // �����Hook��ģ��������Ҫ��hook��ģ�����ֲ�һ��
		{
			
			printf("[*] Module Name does not match,search next...\n");
			pImportDescriptor++;
			continue;
		} 

		// ����ĵ��������Ϻ� OriginalFirstThunk��ָ���������Ʊ���������Ч�ģ������ٸ������������ң����Ǳ��� FirstThunk��ָ�������ַ��ֱ�Ӹ��ݵ�ַ�ж�
		pThunkData = (PIMAGE_THUNK_DATA)((PBYTE)hModToHook + pImportDescriptor->FirstThunk);
		while (pThunkData->u1.Function)                // �������ĺ������ڴ��ַΪ��ʱ
		{

			lpAddr = (ULONG_PTR*)pThunkData;           // ��Ŀ��ģ���еĺ�����ֵ��lpAddr,Ϊ�˺������ֱ��ʹ�� lpAddr����
			if (TargetFunAddr == *lpAddr)              // �ҵ���Ŀ��ģ���е�Ŀ�꺯����ַ
			{
				printf("[*] Find target address!\n");
				// ͨ������µ���������ڴ�ҳ����ֻ���ģ������Ҫ���޸��ڴ�ҳ������Ϊ��д
				VirtualQuery(lpAddr, &mbi, sizeof(mbi));      // �����йص��ý��̵������ַ�ռ��е�һϵ��ҳ�����Ϣ����ȡĿ�꺯�����ڴ���Ϣ
				bRetn = VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &dwOldProtect);  // Ҫ�޸�����Ŀ�꺯�����ڴ���Ϣ��ע��ʱ�ڴ���Ϣ
				if (bRetn)
				{
					// �ڴ�ҳ�����޸ĳɹ���������һ���������ȱ���ԭʼ����
					if (pThunkPointer != NULL)              // pThunkPointer ���ڽ���ָ���޸ĵ�λ�õ�ָ��
					{
						*pThunkPointer = lpAddr;
					}
					if (pOriginalFuncAddr != NULL)
					{
						*pOriginalFuncAddr = *lpAddr;
					}
					// �޸ĵ�ַ
					//lpAddr = (PULONG_PTR)DetourFunc;       // Detour������ַ,���ǵĲ����ļ��ؼ�������ַ�滻Ŀ�꺯���ĵ�ַ
					*lpAddr = (ULONG_PTR)DetourFunc;         // ��ַ�޸ģ����ݵ���ָ�룬�����д������
					result = TRUE;
					// �ָ��ڴ�ҳ������
					VirtualProtect(mbi.BaseAddress, mbi.RegionSize, dwOldProtect, 0);
					printf("[*] Hook ok.\n");
				}
				break;
			}
			pThunkData++;
		}
		pImportDescriptor++;
	}
	FreeLibrary(hModule);     // �ͷ�Ŀ��ģ���ڴ�

	return result;
}

// �����Լ���MessageBox�������滻ԭʼ��MessageBox
int My_MessageBoxA(HWND hWnd,          // handle of owner window
	LPCTSTR lpText,                    // address of text in message box
	LPCTSTR lpCaption,                 // address of title of message box
	UINT uType)                        // style of message box
{
	char newText[1024] = { 0 };
	char newCaption[256] = "pediy.com";

	// �Լ������MessageBox,���ǿ���������д���⹦�ܣ��滻ԭʼ�� MessageBox
	printf("���˵���ԭʼMessageBox, �����Զ����My_MessageBox,��Ҫ׼���滻ԭʼ��MessageBox��\n");
	//Ϊ��ֹԭ�����ṩ�Ļ��������������︴�Ƶ������Լ���һ�����������ٽ��в���
	lstrcpy(newText, lpText);
	lstrcat(newText, "\n\tMessageBox Hacked by pediy.com!");//�۸���Ϣ������
	uType |= MB_ICONERROR;//����һ������ͼ��
	int ret;
	// ��ʱ�Զ����My_MessageBox,��ȻҪ����MessageBox��ɹ��ܣ���ʱ��My_MessageBox�����ܹ��滻ԭʼ��MessageBox ������ʾ
	ret = OldMessageBox(hWnd, newText, newCaption, uType);

	return ret;
}

BOOL IAT_InstallHook()
{
	BOOL bReasult = NULL;
	PULONG_PTR pt;               // ���ڽ���ָ���޸ĵ�λ�õ�ָ��
	ULONG_PTR OrginalAddr;       // ���ڽ���ԭʼ������ַ���������ΪΪ�˱��滷��
	BOOL bResult;

	HMODULE hCurExe = GetModuleHandle(NULL);      // ����ָ��ģ��ľ��������˲���ΪNULL���������ڷ��ش������ý��̵��ļ���������Ƿ������������ļ����
	bReasult = InstallModuleIATHook(hCurExe, "user32.dll", "MessageBoxA", (PVOID)My_MessageBoxA, &pt, &OrginalAddr);     // �Զ��庯����Ϊָ��ģ�鰲װ IAT Hook
	if (bReasult)
	{
		printf("[*] Hook ��װ��ϣ�pThunk = 0x%p  OriginalAddr = 0x%p\n", pt, OrginalAddr);   // ����޸ĵ�ģ��ĵ�ַ�Լ�������ַ
		g_PointerToIATThunk = pt;                         // ��ָ��IAT��pThunk�ĵ�ַ�����б��棬���ں���ж��Hook��ʹ��
		OldMessageBox = (PFN_MessageBoxA)OrginalAddr;     // �����ʼʱMessageBox ����
	}
	return bReasult;


}


void IAT_UnInstallHook()
{
	MEMORY_BASIC_INFORMATION mbi;
	DWORD dwOLD;

	if (g_PointerToIATThunk)     // ��ȡ�����޸ĵ� ָ��IAT��pThunk�ĵ�ַ
	{
		// ��ѯ���޸��ڴ�����
		VirtualQuery((LPCVOID)g_PointerToIATThunk, &mbi, sizeof(mbi));
		VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &dwOLD);     // dwOLD���ڽ��ո�ҳ�������е�һҳ����ǰ���ʱ���ֵ
		// ��ԭʼ�� MessageBoxA ��ַ���� IAT ��
		*g_PointerToIATThunk = (ULONG)OldMessageBox;

		// �ָ��ڴ�ҳ������
		VirtualProtect(mbi.BaseAddress, mbi.RegionSize, dwOLD, 0);
	}
	cout << "Hookж�سɹ�";

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