#include <windows.h>
#include<stdio.h>
#include<string.h>

typedef struct tag_DEBUGPACKET {
	HANDLE  hProcess;
	HANDLE  hThread;
	CONTEXT context;
} DEBUGPACKET, *PDEBUGPACKET;
BOOL AssembleOpCode(PDEBUGPACKET dp, LPCVOID ulAddr, BYTE* opCode, int opLen, BYTE* chkOpCode=NULL);

LPWSTR RegFindUninstaller() {
	HKEY key;
	LPCWSTR path = TEXT("Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall");
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, path, NULL, KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE, &key) != ERROR_SUCCESS) return NULL;

#define MAX_KEY_LENGTH 255
	DWORD index = 0;
	WCHAR buffer[MAX_KEY_LENGTH];
	DWORD dwSize = MAX_KEY_LENGTH;
	WCHAR* rmAgentPath = NULL;
	while (RegEnumKeyEx(key, index, buffer, &dwSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
		HKEY key_sub;
		WCHAR* new_path = new WCHAR[51 + dwSize + 2];
		lstrcpy(new_path, path);
		lstrcpy(&new_path[51], TEXT("\\"));
		lstrcpy(&new_path[52], buffer);
		if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, new_path, NULL, KEY_READ, &key_sub) == ERROR_SUCCESS) {
			dwSize = MAX_KEY_LENGTH;
			LSTATUS result = RegQueryValueEx(key_sub, TEXT("DisplayName"), NULL, NULL, (LPBYTE)buffer, &dwSize);
			if (result == ERROR_SUCCESS && dwSize > 0) {
				if (lstrcmp(buffer, TEXT("AhnLab Policy Agent 4.6")) == 0) {
					dwSize = MAX_KEY_LENGTH;
					LSTATUS result = RegQueryValueEx(key_sub, TEXT("UninstallString"), NULL, NULL, (LPBYTE)buffer, &dwSize);
					if (result == ERROR_SUCCESS && dwSize > 0) {
						rmAgentPath = new WCHAR[wcslen(buffer) - 6]; //Remove " -AGENT" string
						lstrcpyn(rmAgentPath, buffer, wcslen(buffer) - 6);
					}
				}
			}
		}
		delete[] new_path;
		RegCloseKey(key_sub);
		dwSize = MAX_KEY_LENGTH;
		index++;
		
		if (rmAgentPath != NULL) break;
	}
	RegCloseKey(key);
	return rmAgentPath;
}

int main() {
	LPWSTR filePath = RegFindUninstaller();
	if (filePath == NULL) {
		printf("Cannot find Uninstaller\n");
		getchar();
		return 0;
	}
	wprintf(L"Found! %s\n", filePath);

	STARTUPINFO startInfo;
	PROCESS_INFORMATION processInfo;
	ZeroMemory(&startInfo, sizeof(startInfo));
	startInfo.cb = sizeof(startInfo);
	ZeroMemory(&processInfo, sizeof(processInfo));
	DWORD creationFlags = DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION;

	if (CreateProcess(NULL, filePath, NULL, NULL, FALSE, creationFlags, NULL, NULL, &startInfo, &processInfo) == FALSE) {
		printf("CreateProcess failed.\n");
		getchar();
		return 0;
	}
	delete[] filePath;
	SetLastError(0);
	CloseHandle(processInfo.hProcess);
	CloseHandle(processInfo.hThread);

	DEBUGPACKET debugee;
	DEBUG_EVENT stDE;
	bool isLoaderBreak = true;
	while (TRUE) {
		BOOL bProcessDbgEvent = WaitForDebugEvent(&stDE, 100);
		DWORD eventCode = stDE.dwDebugEventCode;
		if (eventCode == CREATE_PROCESS_DEBUG_EVENT) {
			printf("Process was created!\n");
			debugee.hProcess = stDE.u.CreateProcessInfo.hProcess;
			debugee.hThread = stDE.u.CreateProcessInfo.hThread;
			debugee.context.ContextFlags = CONTEXT_FULL;

			if (AssembleOpCode(&debugee, (LPVOID)0x0040207B, (BYTE*)"\x90\x90\x90\x90\x90\x90", 6, (BYTE*)"\x0F\x85\x84\x00\x00\x00") == FALSE) {
				printf("AssembleOpCode failed.\n");
				getchar();
				return 0;
			}
		}else if (eventCode == EXIT_PROCESS_DEBUG_EVENT) {
			break;
		}else if (eventCode == EXCEPTION_DEBUG_EVENT) {
			DWORD ex = stDE.u.Exception.ExceptionRecord.ExceptionCode;
			if (ex == EXCEPTION_BREAKPOINT) {
				if (isLoaderBreak == true) {
					isLoaderBreak = false;
					printf("Loader Break Point");
					getchar();
				}
			}
			ContinueDebugEvent(stDE.dwProcessId, stDE.dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
			continue;
		}
		ContinueDebugEvent(stDE.dwProcessId, stDE.dwThreadId, DBG_CONTINUE);
	}
	printf("Program ended.\n"); getchar();
	return 0;
}

BOOL AssembleOpCode(PDEBUGPACKET dp, LPCVOID ulAddr, BYTE* opCode, int opLen, BYTE* chkOpCode) {
	if (IsBadReadPtr(dp, sizeof(DEBUGPACKET)) == TRUE) return FALSE;

	DWORD dwReadWrite = 0;
	if (chkOpCode != NULL) {
		BYTE* bTargetOp = new BYTE[opLen];
		if (ReadProcessMemory(dp->hProcess, (LPCVOID)ulAddr, bTargetOp, opLen, &dwReadWrite) == FALSE) return FALSE;
		if (dwReadWrite != opLen) return FALSE;
		if (memcmp(bTargetOp, chkOpCode, opLen) != 0) return FALSE;
	}

	MEMORY_BASIC_INFORMATION mbi;
	VirtualQueryEx(dp->hProcess, (LPCVOID)ulAddr, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
	if (VirtualProtectEx(dp->hProcess, mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &mbi.Protect) == FALSE) return FALSE;

	if (WriteProcessMemory(dp->hProcess, (LPVOID)ulAddr, (LPVOID)opCode, opLen, &dwReadWrite) == FALSE) return FALSE;
	if (dwReadWrite != opLen) return FALSE;

	DWORD dwOldProtect;
	VirtualProtectEx(dp->hProcess, mbi.BaseAddress, mbi.RegionSize, mbi.Protect, &dwOldProtect);

	FlushInstructionCache(dp->hProcess, (LPCVOID)ulAddr, sizeof(BYTE));
	return TRUE;
}
