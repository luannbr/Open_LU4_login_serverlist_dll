// inject.cpp — injeta lu4authhook.dll no processo do cliente via LoadLibraryW remoto.
// Uso:  inject.exe <pid> <caminho\lu4authhook.dll>
//
// Compilar (x64):  cl /nologo /O2 /EHsc inject.cpp /Fe:inject.exe

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <cwchar>

int wmain(int argc, wchar_t** argv)
{
    if (argc < 3) {
        wprintf(L"uso: inject.exe <pid> <caminho absoluto da dll>\n");
        return 1;
    }
    DWORD pid = (DWORD)_wtoi(argv[1]);
    const wchar_t* dll = argv[2];

    // caminho absoluto e existência
    wchar_t full[MAX_PATH];
    if (!GetFullPathNameW(dll, MAX_PATH, full, nullptr)) {
        wprintf(L"[!] caminho invalido\n"); return 2;
    }
    if (GetFileAttributesW(full) == INVALID_FILE_ATTRIBUTES) {
        wprintf(L"[!] DLL nao encontrada: %ls\n", full); return 2;
    }

    HANDLE hProc = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, pid);
    if (!hProc) {
        wprintf(L"[!] OpenProcess(%u) falhou: %lu\n", pid, GetLastError());
        return 3;
    }

    SIZE_T bytes = (wcslen(full) + 1) * sizeof(wchar_t);
    LPVOID remote = VirtualAllocEx(hProc, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) {
        wprintf(L"[!] VirtualAllocEx falhou: %lu\n", GetLastError());
        CloseHandle(hProc); return 4;
    }
    if (!WriteProcessMemory(hProc, remote, full, bytes, nullptr)) {
        wprintf(L"[!] WriteProcessMemory falhou: %lu\n", GetLastError());
        CloseHandle(hProc); return 5;
    }

    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    auto loadLib = (LPTHREAD_START_ROUTINE)GetProcAddress(k32, "LoadLibraryW");

    HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, loadLib, remote, 0, nullptr);
    if (!hThread) {
        wprintf(L"[!] CreateRemoteThread falhou: %lu\n", GetLastError());
        CloseHandle(hProc); return 6;
    }
    WaitForSingleObject(hThread, 10000);

    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);   // handle da DLL (baixo 32 bits) se carregou
    if (exitCode == 0) {
        wprintf(L"[!] LoadLibraryW retornou 0 — DLL nao carregou (dependencia? arquitetura?)\n");
    } else {
        wprintf(L"[+] DLL injetada no PID %u (HMODULE ~0x%08X)\n", pid, exitCode);
    }

    VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProc);
    return exitCode ? 0 : 7;
}
