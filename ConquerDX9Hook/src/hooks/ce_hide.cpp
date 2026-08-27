#include "ce_hide.h"
#include "MinHook.h"
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>

#pragma comment(lib, "psapi.lib")

// ============================================================================
// Hide Cheat Engine from ndac.dll's anti-cheat detection. ndac (18MB VMProtect)
// calls EnumProcesses/FindWindowA/QueryDosDeviceW/CreateFile/FindFirstFile/etc.
// to spot CE. We hook those APIs to hide CE's process, window, driver, and
// files from the anti-cheat while leaving the game's own usage unaffected.
// ============================================================================

namespace {

bool IsCeString(const wchar_t* s)
{
    if (!s || !s[0]) return false;
    if (wcsstr(s, L"cheatengine") != nullptr) return true;
    if (wcsstr(s, L"Cheat Engine") != nullptr) return true;
    if (wcsstr(s, L"TfrmCheatEngine") != nullptr) return true;
    if (wcsstr(s, L"DBK64") != nullptr) return true;     // CE kernel driver
    if (wcsstr(s, L"dbk64") != nullptr) return true;
    if (wcsstr(s, L"\\\\.\\DBK") != nullptr) return true; // device path
    if (wcsstr(s, L"\\\\.\\SYSER") != nullptr) return true;
    return false;
}

bool IsCeString(const char* s)
{
    if (!s || !s[0]) return false;
    if (strstr(s, "cheatengine") != nullptr) return true;
    if (strstr(s, "Cheat Engine") != nullptr) return true;
    if (strstr(s, "TfrmCheatEngine") != nullptr) return true;
    if (strstr(s, "DBK64") != nullptr) return true;
    if (strstr(s, "dbk64") != nullptr) return true;
    if (strstr(s, "\\\\.\\DBK") != nullptr) return true;
    if (strstr(s, "\\\\.\\SYSER") != nullptr) return true;
    return false;
}

// ---- IsDebuggerPresent (kernel32) - always return FALSE ----
typedef BOOL (WINAPI* IsDebuggerPresent_t)();
IsDebuggerPresent_t Real_IsDebuggerPresent = nullptr;

BOOL WINAPI Hooked_IsDebuggerPresent()
{
    return FALSE;
}

// ---- EnumProcesses (psapi) - filter CE process IDs ----
typedef BOOL (WINAPI* EnumProcesses_t)(DWORD*, DWORD, DWORD*);
EnumProcesses_t Real_EnumProcesses = nullptr;

BOOL WINAPI Hooked_EnumProcesses(DWORD* lpidProcess, DWORD cb, DWORD* lpcbNeeded)
{
    BOOL ok = Real_EnumProcesses(lpidProcess, cb, lpcbNeeded);
    if (!ok) return ok;
    DWORD count = *lpcbNeeded / sizeof(DWORD);
    DWORD out = 0;
    for (DWORD i = 0; i < count; ++i)
    {
        DWORD pid = lpidProcess[i];
        if (pid == 0) continue;
        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        wchar_t name[MAX_PATH] = {0};
        if (h)
        {
            DWORD len = GetModuleBaseNameW(h, NULL, name, MAX_PATH);
            CloseHandle(h);
            if (len > 0 && IsCeString(name)) continue;
        }
        lpidProcess[out++] = pid;
    }
    *lpcbNeeded = out * sizeof(DWORD);
    return TRUE;
}

// ---- Process32FirstW / Process32NextW (kernel32) - skip CE ----
typedef BOOL (WINAPI* Process32FirstW_t)(HANDLE, LPPROCESSENTRY32W);
typedef BOOL (WINAPI* Process32NextW_t)(HANDLE, LPPROCESSENTRY32W);
Process32FirstW_t Real_Process32FirstW = nullptr;
Process32NextW_t Real_Process32NextW = nullptr;

BOOL WINAPI Hooked_Process32FirstW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe)
{
    BOOL ok = Real_Process32FirstW(hSnapshot, lppe);
    while (ok && IsCeString(lppe->szExeFile))
        ok = Real_Process32NextW(hSnapshot, lppe);
    return ok;
}

BOOL WINAPI Hooked_Process32NextW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe)
{
    BOOL ok = Real_Process32NextW(hSnapshot, lppe);
    while (ok && IsCeString(lppe->szExeFile))
        ok = Real_Process32NextW(hSnapshot, lppe);
    return ok;
}

// ---- FindWindowA / FindWindowExA (user32) - hide CE window ----
typedef HWND (WINAPI* FindWindowA_t)(LPCSTR, LPCSTR);
typedef HWND (WINAPI* FindWindowExA_t)(HWND, HWND, LPCSTR, LPCSTR);
FindWindowA_t Real_FindWindowA = nullptr;
FindWindowExA_t Real_FindWindowExA = nullptr;

HWND WINAPI Hooked_FindWindowA(LPCSTR lpClassName, LPCSTR lpWindowName)
{
    if (IsCeString(lpClassName) || IsCeString(lpWindowName))
        return NULL;
    return Real_FindWindowA(lpClassName, lpWindowName);
}

HWND WINAPI Hooked_FindWindowExA(HWND hwndParent, HWND hwndChildAfter,
                                 LPCSTR lpszClass, LPCSTR lpszWindow)
{
    if (IsCeString(lpszClass) || IsCeString(lpszWindow))
        return NULL;
    return Real_FindWindowExA(hwndParent, hwndChildAfter, lpszClass, lpszWindow);
}

// ---- GetWindowTextA (user32) - hide CE window titles ----
typedef int (WINAPI* GetWindowTextA_t)(HWND, LPSTR, int);
GetWindowTextA_t Real_GetWindowTextA = nullptr;

int WINAPI Hooked_GetWindowTextA(HWND hWnd, LPSTR lpString, int nMaxCount)
{
    int ret = Real_GetWindowTextA(hWnd, lpString, nMaxCount);
    if (ret > 0 && IsCeString(lpString))
    {
        lpString[0] = '\0';
        return 0;
    }
    return ret;
}

// ---- GetClassNameA (user32) - hide CE class names ----
typedef int (WINAPI* GetClassNameA_t)(HWND, LPSTR, int);
GetClassNameA_t Real_GetClassNameA = nullptr;

int WINAPI Hooked_GetClassNameA(HWND hWnd, LPSTR lpClassName, int nMaxCount)
{
    int ret = Real_GetClassNameA(hWnd, lpClassName, nMaxCount);
    if (ret > 0 && IsCeString(lpClassName))
    {
        lpClassName[0] = '\0';
        return 0;
    }
    return ret;
}

// ---- QueryDosDeviceW (kernel32) - hide CE driver devices ----
typedef DWORD (WINAPI* QueryDosDeviceW_t)(LPCWSTR, LPWSTR, DWORD);
QueryDosDeviceW_t Real_QueryDosDeviceW = nullptr;

DWORD WINAPI Hooked_QueryDosDeviceW(LPCWSTR lpDeviceName, LPWSTR lpTargetPath, DWORD ucchMax)
{
    DWORD ret = Real_QueryDosDeviceW(lpDeviceName, lpTargetPath, ucchMax);
    if (ret == 0) return ret;
    // Enumerate mode (lpDeviceName == NULL): lpTargetPath is a multi-string
    // (null-terminated entries, double-null at end). Filter out DBK64/CE entries.
    if (lpDeviceName != NULL) return ret;

    wchar_t* src = lpTargetPath;
    wchar_t* dst = lpTargetPath;
    DWORD remaining = ret; // bytes written by the OS
    while (remaining >= 2 && *src)
    {
        size_t len = wcslen(src);          // chars in this entry (excl. terminator)
        size_t bytes = (len + 1) * 2;      // entry incl. its null terminator
        if (!IsCeString(src))
        {
            memmove(dst, src, bytes);
            dst += len + 1;
        }
        src += len + 1;
        remaining -= (DWORD)bytes;
    }
    *dst = L'\0';
    return (DWORD)((wchar_t*)dst - lpTargetPath + 1) * 2;
}

// ---- CreateFileA / CreateFileW (kernel32) - block CE driver device opens ----
typedef HANDLE (WINAPI* CreateFileA_t)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef HANDLE (WINAPI* CreateFileW_t)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
CreateFileA_t Real_CreateFileA = nullptr;
CreateFileW_t Real_CreateFileW = nullptr;

HANDLE WINAPI Hooked_CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess,
    DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
    if (IsCeString(lpFileName))
    {
        SetLastError(ERROR_FILE_NOT_FOUND);
        return INVALID_HANDLE_VALUE;
    }
    return Real_CreateFileA(lpFileName, dwDesiredAccess, dwShareMode,
        lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

HANDLE WINAPI Hooked_CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess,
    DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
    if (IsCeString(lpFileName))
    {
        SetLastError(ERROR_FILE_NOT_FOUND);
        return INVALID_HANDLE_VALUE;
    }
    return Real_CreateFileW(lpFileName, dwDesiredAccess, dwShareMode,
        lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

// ---- FindFirstFileA / FindFirstFileW / FindNextFileA / FindNextFileW ----
typedef HANDLE (WINAPI* FindFirstFileA_t)(LPCSTR, LPWIN32_FIND_DATAA);
typedef HANDLE (WINAPI* FindFirstFileW_t)(LPCWSTR, LPWIN32_FIND_DATAW);
typedef BOOL   (WINAPI* FindNextFileA_t)(HANDLE, LPWIN32_FIND_DATAA);
typedef BOOL   (WINAPI* FindNextFileW_t)(HANDLE, LPWIN32_FIND_DATAW);
FindFirstFileA_t Real_FindFirstFileA = nullptr;
FindFirstFileW_t Real_FindFirstFileW = nullptr;
FindNextFileA_t Real_FindNextFileA = nullptr;
FindNextFileW_t Real_FindNextFileW = nullptr;

HANDLE WINAPI Hooked_FindFirstFileA(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData)
{
    HANDLE h = Real_FindFirstFileA(lpFileName, lpFindFileData);
    while (h != INVALID_HANDLE_VALUE && IsCeString(lpFindFileData->cFileName))
    {
        if (!Real_FindNextFileA(h, lpFindFileData))
        {
            FindClose(h);
            h = INVALID_HANDLE_VALUE;
            break;
        }
    }
    return h;
}

HANDLE WINAPI Hooked_FindFirstFileW(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData)
{
    HANDLE h = Real_FindFirstFileW(lpFileName, lpFindFileData);
    while (h != INVALID_HANDLE_VALUE && IsCeString(lpFindFileData->cFileName))
    {
        if (!Real_FindNextFileW(h, lpFindFileData))
        {
            FindClose(h);
            h = INVALID_HANDLE_VALUE;
            break;
        }
    }
    return h;
}

BOOL WINAPI Hooked_FindNextFileA(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData)
{
    BOOL ok = Real_FindNextFileA(hFindFile, lpFindFileData);
    while (ok && IsCeString(lpFindFileData->cFileName))
        ok = Real_FindNextFileA(hFindFile, lpFindFileData);
    return ok;
}

BOOL WINAPI Hooked_FindNextFileW(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData)
{
    BOOL ok = Real_FindNextFileW(hFindFile, lpFindFileData);
    while (ok && IsCeString(lpFindFileData->cFileName))
        ok = Real_FindNextFileW(hFindFile, lpFindFileData);
    return ok;
}

// ---- GetModuleBaseNameW (psapi) - filter CE modules ----
typedef DWORD (WINAPI* GetModuleBaseNameW_t)(HANDLE, HMODULE, LPWSTR, DWORD);
GetModuleBaseNameW_t Real_GetModuleBaseNameW = nullptr;

DWORD WINAPI Hooked_GetModuleBaseNameW(HANDLE hProcess, HMODULE hModule, LPWSTR lpBaseName, DWORD nSize)
{
    DWORD ret = Real_GetModuleBaseNameW(hProcess, hModule, lpBaseName, nSize);
    if (ret > 0 && IsCeString(lpBaseName))
    {
        lpBaseName[0] = L'\0';
        return 0;
    }
    return ret;
}

} // namespace

bool InstallCeHideHooks()
{
    bool ok = true;
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    HMODULE u32 = GetModuleHandleA("user32.dll");
    HMODULE psapi = GetModuleHandleA("psapi.dll");
    if (!k32 || !u32 || !psapi) return false;

    MH_STATUS s = MH_Initialize();
    if (s != MH_OK && s != MH_ERROR_ALREADY_INITIALIZED) return false;

    LPVOID dummy = nullptr;

    // Hide CE process
    if (MH_CreateHookApiEx(L"psapi.dll", "EnumProcesses",
        &Hooked_EnumProcesses, (LPVOID*)&Real_EnumProcesses, &dummy) != MH_OK) ok = false;
    if (MH_CreateHookApiEx(L"kernel32.dll", "Process32FirstW",
        &Hooked_Process32FirstW, (LPVOID*)&Real_Process32FirstW, &dummy) != MH_OK) ok = false;
    if (MH_CreateHookApiEx(L"kernel32.dll", "Process32NextW",
        &Hooked_Process32NextW, (LPVOID*)&Real_Process32NextW, &dummy) != MH_OK) ok = false;
    if (MH_CreateHookApiEx(L"psapi.dll", "GetModuleBaseNameW",
        &Hooked_GetModuleBaseNameW, (LPVOID*)&Real_GetModuleBaseNameW, &dummy) != MH_OK) ok = false;

    // Hide CE window
    if (MH_CreateHookApiEx(L"user32.dll", "FindWindowA",
        &Hooked_FindWindowA, (LPVOID*)&Real_FindWindowA, &dummy) != MH_OK) ok = false;
    if (MH_CreateHookApiEx(L"user32.dll", "FindWindowExA",
        &Hooked_FindWindowExA, (LPVOID*)&Real_FindWindowExA, &dummy) != MH_OK) ok = false;
    if (MH_CreateHookApiEx(L"user32.dll", "GetWindowTextA",
        &Hooked_GetWindowTextA, (LPVOID*)&Real_GetWindowTextA, &dummy) != MH_OK) ok = false;
    if (MH_CreateHookApiEx(L"user32.dll", "GetClassNameA",
        &Hooked_GetClassNameA, (LPVOID*)&Real_GetClassNameA, &dummy) != MH_OK) ok = false;

    // Hide CE kernel driver (DBK) and files
    if (MH_CreateHookApiEx(L"kernel32.dll", "QueryDosDeviceW",
        &Hooked_QueryDosDeviceW, (LPVOID*)&Real_QueryDosDeviceW, &dummy) != MH_OK) ok = false;
    if (MH_CreateHookApiEx(L"kernel32.dll", "CreateFileA",
        &Hooked_CreateFileA, (LPVOID*)&Real_CreateFileA, &dummy) != MH_OK) ok = false;
    if (MH_CreateHookApiEx(L"kernel32.dll", "CreateFileW",
        &Hooked_CreateFileW, (LPVOID*)&Real_CreateFileW, &dummy) != MH_OK) ok = false;
    if (MH_CreateHookApiEx(L"kernel32.dll", "FindFirstFileA",
        &Hooked_FindFirstFileA, (LPVOID*)&Real_FindFirstFileA, &dummy) != MH_OK) ok = false;
    if (MH_CreateHookApiEx(L"kernel32.dll", "FindFirstFileW",
        &Hooked_FindFirstFileW, (LPVOID*)&Real_FindFirstFileW, &dummy) != MH_OK) ok = false;
    if (MH_CreateHookApiEx(L"kernel32.dll", "FindNextFileA",
        &Hooked_FindNextFileA, (LPVOID*)&Real_FindNextFileA, &dummy) != MH_OK) ok = false;
    if (MH_CreateHookApiEx(L"kernel32.dll", "FindNextFileW",
        &Hooked_FindNextFileW, (LPVOID*)&Real_FindNextFileW, &dummy) != MH_OK) ok = false;

    // IsDebuggerPresent — always return FALSE (covers both EXE and ndac)
    if (MH_CreateHookApiEx(L"kernel32.dll", "IsDebuggerPresent",
        &Hooked_IsDebuggerPresent, (LPVOID*)&Real_IsDebuggerPresent, &dummy) != MH_OK) ok = false;

    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) ok = false;

    return ok;
}