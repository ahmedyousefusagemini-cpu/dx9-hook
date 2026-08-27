#include "ce_hide.h"
#include "MinHook.h"
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>

#pragma comment(lib, "psapi.lib")

// ============================================================================
// Hide Cheat Engine from ndac.dll's detection. ndac.dll (the 18MB VMProtect
// anti-cheat) calls EnumProcesses/FindWindowA/etc. to spot CE. We hook those
// APIs process-wide so any CE process / window is invisible to it. The game's
// own code is unaffected (it never scans for "cheat" windows/processes).
// ============================================================================

namespace {

bool IsCeName(const wchar_t* name)
{
    if (!name || !name[0]) return false;
    // CE process: "cheatengine*.exe"; CE window class: "TfrmCheatEngine*"
    if (_wcsnicmp(name, L"cheatengine", 11) == 0) return true;
    if (wcsstr(name, L"Cheat Engine") != nullptr) return true;
    if (wcsstr(name, L"TfrmCheatEngine") != nullptr) return true;
    if (_wcsnicmp(name, L"cheat", 5) == 0) return true;
    return false;
}

bool IsCeName(const char* name)
{
    if (!name || !name[0]) return false;
    if (_strnicmp(name, "cheatengine", 11) == 0) return true;
    if (strstr(name, "Cheat Engine") != nullptr) return true;
    if (strstr(name, "TfrmCheatEngine") != nullptr) return true;
    if (_strnicmp(name, "cheat", 5) == 0) return true;
    return false;
}

// ---- EnumProcesses (psapi) ----
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
            if (len > 0 && IsCeName(name)) continue;  // hide CE process
        }
        lpidProcess[out++] = pid;
    }
    *lpcbNeeded = out * sizeof(DWORD);
    return TRUE;
}

// ---- CreateToolhelp32Snapshot / Process32FirstW / Process32NextW ----
typedef HANDLE (WINAPI* CreateToolhelp32Snapshot_t)(DWORD, DWORD);
CreateToolhelp32Snapshot_t Real_CreateToolhelp32Snapshot = nullptr;

HANDLE WINAPI Hooked_CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID)
{
    return Real_CreateToolhelp32Snapshot(dwFlags, th32ProcessID);
}

// Filter CE entries out of the snapshot walk. The anti-cheat uses
// Process32First/Next to list processes; we make those two skip CE.
typedef BOOL (WINAPI* Process32FirstW_t)(HANDLE, LPPROCESSENTRY32W);
typedef BOOL (WINAPI* Process32NextW_t)(HANDLE, LPPROCESSENTRY32W);
Process32FirstW_t Real_Process32FirstW = nullptr;
Process32NextW_t Real_Process32NextW = nullptr;

BOOL WINAPI Hooked_Process32FirstW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe)
{
    BOOL ok = Real_Process32FirstW(hSnapshot, lppe);
    while (ok && IsCeName(lppe->szExeFile))
        ok = Real_Process32NextW(hSnapshot, lppe);
    return ok;
}

BOOL WINAPI Hooked_Process32NextW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe)
{
    BOOL ok = Real_Process32NextW(hSnapshot, lppe);
    while (ok && IsCeName(lppe->szExeFile))
        ok = Real_Process32NextW(hSnapshot, lppe);
    return ok;
}

// ---- FindWindowA / FindWindowExA ----
typedef HWND (WINAPI* FindWindowA_t)(LPCSTR, LPCSTR);
typedef HWND (WINAPI* FindWindowExA_t)(HWND, HWND, LPCSTR, LPCSTR);
FindWindowA_t Real_FindWindowA = nullptr;
FindWindowExA_t Real_FindWindowExA = nullptr;

HWND WINAPI Hooked_FindWindowA(LPCSTR lpClassName, LPCSTR lpWindowName)
{
    if (IsCeName(lpClassName) || IsCeName(lpWindowName))
        return NULL;
    return Real_FindWindowA(lpClassName, lpWindowName);
}

HWND WINAPI Hooked_FindWindowExA(HWND hwndParent, HWND hwndChildAfter,
                                 LPCSTR lpszClass, LPCSTR lpszWindow)
{
    if (IsCeName(lpszClass) || IsCeName(lpszWindow))
        return NULL;
    return Real_FindWindowExA(hwndParent, hwndChildAfter, lpszClass, lpszWindow);
}

} // namespace

bool InstallCeHideHooks()
{
    HMODULE psapi = GetModuleHandleA("psapi.dll");
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    HMODULE u32 = GetModuleHandleA("user32.dll");
    if (!psapi || !k32 || !u32) return false;

    MH_STATUS s = MH_Initialize();
    if (s != MH_OK && s != MH_ERROR_ALREADY_INITIALIZED) return false;

    bool ok = true;

    LPVOID dummy = nullptr;
    if (MH_CreateHookApiEx(L"psapi.dll", "EnumProcesses",
                           &Hooked_EnumProcesses, (LPVOID*)&Real_EnumProcesses, &dummy) != MH_OK)
        ok = false;
    if (MH_CreateHookApiEx(L"kernel32.dll", "CreateToolhelp32Snapshot",
                           &Hooked_CreateToolhelp32Snapshot,
                           (LPVOID*)&Real_CreateToolhelp32Snapshot, &dummy) != MH_OK)
        ok = false;
    if (MH_CreateHookApiEx(L"kernel32.dll", "Process32FirstW",
                           &Hooked_Process32FirstW, (LPVOID*)&Real_Process32FirstW, &dummy) != MH_OK)
        ok = false;
    if (MH_CreateHookApiEx(L"kernel32.dll", "Process32NextW",
                           &Hooked_Process32NextW, (LPVOID*)&Real_Process32NextW, &dummy) != MH_OK)
        ok = false;
    if (MH_CreateHookApiEx(L"user32.dll", "FindWindowA",
                           &Hooked_FindWindowA, (LPVOID*)&Real_FindWindowA, &dummy) != MH_OK)
        ok = false;
    if (MH_CreateHookApiEx(L"user32.dll", "FindWindowExA",
                           &Hooked_FindWindowExA, (LPVOID*)&Real_FindWindowExA, &dummy) != MH_OK)
        ok = false;

    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK)
        ok = false;

    return ok;
}
