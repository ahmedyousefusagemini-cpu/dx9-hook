#include "nt_hide.h"
#include "MinHook.h"
#include <windows.h>

// ============================================================================
// ntdll-level CE hiding for ndac.dll (VMProtect anti-cheat) + crash logger.
// ============================================================================

extern void HookLog(const char* fmt, ...);  // defined in dllmain.cpp

namespace {

// ---- NtQuerySystemInformation ----
// SystemProcessInformation (5): process list with names
// SystemModuleInformation   (11): loaded kernel modules (drivers)
// SystemHandleInformation    (16): handle table
// SystemExtendedProcessInformation (57): like 5
typedef LONG (NTAPI* NtQuerySystemInformation_t)(ULONG, PVOID, ULONG, PULONG);
NtQuerySystemInformation_t Real_NtQuerySystemInformation = nullptr;

bool IsCeWide(const wchar_t* s)
{
    if (!s || !s[0]) return false;
    if (wcsstr(s, L"cheatengine")) return true;
    if (wcsstr(s, L"Cheat Engine")) return true;
    if (wcsstr(s, L"TfrmCheatEngine")) return true;
    if (wcsstr(s, L"DBK64")) return true;
    if (wcsstr(s, L"dbk64")) return true;
    return false;
}

// SYSTEM_PROCESS_INFORMATION is a linked list; each entry ends with
// ImageName (UNICODE_STRING). We filter entries whose name matches CE.
// Layout (x86):
//   ULONG NextEntryOffset; ULONG NumberOfThreads; ...
//   UNICODE_STRING ImageName at offset 0x2C (after Reserved[3], CreateTime etc.)
// Using the documented offsets for the start of ImageName is fragile across
// builds; instead we walk by NextEntryOffset and treat the structure via the
// Windows SDK type when available, else raw bytes with a generous approach:
//   ImageName is at fixed offset 0x2C on 32-bit for SystemProcessInformation.
struct RAW_PROC_INFO {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    BYTE  rest[0x24];       // up to ImageName
    USHORT ImageNameLength;
    USHORT ImageNameMaxLen;
    PWSTR  ImageNameBuffer; // relative pointer on x86 (absolute)
};

LONG NTAPI Hooked_NtQuerySystemInformation(ULONG cls, PVOID info, ULONG len, PULONG ret)
{
    LONG st = Real_NtQuerySystemInformation(cls, info, len, ret);
    if (st != 0)
        return st;

    if (cls == 5 || cls == 57) // SystemProcessInformation / Extended
    {
        BYTE* p = (BYTE*)info;
        BYTE* end = p + len;
        while (p + 0x34 <= end)
        {
            RAW_PROC_INFO* pi = (RAW_PROC_INFO*)p;
            if (pi->ImageNameLength > 0 && pi->ImageNameLength < 0x1000 &&
                pi->ImageNameBuffer &&
                (uintptr_t)pi->ImageNameBuffer >= 0x10000 &&
                (uintptr_t)pi->ImageNameBuffer < (uintptr_t)0x7FFFFFFF)
            {
                if (pi->ImageNameLength >= 2)
                {
                    wchar_t tmp[520];
                    size_t n = (pi->ImageNameLength > sizeof(tmp)-2) ? sizeof(tmp)/2-1 : pi->ImageNameLength/2;
                    memcpy(tmp, pi->ImageNameBuffer, n*2);
                    tmp[n] = 0;
                    if (IsCeWide(tmp))
                    {
                        // Zero out the name so scanners see an empty name
                        memset(pi->ImageNameBuffer, 0, pi->ImageNameLength);
                        pi->ImageNameLength = 0;
                    }
                }
            }
            if (pi->NextEntryOffset == 0) break;
            p += pi->NextEntryOffset;
        }
    }
    else if (cls == 11) // SystemModuleInformation - hide DBK driver module
    {
        // ULONG NumberOfModules; then SYSTEM_MODULE_INFORMATION entries (x86):
        //   ULONG Reserved[2]; ULONG Base; ULONG Size; ULONG Flags; USHORT Index;
        //   USHORT Unknown; USHORT LoadCount; USHORT NameLength; CHAR Name[256];
        // Name is at offset 0x18; entry stride is 0x11C on x86.
        ULONG* pn = (ULONG*)info;
        ULONG count = *pn;
        BYTE* entry = (BYTE*)info + 4;
        for (ULONG i = 0; i < count; ++i)
        {
            BYTE* name = entry + 0x18;
            char tmp[300]; tmp[0]=0;
            memcpy(tmp, name, sizeof(tmp)-1);
            if (strstr(tmp, "dbk") || strstr(tmp, "DBK") ||
                strstr(tmp, "cheatengine") || strstr(tmp, "Cheat Engine"))
            {
                memset(name, 0, 0x100);
            }
            entry += 0x11C;
        }
    }
    return st;
}

// ---- NtOpenFile / NtCreateFile - block \Device\DBK* ----
typedef LONG (NTAPI* NtOpenFile_t)(PHANDLE, ACCESS_MASK, PVOID, PVOID, ULONG, ULONG);
typedef LONG (NTAPI* NtCreateFile_t)(PHANDLE, ACCESS_MASK, PVOID, PVOID, PVOID, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
NtOpenFile_t Real_NtOpenFile = nullptr;
NtCreateFile_t Real_NtCreateFile = nullptr;

// OBJECT_ATTRIBUTES.ObjectName -> UNICODE_STRING -> buffer. Check for DBK path.
bool IsDbkObjectAttributes(const void* oa)
{
    if (!oa) return false;
    // OBJECT_ATTRIBUTES: ULONG Length; HANDLE RootDirectory; PUNICODE_STRING ObjectName; ...
    const BYTE* p = (const BYTE*)oa;
    const void* objNamePtr = *(const void**)(p + 8);
    if (!objNamePtr) return false;
    USHORT len = *(const USHORT*)objNamePtr;
    const void* buf = *(const void**)((const BYTE*)objNamePtr + 4);
    if (!buf || len == 0 || len > 0x2000) return false;
    wchar_t tmp[520]; size_t n = len/2; if (n > 519) n = 519;
    memcpy(tmp, buf, n*2); tmp[n] = 0;
    if (wcsstr(tmp, L"DBK") || wcsstr(tmp, L"dbk")) return true;
    if (wcsstr(tmp, L"cheatengine")) return true;
    return false;
}

LONG NTAPI Hooked_NtOpenFile(PHANDLE fh, ACCESS_MASK acc, PVOID oa, PVOID iosb,
                             ULONG share, ULONG open)
{
    if (IsDbkObjectAttributes(oa))
        return (LONG)0xC0000022; // STATUS_ACCESS_DENIED
    return Real_NtOpenFile(fh, acc, oa, iosb, share, open);
}

LONG NTAPI Hooked_NtCreateFile(PHANDLE fh, ACCESS_MASK acc, PVOID oa, PVOID iosb,
                               PVOID alloc, ULONG attr, ULONG share, ULONG disp,
                               ULONG opts, PVOID ea, ULONG ealen)
{
    if (IsDbkObjectAttributes(oa))
        return (LONG)0xC0000022;
    return Real_NtCreateFile(fh, acc, oa, iosb, alloc, attr, share, disp, opts, ea, ealen);
}

// ---- Crash logger ----
LONG WINAPI CrashHandler(EXCEPTION_POINTERS* ep)
{
    static bool logged = false;
    if (!logged && ep && ep->ExceptionRecord)
    {
        logged = true;
        DWORD code = ep->ExceptionRecord->ExceptionCode;
        void* addr = ep->ExceptionRecord->ExceptionAddress;
        HMODULE mod = nullptr;
        GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCSTR)addr, &mod);
        char modname[MAX_PATH] = "?";
        if (mod) GetModuleFileNameA(mod, modname, MAX_PATH);
        char* base = strrchr(modname, '\\'); if (base) base = base + 1; else base = modname;
        if (ep->ContextRecord)
        {
            void* eip = (void*)ep->ContextRecord->Eip;
            HookLog("*** CRASH code=0x%08X at %p (module %s) EIP=%p", code, addr, base, eip);
        }
        else
        {
            HookLog("*** CRASH code=0x%08X at %p (module %s)", code, addr, base);
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

} // namespace

bool InstallNtHideHooks()
{
    bool ok = true;
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return false;

    MH_STATUS s = MH_Initialize();
    if (s != MH_OK && s != MH_ERROR_ALREADY_INITIALIZED) return false;

    LPVOID dummy = nullptr;

    if (MH_CreateHookApiEx(L"ntdll.dll", "NtQuerySystemInformation",
        &Hooked_NtQuerySystemInformation, (LPVOID*)&Real_NtQuerySystemInformation, &dummy) != MH_OK)
        ok = false;
    if (MH_CreateHookApiEx(L"ntdll.dll", "NtOpenFile",
        &Hooked_NtOpenFile, (LPVOID*)&Real_NtOpenFile, &dummy) != MH_OK)
        ok = false;
    if (MH_CreateHookApiEx(L"ntdll.dll", "NtCreateFile",
        &Hooked_NtCreateFile, (LPVOID*)&Real_NtCreateFile, &dummy) != MH_OK)
        ok = false;

    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK)
        ok = false;

    // Crash logger — always, regardless of hook success.
    SetUnhandledExceptionFilter(CrashHandler);

    return ok;
}
