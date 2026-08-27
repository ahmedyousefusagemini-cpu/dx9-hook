#include "anticheat.h"
#include <windows.h>

// ============================================================================
// Memory-only anti-debug / anti-CE bypass for Conquer.exe + anti-cheat DLLs.
// The EXE on disk is never modified; everything is patched in the running
// process image. Safe to run every launch (idempotent byte writes).
//
// IMPORTANT ADDRESS RULE: all constants below are RVAs (image-base-relative,
// i.e. Ghidra VA minus 0x00400000). Every write goes to imageBase + rva.
// ============================================================================

namespace {

// ---- Conquer.exe (fixed image base 0x00400000, no ASLR) ------------------
// Login-dialog init (FUN_00A227E9, Ghidra VA 0x00A227E9). All five failure
// branches jump to CDialog::EndDialog(this,0). We NOP them so the init always
// succeeds and the game never self-closes on debugger / SoftICE presence.
// (Ghidra VA -> RVA = VA - 0x00400000)

struct Patch {
    DWORD rva;                 // image-base-relative
    BYTE  data[6];             // replacement bytes
};

const Patch kExePatches[] = {
    // VA 00A22CB8: JNZ 0x00A22F72  (device \\.\SICE probe)     -> NOP
    { 0x00622CB8, { 0x90,0x90,0x90,0x90,0x90,0x90 } },
    // VA 00A22CCB: JNZ 0x00A22F72  (device \\.\SIWDEBUG probe) -> NOP
    { 0x00622CCB, { 0x90,0x90,0x90,0x90,0x90,0x90 } },
    // VA 00A22CDE: JNZ 0x00A22F72  (device \\.\NTICE probe)    -> NOP
    { 0x00622CDE, { 0x90,0x90,0x90,0x90,0x90,0x90 } },
    // VA 00A22CF1: JNZ 0x00A22F72  (device \\.\SIWVID probe)   -> NOP
    { 0x00622CF1, { 0x90,0x90,0x90,0x90,0x90,0x90 } },
    // VA 00A22CF7: CALL [0x014F522C] IsDebuggerPresent          -> xor eax,eax
    { 0x00622CF7, { 0x33,0xC0,0x90,0x90,0x90,0x90 } },
    // VA 00A22D01: JNZ 0x00A22F74  (debugger present)           -> NOP
    { 0x00622D01, { 0x90,0x90,0x90,0x90,0x90,0x90 } },
};

// ---- Delay-load IAT slots for every anti-cheat DLL ------------------------
// Conquer.exe delay-loads several DLLs through IAT slot tables in .data. Each
// slot is pre-filled with the per-import delay-load helper stub; overwriting
// the slot with the address of one of our no-op stubs makes the import resolve
// to a harmless function and the target DLL is NEVER mapped.
//
// Slot addresses verified against the PE delay-load directory @ VA 0x019DD4F0:
//   ndac.dll        IAT VA 0x01A54474  -> RVA 0x01654474 (26 ordinal imports)
//   Assist.dll      IAT VA 0x01A54378  -> RVA 0x01654378 (15 slots)
//   TqNDProtect.dll IAT VA 0x01A54448  -> RVA 0x01654448 (3 imports)
//
// Slot values must be POINTERS to executable stub code (below).

const DWORD kInitSlotRva    = 0x01654448;   // TQNDP_Initialize
const DWORD kDestroySlotRva = 0x0165444C;   // TQNDP_Destroy
const DWORD kTokenSlotRva   = 0x01654450;   // TQNDP_GetPlayerToken

const DWORD kNdacIatRva   = 0x01654474;
const DWORD kNdacSlots    = 26;
const DWORD kAssistIatRva = 0x01654378;
const DWORD kAssistSlots  = 15;

// Stub machine code. The thunks do `JMP [slot]`, so the stub address stored in
// the slot must point to EXECUTABLE memory. We allocate one RWX page at init
// and copy these byte sequences there (see InstallAntiCheatBypass).
//   stub_TQNDP_Initialize    : mov al,1; ret   (returns success, AL=1)
//   stub_GenericNoop         : xor eax,eax; ret (returns 0 / NULL)
const BYTE kStubInitCode[]  = { 0xB0, 0x01, 0xC3, 0x90, 0x90, 0x90, 0x90 }; // mov al,1; ret
const BYTE kStubNoopCode[]  = { 0x33, 0xC0, 0xC3, 0x90, 0x90, 0x90, 0x90 }; // xor eax,eax; ret

BYTE* g_stubInit = nullptr;   // executable copy of kStubInitCode
BYTE* g_stubNoop = nullptr;   // executable copy of kStubNoopCode

bool WriteMemory(void* address, const void* data, size_t length)
{
    DWORD oldProtect = 0;
    if (!VirtualProtect(address, length, PAGE_EXECUTE_READWRITE, &oldProtect))
        return false;
    memcpy(address, data, length);
    VirtualProtect(address, length, oldProtect, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), address, length);
    return true;
}

bool WritePointer(DWORD slotRva, uintptr_t imageBase, const void* target)
{
    DWORD address = (DWORD)target;
    return WriteMemory((void*)(imageBase + slotRva), &address, sizeof(address));
}

} // namespace

bool InstallAntiCheatBypass()
{
    const uintptr_t imageBase = (uintptr_t)GetModuleHandleA(nullptr);
    if (!imageBase)
        return false;

    // Allocate an executable page for the stubs (data arrays are not
    // executable under DEP; the game JMPs into these addresses).
    if (!g_stubInit || !g_stubNoop)
    {
        BYTE* page = (BYTE*)VirtualAlloc(nullptr, 0x100, MEM_COMMIT | MEM_RESERVE,
                                         PAGE_EXECUTE_READWRITE);
        if (!page)
            return false;
        memcpy(page, kStubInitCode, sizeof(kStubInitCode));
        memcpy(page + 0x10, kStubNoopCode, sizeof(kStubNoopCode));
        g_stubInit = page;
        g_stubNoop = page + 0x10;
    }

    bool ok = true;

    // 1) Neutralize the EXE's debugger/SoftICE checks.
    for (const Patch& p : kExePatches)
    {
        if (!WriteMemory((void*)(imageBase + p.rva), p.data, sizeof(p.data)))
            ok = false;
    }

    // 2) Block TqNDProtect.dll: point its three delay-load IAT slots at our
    //    no-op stubs. The DLL never loads, so its CE watchdog never runs.
    if (!WritePointer(kInitSlotRva,    imageBase, g_stubInit))
        ok = false;
    if (!WritePointer(kDestroySlotRva, imageBase, g_stubNoop))
        ok = false;
    if (!WritePointer(kTokenSlotRva,   imageBase, g_stubNoop))
        ok = false;

    // 3) Block ndac.dll (VMProtect anti-cheat) + Assist.dll by filling their
    //    whole delay-load IAT with a generic no-op stub.
    for (DWORD i = 0; i < kNdacSlots; ++i)
    {
        if (!WritePointer(kNdacIatRva + i * 4, imageBase, g_stubNoop))
            ok = false;
    }
    for (DWORD i = 0; i < kAssistSlots; ++i)
    {
        if (!WritePointer(kAssistIatRva + i * 4, imageBase, g_stubNoop))
            ok = false;
    }

    return ok;
}
