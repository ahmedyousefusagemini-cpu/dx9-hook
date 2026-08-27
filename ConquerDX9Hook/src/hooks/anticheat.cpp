#include "anticheat.h"
#include <windows.h>

// ============================================================================
// Memory-only anti-debug / anti-CE bypass for Conquer.exe + TqNDProtect.dll.
// The EXE on disk is never modified; everything is patched in the running
// process image. Safe to run every launch (idempotent byte writes).
// ============================================================================

namespace {

// ---- Conquer.exe (fixed image base 0x00400000, no ASLR) ------------------
// Login-dialog init (FUN_00A227E9). All five failure branches jump to
// CDialog::EndDialog(this,0). We NOP them so the init always succeeds and the
// game never self-closes on debugger / SoftICE driver presence.

struct Patch {
    DWORD rva;                 // image-base-relative
    BYTE  data[6];             // replacement bytes
};

const Patch kExePatches[] = {
    // 00A22CB8: JNZ 0x00A22F72  (device \\.\SICE probe)     -> NOP
    { 0x00A22CB8, { 0x90,0x90,0x90,0x90,0x90,0x90 } },
    // 00A22CCB: JNZ 0x00A22F72  (device \\.\SIWDEBUG probe) -> NOP
    { 0x00A22CCB, { 0x90,0x90,0x90,0x90,0x90,0x90 } },
    // 00A22CDE: JNZ 0x00A22F72  (device \\.\NTICE probe)    -> NOP
    { 0x00A22CDE, { 0x90,0x90,0x90,0x90,0x90,0x90 } },
    // 00A22CF1: JNZ 0x00A22F72  (device \\.\SIWVID probe)   -> NOP
    { 0x00A22CF1, { 0x90,0x90,0x90,0x90,0x90,0x90 } },
    // 00A22CF7: CALL [0x014F522C] IsDebuggerPresent          -> xor eax,eax
    { 0x00A22CF7, { 0x33,0xC0,0x90,0x90,0x90,0x90 } },
    // 00A22D01: JNZ 0x00A22F74  (debugger present)           -> NOP
    { 0x00A22D01, { 0x90,0x90,0x90,0x90,0x90,0x90 } },
};

// ---- Delay-load IAT slots for every anti-cheat DLL ------------------------
// Conquer.exe delay-loads several DLLs through IAT slot tables in .data. Each
// slot is pre-filled with the per-import delay-load helper stub; overwriting
// the slot with the address of one of our no-op stubs makes the import resolve
// to a harmless function and the target DLL is NEVER mapped.
//
// Descriptor map (from the PE delay-load directory at 0x019DD4F0):
//   ndac.dll       IAT @ 0x01A54474  (26 ordinal imports)
//   Assist.dll     IAT @ 0x01A54378
//   TqNDProtect.dll IAT @ 0x01A54448 (3 imports)  -- patched below
//   (unnamed)      IAT @ 0x01A54384
//   RecordGame.dll IAT @ 0x01A54340
//
// We neutralize ndac.dll + Assist.dll too: they are the anti-cheat family
// (ndac.dll = 18MB VMProtect "ND" anti-cheat). Slot values are POINTERS to
// the stubs below, not stub bytes.

const DWORD kInitSlotRva    = 0x01A54448;   // TQNDP_Initialize
const DWORD kDestroySlotRva = 0x01A5444C;   // TQNDP_Destroy
const DWORD kTokenSlotRva   = 0x01A54450;   // TQNDP_GetPlayerToken

// ndac.dll / Assist.dll slot tables (RVA base + index*4). We blanket the whole
// range; every slot gets the same generic stub (xor eax,eax; ret) because the
// imports are by-ordinal and callers tolerate a NULL/0 result.
const DWORD kNdacIatRva   = 0x01A54474;
const DWORD kNdacSlots    = 26;
const DWORD kAssistIatRva = 0x01A54378;
const DWORD kAssistSlots  = 10;

// __cdecl stubs (machine code) living in our DLL's .text. Each returns a
// benign value and does NOT clean the stack (callers pop their own args).
__declspec(align(16)) BYTE stub_TQNDP_Initialize[]     = { 0xB0, 0x01, 0xC3, 0x90, 0x90, 0x90 }; // mov al,1; ret
__declspec(align(16)) BYTE stub_TQNDP_Destroy[]        = { 0x33, 0xC0, 0xC3, 0x90, 0x90, 0x90 }; // xor eax,eax; ret
__declspec(align(16)) BYTE stub_TQNDP_GetPlayerToken[] = { 0x33, 0xC0, 0xC3, 0x90, 0x90, 0x90 }; // xor eax,eax; ret
__declspec(align(16)) BYTE stub_GenericNoop[]          = { 0x33, 0xC0, 0xC3, 0x90, 0x90, 0x90 }; // xor eax,eax; ret

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

    bool ok = true;

    // 1) Neutralize the EXE's debugger/SoftICE checks.
    for (const Patch& p : kExePatches)
    {
        if (!WriteMemory((void*)(imageBase + p.rva), p.data, sizeof(p.data)))
            ok = false;
    }

    // 2) Block TqNDProtect.dll: point its three delay-load IAT slots at our
    //    no-op stubs. The DLL never loads, so its CE watchdog never runs.
    if (!WritePointer(kInitSlotRva,    imageBase, stub_TQNDP_Initialize))
        ok = false;
    if (!WritePointer(kDestroySlotRva, imageBase, stub_TQNDP_Destroy))
        ok = false;
    if (!WritePointer(kTokenSlotRva,   imageBase, stub_TQNDP_GetPlayerToken))
        ok = false;

    // 3) Block ndac.dll (VMProtect anti-cheat) + Assist.dll by filling their
    //    whole delay-load IAT with a generic no-op stub.
    for (DWORD i = 0; i < kNdacSlots; ++i)
    {
        if (!WritePointer(kNdacIatRva + i * 4, imageBase, stub_GenericNoop))
            ok = false;
    }
    for (DWORD i = 0; i < kAssistSlots; ++i)
    {
        if (!WritePointer(kAssistIatRva + i * 4, imageBase, stub_GenericNoop))
            ok = false;
    }

    return ok;
}
