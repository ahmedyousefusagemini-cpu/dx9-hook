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

// ---- TqNDProtect.dll delay-load IAT slots (Conquer.exe .data) ------------
// These three slots are pre-initialized to the per-function delay-load helper
// (00D1ADAC / 00D1ADCD / 013112EE). The thunks do `JMP [slot]`, so the moment
// we overwrite the slot with our stub address the anti-cheat DLL is never
// mapped and its self-decrypting CE detector never runs.
//
// Slot values must be POINTERS to the stubs (below), not the stub bytes.

const DWORD kInitSlotRva    = 0x01A54448;   // TQNDP_Initialize
const DWORD kDestroySlotRva = 0x01A5444C;   // TQNDP_Destroy
const DWORD kTokenSlotRva   = 0x01A54450;   // TQNDP_GetPlayerToken

// __cdecl stubs (machine code) living in our DLL's .text. Each returns a
// benign value and does NOT clean the stack (callers pop their own args).
__declspec(align(16)) BYTE stub_TQNDP_Initialize[]     = { 0xB0, 0x01, 0xC3, 0x90, 0x90, 0x90 }; // mov al,1; ret
__declspec(align(16)) BYTE stub_TQNDP_Destroy[]        = { 0x33, 0xC0, 0xC3, 0x90, 0x90, 0x90 }; // xor eax,eax; ret
__declspec(align(16)) BYTE stub_TQNDP_GetPlayerToken[] = { 0x33, 0xC0, 0xC3, 0x90, 0x90, 0x90 }; // xor eax,eax; ret

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

    return ok;
}
