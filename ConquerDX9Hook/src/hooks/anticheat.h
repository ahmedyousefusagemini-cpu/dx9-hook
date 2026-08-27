#pragma once

// Disables the game's anti-debug / anti-Cheat-Engine protections in memory
// (the EXE file on disk is never touched):
//
//  1. Conquer.exe login-dialog init (VA 0x00A227E9): neutralizes the 4x
//     SoftICE device probes and the IsDebuggerPresent() check that would call
//     CDialog::EndDialog() and close the game the moment a debugger (or Cheat
//     Engine) attaches.
//
//  2. TqNDProtect.dll: the game delay-loads this self-decrypting anti-cheat
//     through three IAT slots (VA 0x01A54448/4C/50). We redirect those slots
//     to no-op stubs so the DLL is never loaded at all -> its CE detector
//     (which lives in a runtime-decrypted blob) never executes.
//
//  3. ndac.dll (VMProtect anti-cheat, IAT VA 0x01A54474, 26 ordinal imports)
//     and Assist.dll (process/window monitor, IAT VA 0x01A54378, 15 slots):
//     whole delay-load IAT tables redirected to no-op stubs.
//
// All addresses are stored as RVAs (image base 0x00400000). Stubs are written
// into an executable RWX page at runtime (data arrays are not executable under
// DEP and the game JMPs straight into these addresses).
//
// Calling convention of every stub is __cdecl, matching the EXE call sites:
//    TQNDP_Initialize     @ 0042006B  (PUSH arg; CALL; POP ECX) -> AL = result
//    TQNDP_GetPlayerToken @ 01101FE6  (PUSH arg; PUSH arg; CALL; POP; POP)
//    TQNDP_Destroy        @ 0041F2DC  (no args)
//
// Call InstallAntiCheatBypass() early (DLL_PROCESS_ATTACH) so the patches are
// in place before TQNDP_Initialize is ever invoked.

bool InstallAntiCheatBypass();
