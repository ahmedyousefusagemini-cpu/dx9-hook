#pragma once

// Disables the game's anti-debug / anti-Cheat-Engine protections in memory
// (the EXE file on disk is never touched):
//
//  1. Conquer.exe login-dialog init: neutralizes the 4x SoftICE device probes
//     and the IsDebuggerPresent() check that would call CDialog::EndDialog()
//     and close the game the moment a debugger (or Cheat Engine) attaches.
//
//  2. TqNDProtect.dll: the game delay-loads this self-decrypting anti-cheat
//     through three IAT slots. We redirect those slots to tiny no-op stubs so
//     the DLL is never loaded at all -> its CE detector (which lives in a
//     runtime-decrypted blob) never executes.
//
// Calling convention of every stub is __cdecl, matching the EXE call sites:
//    TQNDP_Initialize    @ 0042006B  (PUSH arg; CALL; POP ECX) -> AL = result
//    TQNDP_GetPlayerToken @ 01101FE6 (PUSH arg; PUSH arg; CALL; POP; POP)
//    TQNDP_Destroy       @ 0041F2DC  (no args)
//
// Call InstallAntiCheatBypass() early (DLL_PROCESS_ATTACH) so the patches are
// in place before TQNDP_Initialize is ever invoked.

bool InstallAntiCheatBypass();
