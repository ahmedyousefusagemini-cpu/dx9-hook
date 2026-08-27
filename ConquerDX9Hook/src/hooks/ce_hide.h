#pragma once

// Hides Cheat Engine from the game's anti-cheat (ndac.dll) by hooking the
// Windows APIs ndac uses for detection:
//   - EnumProcesses / CreateToolhelp32Snapshot + Process32*  -> CE process hidden
//   - FindWindowA / FindWindowExA                             -> CE window hidden
//   - GetModuleBaseNameW                                      -> CE module hidden
//
// This is memory-only and does not change any file. CE is filtered by process
// name / window class containing "cheat" (case-insensitive).
//
// Call InstallCeHideHooks() after MinHook is initialized (from the hook thread).

bool InstallCeHideHooks();
