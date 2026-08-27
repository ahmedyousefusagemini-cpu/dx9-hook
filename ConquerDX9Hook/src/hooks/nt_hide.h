#pragma once

// ntdll-level CE hiding + crash logging.
//
// ndac.dll (VMProtect) can enumerate processes/drivers via ntdll directly,
// bypassing kernel32/user32 hooks. These hooks cover the ntdll surface:
//   - NtQuerySystemInformation (SystemProcessInformation / SystemModuleInformation)
//   - NtOpenFile / NtCreateFile  (block \Device\DBK* driver opens)
//
// InstallNtHideHooks() also installs an unhandled-exception filter that logs
// the faulting module + address to hook_init.log, so crash causes stop being
// guesswork.

bool InstallNtHideHooks();
