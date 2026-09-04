#pragma once

void LogLogin(const char* stage, const char* fmt, ...);
void LogCredentialState(const char* tag);
bool InstallLoginTraceHooks();
void UninstallLoginTraceHooks();
// Recv-loop logging is verbose: gated by this flag (auto_login sets it from
// the per-frame state: on at the login screen, off in game). Debug only.
void SetLoginTraceVerbose(bool v);