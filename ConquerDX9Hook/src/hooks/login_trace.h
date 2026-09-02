#pragma once

void LogLogin(const char* stage, const char* fmt, ...);
void LogCredentialState(const char* tag);
bool InstallLoginTraceHooks();
void UninstallLoginTraceHooks();