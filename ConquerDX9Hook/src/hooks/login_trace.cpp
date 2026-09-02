// ============================================================================
// Login Trace Logger - Conquer.exe client 7952 (image base 0x400000)
// ----------------------------------------------------------------------------
// Append-only login-sequence log file ("loginlog.txt" next to the exe).
// Captures the exact wire bytes the client sends (FUN_0126f63a) and receives
// (FUN_0126fa05) so a manual login and an auto-fill login can be diffed
// byte-for-byte to find why the server rejects auto-filled credentials.
//
// Ghidra anchors (verified 7952):
//   FUN_0126f63a @ 0x0126F63A - __thiscall(int* this, char* buf, int len)
//     send loop: while(len>0) send(this[1], buf, len, 0)
//   FUN_0126fa05 @ 0x0126FA05 - __thiscall(int* this, void* handler, int max)
//     receive loop (CMyClientSocket::DoReceive)
//   CEncryptData::GetString @ 0x00EB3383 - __thiscall(void* this, char* out[256])
// ============================================================================

#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include "MinHook.h"

// Send (FUN_0126f63a): __thiscall(this, buf, len) - sends len bytes on socket this[1].
typedef int (__thiscall* SendLoopFunc)(void* thisPtr, char* buf, int len);

// Receive (FUN_0126fa05): __thiscall(this, msgHandler, maxPackets) - receive loop.
typedef void (__thiscall* RecvLoopFunc)(void* thisPtr, void* msgHandler, int maxPackets);

// CEncryptData::GetString - __thiscall(this, out) - decrypts this+0x108 into out.
typedef void (__thiscall* EncGetStringFunc)(void* encData, char* out);

static SendLoopFunc g_origSendLoop = NULL;
static RecvLoopFunc g_origRecvLoop = NULL;
static bool g_sendHookInstalled = false;
static bool g_recvHookInstalled = false;

static HANDLE g_logFile = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION g_logCs;

static const uintptr_t SEND_LOOP_ADDR = 0x0126F63A;
static const uintptr_t RECV_LOOP_ADDR = 0x0126FA05;
static const uintptr_t ENC_GETSTRING_ADDR = 0x00EB3383;

static void HexDump(char* dst, size_t dstLen, const unsigned char* data, int len)
{
	int used = 0;
	for (int i = 0; i < len && used < (int)dstLen - 4; i++) {
		unsigned char c = data[i];
		dst[used++] = "0123456789ABCDEF"[c >> 4];
		dst[used++] = "0123456789ABCDEF"[c & 0xF];
		dst[used++] = ' ';
	}
	dst[used] = 0;
}

void LogLogin(const char* stage, const char* fmt, ...)
{
	InitLogFile();
	if (g_logFile == INVALID_HANDLE_VALUE)
		return;
	EnterCriticalSection(&g_logCs);

	char line[2048];
	char body[1500];
	va_list args;
	va_start(args, fmt);
	_vsnprintf_s(body, sizeof(body), _TRUNCATE, fmt, args);
	va_end(args);

	SYSTEMTIME st;
	GetLocalTime(&st);
	_snprintf_s(line, sizeof(line), _TRUNCATE,
		"%04d-%02d-%02d %02d:%02d:%02d.%03d | %-16s | %s\r\n",
		st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
		stage, body);

	DWORD written = 0;
	__try {
		WriteFile(g_logFile, line, (DWORD)strlen(line), &written, NULL);
		FlushFileBuffers(g_logFile);
	} __except (EXCEPTION_EXECUTE_HANDLER) {}
	LeaveCriticalSection(&g_logCs);
}

static void InitLogFile()
{
	static bool s_init = false;
	if (s_init) return;
	s_init = true;
	InitializeCriticalSection(&g_logCs);

	char path[MAX_PATH];
	DWORD n = GetModuleFileNameA(NULL, path, MAX_PATH);
	if (n == 0 || n >= MAX_PATH) return;
	char* slash = strrchr(path, '\\');
	if (slash) *(slash + 1) = 0;
	lstrcatA(path, "loginlog.txt");

	// 2nd param = 0 -> always create new file per session (fresh diff each run).
	g_logFile = CreateFileA(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (g_logFile != INVALID_HANDLE_VALUE) {
		LogLogin("TRACE_START", "login log opened at %s", path);
	}
}

// Try to decode a CEncryptData* into its plaintext (safe; empty on failure).
static void DecodeEnc(char* out, size_t outLen, void* encData)
{
	out[0] = 0;
	if (!encData || IsBadReadPtr(encData, 0x208))
		return;
	__try {
		char tmp[256];
		((EncGetStringFunc)ENC_GETSTRING_ADDR)(encData, tmp);
		// GetString returns an MSVC SSO std::string: cap at +0x14 (<=15 ->
		// inline at +0), size at +0x10, heap pointer at +0 for longer text.
		int cap = *(int*)(tmp + 0x14);
		int sz = *(int*)(tmp + 0x10);
		const char* ps = (cap <= 15) ? tmp : *(const char**)tmp;
		if (sz > 0 && sz < 200 && ps && !IsBadReadPtr(ps, sz)) {
			memcpy(out, ps, sz);
			out[sz] = 0;
		}
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		out[0] = 0;
	}
}

// The CDlgLogin memory slots (may not exist if the login dialog is closed).
static char* GetDlgBase()
{
	__try {
		void* shell = *(void**)0x01A5A510;
		if (shell && !IsBadReadPtr((char*)shell + 0x39B948, 0x100))
			return (char*)shell + 0x39B948;
	} __except (EXCEPTION_EXECUTE_HANDLER) {}
	return NULL;
}

// Logs the state of all credential slots (account std::strings + CEncryptData).
void LogCredentialState(const char* tag)
{
	char* dlg = GetDlgBase();
	if (!dlg) {
		LogLogin(tag, "(no login dialog)");
		return;
	}
	__try {
		// Account std::strings at 0x13B88 (normal) and 0x13938 (reconnect).
		const uintptr_t accOffs[2] = {0x13B88, 0x13938};
		for (int i = 0; i < 2; i++) {
			char* acc = dlg + accOffs[i];
			if (IsBadReadPtr(acc, 0x18)) continue;
			int size = *(int*)(acc + 0x10);
			int cap = *(int*)(acc + 0x14);
			char* p = acc;
			if (cap > 0xF) p = *(char**)acc;
			char txt[80];
			if (size > 0 && size < 64 && p && !IsBadReadPtr(p, size)) {
				memcpy(txt, p, size); txt[size] = 0;
			} else txt[0] = 0;
			LogLogin(tag, "acct +0x%04X size=%d cap=%d \"%s\"", (unsigned)(accOffs[i] & 0xFFFF), size, cap, txt);
		}

		// Password CEncryptData slots at 0x13BD0 and 0x13980.
		const uintptr_t pwdOffs[2] = {0x13BD0, 0x13980};
		for (int i = 0; i < 2; i++) {
			char* enc = dlg + pwdOffs[i];
			if (IsBadReadPtr(enc, 0x208)) continue;
			int len = *(int*)(enc + 0x104);
			char dec[256];
			DecodeEnc(dec, sizeof(dec), enc);
			char hex[80];
			HexDump(hex, sizeof(hex), (const unsigned char*)(enc + 0x108),
				(len > 0 && len <= 16) ? len : 0);
			char key[32];
			HexDump(key, sizeof(key), (const unsigned char*)enc, 8);
			LogLogin(tag, "pwd +0x%04X len=%d key=%s blob=%s dec=\"%s\"",
				(unsigned)(pwdOffs[i] & 0xFFFF), len, key, hex, dec);
		}

		// The fgui edit's own CEncryptData at *(dlg+0x13DD8)+0x30C.
		void* editCEnc = *(void**)(dlg + 0x13DD8);
		if (editCEnc && !IsBadReadPtr((char*)editCEnc + 0x30C, 0x208)) {
			char* editEnc = (char*)editCEnc + 0x30C;
			int editLen = *(int*)(editEnc + 0x104);
			char dec[256];
			DecodeEnc(dec, sizeof(dec), editEnc);
			LogLogin(tag, "fgui editCEnc ptr=0x%08X len=%d dec=\"%s\"",
				(unsigned)editCEnc, editLen, dec);
		} else {
			LogLogin(tag, "fgui editCEnc (unreadable)");
		}
	} __except (EXCEPTION_EXECUTE_HANDLER) {}
}

static int __thiscall HookedSendLoop(void* thisPtr, char* buf, int len)
{
	if (buf && len > 0) {
		__try {
			if (!IsBadReadPtr(buf, (len < 256) ? len : 256)) {
				char hex[256];
				int showLen = (len < 64) ? len : 64;
				HexDump(hex, sizeof(hex), (const unsigned char*)buf, showLen);
				LogLogin("SEND", "sock=0x%08X len=%d bytes=%s",
					(unsigned)(thisPtr ? *(unsigned*)((char*)thisPtr + 4) : 0), len, hex);
			}
		} __except (EXCEPTION_EXECUTE_HANDLER) {}
	}
	if (g_origSendLoop)
		return g_origSendLoop(thisPtr, buf, len);
	return 0;
}

static void __thiscall HookedRecvLoop(void* thisPtr, void* msgHandler, int maxPackets)
{
	if (g_origRecvLoop)
		g_origRecvLoop(thisPtr, msgHandler, maxPackets);
}

bool InstallLoginTraceHooks()
{
	InitLogFile();

	if (!g_sendHookInstalled) {
		if (IsBadReadPtr((void*)SEND_LOOP_ADDR, 5))
			return false;
		MH_STATUS st = MH_Initialize();
		if (st != MH_OK && st != MH_ERROR_ALREADY_INITIALIZED)
			return false;
		if (MH_CreateHook((LPVOID)SEND_LOOP_ADDR, (LPVOID)HookedSendLoop, (LPVOID*)&g_origSendLoop) == MH_OK &&
			MH_EnableHook((LPVOID)SEND_LOOP_ADDR) == MH_OK) {
			g_sendHookInstalled = true;
			LogLogin("HOOK", "send-loop hook installed (FUN_0126f63a)");
		}
	}

	if (!g_recvHookInstalled) {
		if (IsBadReadPtr((void*)RECV_LOOP_ADDR, 5))
			return false;
		MH_STATUS st = MH_Initialize();
		if (st != MH_OK && st != MH_ERROR_ALREADY_INITIALIZED)
			return false;
		if (MH_CreateHook((LPVOID)RECV_LOOP_ADDR, (LPVOID)HookedRecvLoop, (LPVOID*)&g_origRecvLoop) == MH_OK &&
			MH_EnableHook((LPVOID)RECV_LOOP_ADDR) == MH_OK) {
			g_recvHookInstalled = true;
			LogLogin("HOOK", "recv-loop hook installed (FUN_0126fa05)");
		}
	}

	return g_sendHookInstalled || g_recvHookInstalled;
}

void UninstallLoginTraceHooks()
{
	if (g_sendHookInstalled && g_origSendLoop) {
		MH_DisableHook((LPVOID)SEND_LOOP_ADDR);
		g_sendHookInstalled = false;
	}
	if (g_recvHookInstalled && g_origRecvLoop) {
		MH_DisableHook((LPVOID)RECV_LOOP_ADDR);
		g_recvHookInstalled = false;
	}
}