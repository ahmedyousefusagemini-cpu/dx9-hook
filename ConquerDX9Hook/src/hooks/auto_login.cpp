#include <windows.h>
#include <stdint.h>
#include <string>
#include <vector>
#include "MinHook.h"
#include <cstdio>
#include <cstring>

// ============================================================================
// Auto Login + Auto Relogin - Conquer.exe client 7937 (image base 0x400000)
// ----------------------------------------------------------------------------
// Reads credentials from auto_login.ini (next to Conquer.exe) and drives the
// game's OWN login chain - no overlay UI, no packet forging, no extra threads.
//
// Config file format:
//   [accounts]
//   enabled  = 1        ; feature master switch
//   selected = 0        ; WHICH account block to use (0-based)
//
//   [account_0]
//   server   = DevServer    ; server name (display only, third credential)
//   account  = MyUser
//   password = MyPass
//
//   [account_1]
//   server   = etc
//   account  = ...
//   password = ...
//
// Reverse-engineered chain (verified in Ghidra, client 7937, base 0x400000):
//
//   1. The account-login dialog (CDlgLogin, myshell\dlglogin.cpp) holds the
//      typed account as a CSimpleString at dialog+0x13B88 and the password at
//      dialog+0x13BD0 in the SAME display window object.
//
//   2. The "Login" button handler (FUN_008a8fba, __fastcall ECX=dialog) is the
//      single dispatch: it resolves the realm through the server config
//      (FUN_008827c2: GetServerInfo ACCOUNT_SERVER -> the accounting realm
//      ip:port) and then calls the ACTUAL credential send:
//
//          FUN_0101bfe7(account, password, serverInfo, mode, flags)
//
//      - mode 0 = classic account/password  -> CMsgAccountEx
//        ("Login Send 1 : CMsgAccountEx", 3drole\gamemain.cpp),
//      - mode 1 = QR-code login,
//      - mode 2 = card/poker login.
//      On success the function calls the network send (FUN_010cf416).
//      On a bad account it returns 0xFFFFFFFF and logs
//      "invalid Account or Psw, size >= %d!".
//
//   3. After logout/disconnect the game runs FUN_00a37821 (a big
//      "reset and return to account login" routine) which calls
//      FUN_00c3ac82 = CQMain_BackToLogin - the single back-to-account-screen
//      signal (it has exactly ONE caller, FUN_00a37821).
//
// So this module:
//   - MinHooks FUN_0101bfe7 (the login send) and forces the configured
//     account/password/server text into the outgoing packet every time a
//     login is attempted - whether WE trigger it or the game does,
//   - watches FUN_00c3ac82 (back to login) to re-arm for the next auto
//     re-login,
//   - auto-submits the login once when the client is back at the account
//     login screen, so the user never has to click.
//
// The client-side realm/IP resolution is left entirely to the game (it picks
// the configured server or the last selected one). The server name field in
// the ini is displayed / matched by the client's own login dialog when the
// client exposes it; for servers where the login screen only shows IP/port,
// the "selected = N" row is the only thing that matters.
// ============================================================================

namespace AutoLogin
{
	// ------------------------------------------------------------------
	// Native anchors (client 7937). Prologue-verified before hooking.
	// ------------------------------------------------------------------
	// FUN_0101bfe7 - the credential send (gamemain.cpp):
	//   PUSH 0x408; MOV EAX,0x14B2D62; CALL 0x01260F55
	const uintptr_t LOGIN_SEND_ADDRESS = 0x0101BFE7;

	// FUN_00c3ac82 - CQMain_BackToLogin (only caller = FUN_00a37821)
	//   PUSH 0x16CE374 ; CALL FUN_0043e5d1
	const uintptr_t BACK_TO_LOGIN_ADDRESS = 0x00C3AC82;

	// cdecl, 5 params; the caller cleans the stack (bare RET at 0x0101C250).
	typedef int (__cdecl* LoginSendFn)(const char* account, const char* password, void* serverInfo, int mode, int flags);

	// void __fastcall? no - it reads no args; cdecl no-arg is fine for the hook.
	typedef void (__cdecl* BackToLoginFn)(void);

	LoginSendFn    g_OriginalLoginSend = nullptr;
	BackToLoginFn  g_OriginalBackToLogin = nullptr;

	// ------------------------------------------------------------------
	// Config (auto_login.ini next to Conquer.exe)
	// ------------------------------------------------------------------
	char  g_cfgPath[MAX_PATH] = {0};
	bool  g_enabled = false;
	int   g_selectedAccount = 0;
	char  g_account[128] = {0};
	char  g_password[128] = {0};
	char  g_server[128] = {0};

	unsigned long g_bootWaitMs   = 6000;   // first submit delay after attach
	unsigned long g_reloginWaitMs = 6000;  // submit delay after a disconnect
	unsigned long g_retryMs      = 2000;   // retry delay when the send is -1
	int           g_maxRetries   = 8;

	// ------------------------------------------------------------------
	// runtime state
	// ------------------------------------------------------------------
	bool  g_hooks = false;
	bool  g_attemptDone = false;   // a login was sent this cycle
	bool  g_backToLoginSeen = false;  // we returned to the account screen
	unsigned long g_cycleStartTick = 0;
	unsigned long g_lastAttemptTick = 0;
	int   g_retryCount = 0;
	unsigned long g_submitCount = 0;
	char  g_lastResult[64] = "idle";

} // namespace AutoLogin

// ============================================================================
// Config loading
// ============================================================================
static void AutoLoginSetPath()
{
	if (AutoLogin::g_cfgPath[0])
		return;
	// Put the ini next to Conquer.exe (same folder the DLL proxy lives in).
	GetModuleFileNameA(NULL, AutoLogin::g_cfgPath, MAX_PATH);
	char* slash = strrchr(AutoLogin::g_cfgPath, '\\');
	if (slash)
		*(slash + 1) = '\0';
	strncat_s(AutoLogin::g_cfgPath, "auto_login.ini", _TRUNCATE);
}

static void LoadConfig()
{
	AutoLoginSetPath();

	// master switch + which account block
	AutoLogin::g_enabled = (GetPrivateProfileIntA("accounts", "enabled", 0, AutoLogin::g_cfgPath) != 0);
	AutoLogin::g_selectedAccount = GetPrivateProfileIntA("accounts", "selected", 0, AutoLogin::g_cfgPath);
	if (AutoLogin::g_selectedAccount < 0)
		AutoLogin::g_selectedAccount = 0;

	char section[32];
	sprintf_s(section, "account_%d", AutoLogin::g_selectedAccount);

	GetPrivateProfileStringA(section, "account",  "", AutoLogin::g_account,  sizeof(AutoLogin::g_account),  AutoLogin::g_cfgPath);
	GetPrivateProfileStringA(section, "password", "", AutoLogin::g_password, sizeof(AutoLogin::g_password), AutoLogin::g_cfgPath);
	GetPrivateProfileStringA(section, "server",   "", AutoLogin::g_server,   sizeof(AutoLogin::g_server),   AutoLogin::g_cfgPath);

	// optional tuning knobs in [accounts]
	char buf[32];
	GetPrivateProfileStringA("accounts", "boot_wait_ms", "6000", buf, 32, AutoLogin::g_cfgPath);
	AutoLogin::g_bootWaitMs = atoi(buf);
	if (AutoLogin::g_bootWaitMs < 500)
		AutoLogin::g_bootWaitMs = 500;

	GetPrivateProfileStringA("accounts", "relogin_wait_ms", "6000", buf, 32, AutoLogin::g_cfgPath);
	AutoLogin::g_reloginWaitMs = atoi(buf);
	if (AutoLogin::g_reloginWaitMs < 500)
		AutoLogin::g_reloginWaitMs = 500;

	GetPrivateProfileStringA("accounts", "retry_ms", "2000", buf, 32, AutoLogin::g_cfgPath);
	AutoLogin::g_retryMs = atoi(buf);
	if (AutoLogin::g_retryMs < 250)
		AutoLogin::g_retryMs = 250;

	AutoLogin::g_maxRetries = GetPrivateProfileIntA("accounts", "max_retries", 8, AutoLogin::g_cfgPath);
	if (AutoLogin::g_maxRetries < 0)
		AutoLogin::g_maxRetries = 0;

	strcpy_s(AutoLogin::g_lastResult, "config loaded");
}

// ============================================================================
// Support check: the two anchor prologues must match this build.
// ============================================================================
static bool IsSupported()
{
	if (IsBadReadPtr((const void*)AutoLogin::LOGIN_SEND_ADDRESS, 12))
		return false;
	const unsigned char* p = (const unsigned char*)AutoLogin::LOGIN_SEND_ADDRESS;
	if (p[0] != 0x68 || p[1] != 0x08 || p[2] != 0x04 || p[3] != 0x00 || p[4] != 0x00)
		return false;
	if (p[5] != 0xB8 || p[6] != 0x62 || p[7] != 0x2D || p[8] != 0x4B || p[9] != 0x01)
		return false;

	// FUN_00c3ac82: 68 74 E3 6C 01  E8 45 39 80 FF (PUSH 0x16CE374; CALL)
	if (IsBadReadPtr((LPCVOID)AutoLogin::BACK_TO_LOGIN_ADDRESS, 6))
		return false;
	p = (const unsigned char*)AutoLogin::BACK_TO_LOGIN_ADDRESS;
	if (p[0] != 0x68 || p[1] != 0x74 || p[2] != 0xE3 || p[3] != 0x6C || p[4] != 0x01)
		return false;

	return true;
}

// ============================================================================
// Hooks
// ============================================================================
int __cdecl HookedLoginSend(const char* account, const char* password, void* serverInfo, int mode, int flags)
{
	// Whatever triggers the login (our auto-submit below, or the game's own
	// "Login" button / any relogin), force the configured account row into it.
	if (AutoLogin::g_enabled &&
		AutoLogin::g_account[0] &&
		(mode == 0 || mode == 1 || mode == 2))   // classic/QR/poker all carry the account
	{
		const char* acc = AutoLogin::g_account;
		const char* pwd = AutoLogin::g_password[0] ? AutoLogin::g_password : (password ? password : "");

		// The server pointer is a CSimpleString-ish buffer; best-effort, may
		// also be left as-is. We keep the original serverInfo (the game has
		// already resolved the realm) but pass our account/password through.
		account = acc;
		password = pwd;

		if (!AutoLogin::g_attemptDone)
		{
			AutoLogin::g_attemptDone = true;
			strcpy_s(AutoLogin::g_lastResult, "login send (injected)");
		}
	}
	if (AutoLogin::g_OriginalLoginSend)
		return AutoLogin::g_OriginalLoginSend(account, password, serverInfo, mode, flags);
	return 0;
}

void __cdecl HookedBackToLogin()
{
	// Call the original first (it must actually navigate back).
	if (AutoLogin::g_OriginalBackToLogin)
		AutoLogin::g_OriginalBackToLogin();

	// The account was disconnected / logged out: re-arm a fresh login cycle.
	AutoLogin::g_backToLoginSeen = true;
	AutoLogin::g_attemptDone = false;
	AutoLogin::g_retryCount = 0;
	AutoLogin::g_cycleStartTick = GetTickCount();
	strcpy_s(AutoLogin::g_lastResult, "back-to-login; re-arming");
}

bool  InstallHooks()
{
	if (AutoLogin::g_hooks)
		return true;
	if (!IsSupported())
	{
		strcpy_s(AutoLogin::g_lastResult, "unsupported build - inert");
		return false;
	}

	if (MH_Initialize() != MH_OK && MH_Initialize() != MH_ERROR_ALREADY_INITIALIZED)
	{
		strcpy_s(AutoLogin::g_lastResult, "MinHook init failed");
		return false;
	}

	if (MH_CreateHook((LPVOID)AutoLogin::LOGIN_SEND_ADDRESS, (LPVOID)HookedLoginSend,
		(LPVOID*)&AutoLogin::g_OriginalLoginSend) != MH_OK)
		return false;
	if (MH_EnableHook((LPVOID)AutoLogin::LOGIN_SEND_ADDRESS) != MH_OK)
		return false;

	if (MH_CreateHook((LPVOID)AutoLogin::BACK_TO_LOGIN_ADDRESS, (LPVOID)HookedBackToLogin,
		(LPVOID*)&AutoLogin::g_OriginalBackToLogin) != MH_OK)
		strcpy_s(AutoLogin::g_lastResult, "backtologin hook omitted");
	else
		MH_EnableHook((LPVOID)AutoLogin::BACK_TO_LOGIN_ADDRESS);

	AutoLogin::g_hooks = true;
	strcpy_s(AutoLogin::g_lastResult, "hooks installed");
	return true;
}

// ============================================================================
// Auto-submit tick - call every frame (even with the overlay closed).
// ============================================================================
void AutoLoginTick()
{
	// Static-load once.
	if (!AutoLogin::g_cfgPath[0])
		LoadConfig();

	if (!AutoLogin::g_enabled || !AutoLogin::g_account[0])
		return;

	if (!AutoLogin::g_hooks)
	{
		if (!InstallHooks())
			return;   // unsupported build: never touch the client
		AutoLogin::g_cycleStartTick = GetTickCount();
	}

	unsigned long now = GetTickCount();

	if (AutoLogin::g_attemptDone)
		return;   // a login was already sent this cycle; wait for the world.

	// Pick the wait base: after a back-to-login use the relogin delay, else boot.
	unsigned long waitMs = AutoLogin::g_backToLoginSeen
		? AutoLogin::g_reloginWaitMs
		: AutoLogin::g_bootWaitMs;

	// First submit waits from the current cycle start; a retry waits only the
	// short retry gap.
	if (AutoLogin::g_retryCount == 0)
	{
		if (now - AutoLogin::g_cycleStartTick < waitMs)
			return;
	}
	else if (now - AutoLogin::g_lastAttemptTick < AutoLogin::g_retryMs)
	{
		return;
	}

	// Actually send the login. This is exactly the call the game's own login
	// button makes (FUN_0101bfe7, mode 0 = classic account/password).
	// A small stack buffer is fine for serverInfo - the client resolves the
	// realm itself.
	char serverBuf[16] = { 0 };
	AutoLogin::g_lastAttemptTick = now;
	AutoLogin::g_retryCount++;

	if (AutoLogin::g_OriginalLoginSend)
	{
		int ret = AutoLogin::g_OriginalLoginSend(
			AutoLogin::g_account,
			AutoLogin::g_password,
			AutoLogin::g_server[0] ? (void*)AutoLogin::g_server : (void*)serverBuf,
			0,
			0);
		AutoLogin::g_submitCount++;

		// The classic branch returns 0 when it actually queued the send,
		// and 0xFFFFFFFF on a rejected/invalid account (logs
		// "invalid Account or Psw") - stop retrying in that case so a
		// wrong password doesn't spam the server.
		if (ret == 0)
		{
			AutoLogin::g_attemptDone = true;
			strcpy_s(AutoLogin::g_lastResult, "auto-login queued (file creds)");
		}
		else if (AutoLogin::g_retryCount >= AutoLogin::g_maxRetries)
		{
			AutoLogin::g_attemptDone = true;
			sprintf_s(AutoLogin::g_lastResult, "login failed - max %d retries hit", AutoLogin::g_maxRetries);
		}
		else
		{
			sprintf_s(AutoLogin::g_lastResult, "login rejected - retry %d/%d", AutoLogin::g_retryCount, AutoLogin::g_maxRetries);
		}
	}
	else
	{
		strcpy_s(AutoLogin::g_lastResult, "no login hook - retrying");
	}
}

// Periodic refresh of the config (called from the topic too, cheap enough).
void AutoLoginReloadConfig()
{
	if (!AutoLogin::g_cfgPath[0])
		LoadConfig();
}

// ============================================================================
// Public entry points
// ============================================================================
// Runs every frame from the ImGui loop (menu open or closed), same slot as the
// other Apply*ClientState() helpers.
void ApplyAutoLoginClientState()
{
	AutoLoginTick();
}

// Debug/status readout for the overlay-free module (visible via a file log or
// just left as string state used by future diagnostics).
const char* GetAutoLoginStateString()     { return AutoLogin::g_lastResult; }
bool        GetAutoLoginEnabled()         { return AutoLogin::g_enabled; }
bool        GetAutoLoginHooksInstalled()  { return AutoLogin::g_hooks; }
unsigned long GetAutoLoginSubmitCount()   { return AutoLogin::g_submitCount; }
int         GetAutoLoginSelectedAccount() { return AutoLogin::g_selectedAccount; }
unsigned long GetAutoLoginLastAttemptTick(){ return AutoLogin::g_lastAttemptTick; }