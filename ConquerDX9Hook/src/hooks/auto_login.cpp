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
//   server   = DevServer    ; fallback server name (the dialog's own selected
//                            ; realm is used first - see below)
//   account  = MyUser
//   password = MyPass
//
//   [account_1] ...        ; etc
//
// Reverse-engineered chain (verified in Ghidra, client 7937, base 0x400000):
//
//   1. The account-login dialog lives at *(void**)0x01A53980 + 0x39B948
//      (client object at DAT_01a53980; the dispatcher loads that base and the
//      dialog offset in FUN_00a525b4 @0x00a525ec, the Login-button call site
//      @0x00a5b8dd-0x00a5b8fe). The dialog's HWND is at dialog+0x20.
//
//   2. The game itself only invokes the Login handler while the dialog is
//      visible: at 0x00a5b896/0x00a5b8eb it calls FUN_00bfee7b(dialog,1) =
//      IsWindow/IsWindowVisible(dialog+0x20) before CALL 0x008a8fba. We gate
//      the auto-submit on the SAME condition. Sending before the dialog is up
//      queues the packet into a dead socket and the client silently drops it
//      (this was the "no login sequence at boot" bug).
//
//   3. The Login button handler (FUN_008a8fba, __fastcall ECX=dialog) reads the
//      typed account/password from two "edit" wrapper objects inside the dialog
//      and then calls the actual credential send:
//
//          FUN_0101bfe7(account_cstr, password_obj, serverName_cstr, mode, port)
//
//      - account   : SSO string at dialog+0x13B88 (pair A) or dialog+0x13938
//                    (pair B), selected by the flag byte at dialog+0x13620.
//                    SSO layout: inline data at +0..+0xF, length at +0x14;
//                    length > 0xF means heap (pointer at +0).
//      - password  : wrapper object at dialog+0x13BD0 (A) / +0x13980 (B).
//                    The send reads its length at +0x104 (0x0101c03e, fails
//                    >= 0x81), a count at +0x100 and the ENCRYPTED text at
//                    +0x108 (FUN_00ed335e -> VM ordinals 47/1/65).
//                    The wrapper is CGameInputStr (encryptdata.cpp): text is
//                    XOR-encrypted in place against the wrapper's own +0..0xFF
//                    random key table (set once per boot by the dialog ctor);
//                    the ONLY correct way to fill it is the game's own
//                    SetPassword FUN_00ea1692(ECX=wrapper, text) - it writes
//                    len@+0x104 + encrypted text@+0x108 + terminator@+0x207.
//                    NOTE: passing a plain char* here is WRONG - the send
//                    interprets the pointer as this object and reads
//                    [ptr+0x104] (garbage >= 0x81 -> "invalid Account or Psw"
//                    -> 0xFFFFFFFF). That was the original auto-login bug.
//      - serverName: the dialog's own selected realm string at dialog+0x13628
//                    (c_str of the SSO string; the game uses it verbatim as
//                    arg3 in the non-poker path at 0x008a9039).
//      - port      : atoi(dialog+0x13BB8 SSO string), but only when the int
//                    flag at dialog+0x13BC8 != 0, else 0 (0x008a91b2).
//      - mode 0    = classic account/password (CMsgAccountEx).
//      Returns 0 when the send was queued, 0xFFFFFFFF on local rejection.
//
//   4. After logout/disconnect the game runs FUN_00a37821 (the big
//      "reset and return to account login" routine) which calls
//      FUN_00c3ac82 (CQMain_BackToLogin) from 0x00a37c4f (and 0x00a267da in an
//      unanalyzed region - the hook catches both).
//
// So this module:
//   - passes EVERY game login through unmodified (passthrough hook) - manual
//     logins now work exactly as before; the hook only marks that an attempt
//     is in flight so the auto-submit does not double-fire,
//   - watches FUN_00c3ac82 (back to login) to re-arm for the next auto
//     re-login,
//   - auto-submits once the dialog is visible by writing the configured
//     credentials into the dialog's OWN fields (exactly what typing + clicking
//     Login produces) and calling FUN_0101bfe7 with the game-identical
//     argument shapes.
//
// Known residual: none expected on the password side - the fill calls the
// game's own CGameInputStr::SetPassword (FUN_00ea1692) on the dialog's
// wrapper object, byte-identical to what typing produces. The only field the
// packet hash reads that SetPassword does not touch is the +0x100 count
// (set by the wrapper ctor); if the server still rejects the auto-login while
// a manual login with the same creds works, verify dynamically (compare
// wrapper+0x100 after a manual typing vs. after the auto-fill) and mirror it.
// ============================================================================

namespace AutoLogin
{
	// ------------------------------------------------------------------
	// Native anchors (client 7937). Prologue-verified before hooking.
	// ------------------------------------------------------------------
	// FUN_0101bfe7 - the credential send (gamemain.cpp):
	//   PUSH 0x408; MOV EAX,0x14B2D62; CALL 0x01260F55
	const uintptr_t LOGIN_SEND_ADDRESS = 0x0101BFE7;

	// FUN_00c3ac82 - CQMain_BackToLogin (callers: FUN_00a37821 @ 0x00a37c4f
	// and 0x00a267da).  PUSH 0x16CE374; CALL FUN_0043e5d1
	const uintptr_t BACK_TO_LOGIN_ADDRESS = 0x00C3AC82;

	// Client object + login dialog (see header comment).
	const uintptr_t MAIN_CLIENT_GLOBAL  = 0x01A53980; // DAT_01a53980 (runtime-set)
	const uintptr_t LOGIN_DIALOG_OFFSET = 0x39B948;   // dialog = client + 0x39B948
	const uintptr_t DLG_HWND_OFFSET     = 0x20;       // dialog+0x20 = HWND
	const uintptr_t DLG_PAIR_FLAG       = 0x13620;    // byte != 0 -> pair B
	const uintptr_t DLG_SERVER_NAME     = 0x13628;    // SSO string (selected realm)
	const uintptr_t DLG_PORT_STR        = 0x13BB8;    // SSO string (port text)
	const uintptr_t DLG_PORT_FLAG       = 0x13BC8;    // int != 0 -> use port text
	const uintptr_t DLG_ACCOUNT_A       = 0x13B88;    // SSO strings, 0x48 apart
	const uintptr_t DLG_PASSWORD_A      = 0x13BD0;    // wrapper objects
	const uintptr_t DLG_ACCOUNT_B       = 0x13938;
	const uintptr_t DLG_PASSWORD_B      = 0x13980;
	const uintptr_t SSO_LEN_OFFSET      = 0x14;       // SSO: len > 0xF -> heap ptr at +0

	// FUN_00ea1692 - CGameInputStr::SetPassword (encryptdata.cpp):
	//   __thiscall(ECX = wrapper, stack = plaintext), RET 4. Writes len@+0x104,
	//   XOR-encrypts the text into +0x108 (key = the wrapper's own +0..0xFF
	//   random key table installed by the dialog ctor), terminator@+0x207.
	//   Asserts strlen(text) < 0x100 - caller must truncate.
	const uintptr_t SET_PASSWORD_ADDRESS = 0x00EA1692;
	typedef void(__fastcall* SetPasswordFn)(void* pswObj, void* /*edx_dummy*/, const char* text);

	// cdecl, 5 params; the caller cleans the stack (bare RET at 0x0101C250).
	// NOTE: arg2 is the dialog's password WRAPPER OBJECT, not a char*.
	typedef int (__cdecl* LoginSendFn)(const char* account, void* password, const char* serverInfo, int mode, int port);

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
	bool  g_attemptDone = false;      // a login was sent this cycle (auto or manual)
	bool  g_backToLoginSeen = false;  // we returned to the account screen
	unsigned long g_cycleStartTick = 0;
	unsigned long g_lastAttemptTick = 0;
	int   g_retryCount = 0;
	unsigned long g_submitCount = 0;
	char  g_lastResult[64] = "idle";

	// ------------------------------------------------------------------
	// SSO helpers for the dialog's string fields
	// ------------------------------------------------------------------
	// Layout used by the game's own readers (e.g. 0x008a929f):
	//   obj+0x0..0xF inline data, obj+0x14 = length; length > 0xF -> heap,
	//   the real data is at *(void**)obj.
	static const char* SsoCStr(const void* obj)
	{
		const unsigned char* p = (const unsigned char*)obj;
		if (*(const unsigned long*)(p + SSO_LEN_OFFSET) > 0xF)
			return *(const char**)p;
		return (const char*)p;
	}

	// Writes an inline SSO string (creds are short; longer ones truncate).
	static void SsoSet(void* obj, const char* text)
	{
		unsigned char* p = (unsigned char*)obj;
		size_t n = strlen(text);
		if (n > 0xF)
			n = 0xF;
		memcpy(p, text, n);
		memset(p + n, 0, 0x10 - n);
		*(unsigned long*)(p + SSO_LEN_OFFSET) = (unsigned long)n;
	}

	// The account-login dialog (null when the client object is not up yet).
	static void* GetLoginDialog()
	{
		void* client = *(void**)MAIN_CLIENT_GLOBAL;
		if (!client)
			return nullptr;
		return (unsigned char*)client + LOGIN_DIALOG_OFFSET;
	}

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
int __cdecl HookedLoginSend(const char* account, void* password, const char* serverInfo, int mode, int port)
{
	// Passthrough. The game (or the user's Login click) initiated a login with
	// ITS OWN argument shapes - pass them through untouched. The old version
	// injected ini char* into the password slot, but FUN_0101bfe7 treats arg2
	// as a wrapper object and reads [ptr+0x104] as its length - a char* there
	// is garbage >= 0x81 and the send rejects with "invalid Account or Psw"
	// (0xFFFFFFFF). That is why manual logins showed a wrong password.
	//
	// We only record that an attempt is in flight so the auto-submit does not
	// double-fire while the user is logging in manually.
	if (!AutoLogin::g_attemptDone)
	{
		AutoLogin::g_attemptDone = true;
		strcpy_s(AutoLogin::g_lastResult, "manual login send");
	}
	if (AutoLogin::g_OriginalLoginSend)
		return AutoLogin::g_OriginalLoginSend(account, password, serverInfo, mode, port);
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

	// Gate: the game only submits while the account-login dialog is actually
	// visible (its dispatcher checks IsWindowVisible(dialog+0x20) right before
	// invoking the Login handler). Sending earlier queues the packet into a
	// dead socket and the client silently drops it - the boot "nothing
	// happens" bug.
	void* dialog = AutoLogin::GetLoginDialog();
	if (!dialog || !IsWindowVisible(*(HWND*)((unsigned char*)dialog + AutoLogin::DLG_HWND_OFFSET)))
	{
		if (AutoLogin::g_retryCount == 0)
			strcpy_s(AutoLogin::g_lastResult, "waiting for login screen");
		return;
	}

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

	// Fill the dialog's OWN credential fields - the exact inputs a manual
	// typing + Login click would produce. Pair A/B is chosen by the same flag
	// byte the button handler reads (0x008a91e7).
	unsigned char* dlg = (unsigned char*)dialog;
	unsigned char* accountObj;
	unsigned char* pswObj;
	if (*(unsigned char*)(dlg + AutoLogin::DLG_PAIR_FLAG) != 0)
	{
		accountObj = dlg + AutoLogin::DLG_ACCOUNT_B;
		pswObj     = dlg + AutoLogin::DLG_PASSWORD_B;
	}
	else
	{
		accountObj = dlg + AutoLogin::DLG_ACCOUNT_A;
		pswObj     = dlg + AutoLogin::DLG_PASSWORD_A;
	}

	AutoLogin::SsoSet(accountObj, AutoLogin::g_account);

	// Password: call the game's OWN CGameInputStr::SetPassword on the dialog's
	// wrapper object. It writes len@+0x104, XOR-encrypts the text into +0x108
	// against the wrapper's per-boot key table and nulls +0x207 - byte-identical
	// to what typing produces. Do NOT touch the wrapper's +0..0xFF area by hand
	// (SsoSet would clobber the key table) and do NOT write +0x108 directly
	// (the packet hash expects the encrypted form).
	const char* pswText = AutoLogin::g_password;
	char pswTrunc[0x100];
	if (pswText && strlen(pswText) >= 0x100)
	{
		strncpy_s(pswTrunc, pswText, 0xFF);
		pswTrunc[0xFF] = '\0';
		pswText = pswTrunc;
	}
	if (pswText && *pswText)
	{
		AutoLogin::SetPasswordFn setPsw = (AutoLogin::SetPasswordFn)AutoLogin::SET_PASSWORD_ADDRESS;
		setPsw(pswObj, nullptr, pswText);
	}

	// Realm: the dialog's own selected server name (the game passes exactly
	// this string as arg3 in the non-poker path), ini server as fallback.
	const char* serverName = AutoLogin::SsoCStr(dlg + AutoLogin::DLG_SERVER_NAME);
	if (!serverName || !serverName[0])
		serverName = AutoLogin::g_server;

	// Port argument: replicate the button handler (flag gate + atoi).
	int port = 0;
	if (*(int*)(dlg + AutoLogin::DLG_PORT_FLAG) != 0)
	{
		const char* ps = AutoLogin::SsoCStr(dlg + AutoLogin::DLG_PORT_STR);
		if (ps)
			port = atoi(ps);
	}

	AutoLogin::g_lastAttemptTick = now;
	AutoLogin::g_retryCount++;

	if (AutoLogin::g_OriginalLoginSend)
	{
		// Game-identical call shapes: account as c_str, password as the dialog's
		// wrapper object, server name as char*, mode 0 = classic CMsgAccountEx.
		int ret = AutoLogin::g_OriginalLoginSend(
			AutoLogin::SsoCStr(accountObj),
			pswObj,
			serverName,
			0,
			port);
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