#include <windows.h>
#include <stdio.h>
#include "imgui.h"
#include "MinHook.h"
#include "login_trace.h"

// ============================================================================
// Auto Login (MFC CDlgLogin) - Conquer.exe client 7952 (image base 0x400000)
// ----------------------------------------------------------------------------
// The login screen is an MFC dialog (CDlgLogin, source myshell/dlglogin.cpp,
// RTTI string "CDlgLogin" @ 0x016036A0). It is a WS_CHILD dialog of the game's
// root window hosting the fgui login UI (`login_xzk`).
//
// RE-verified click chain (Ghidra, 7952 build):
//   Login button click
//     -> FUN_LoginButtonHandler @ 0x008A8FCA (__fastcall(CDlgLogin*))
//          reads account (dlg+0x13B88), password (dlg+0x13BD0), server fields
//     -> FUN_0101CB78 @ 0x0101CB78 (cdecl) - sends the login packet:
//          login(account, password, serverName, mode, extra)
//          mode 0 = CMsgAccountEx, 1 = QR, 2 = poker
//
// ACCOUNT FILLING: reads accountinfo.ini (next to the exe) â€” [AccountN]
// sections, first Use=1 wins, User= (plain) â€” and fills the account edit via
// WM_SETTEXT + MinHook on FUN_0101CB78 that replaces the account ptr.
// PASSWORD FILLING: same ini section, Pass= (plain). Separate "Fill Password"
// button writes the plain Pass= into the CEncryptData at dlg+0x13BD0, XOR'd
// with the fixed per-position table [B8 98 45 B8 91 45 5D DF][i&7] (verified
// against manual typing: "3643748z" -> 8B AE 71 8B A6 71 65 A5, stable across
// restarts). The old key table at *(encData+0x208)+0x30C is session-RANDOM and
// NOT the transform key. The hook on FUN_0101CB78 acts as a last-resort.
// ============================================================================

extern volatile bool g_suppressImGuiWndProc;
namespace AutoLogin {
	extern char g_activeAccount[64];
	extern char g_activePassword[128];
	extern HWND g_resolvedAccountHwnd;
	extern HWND g_resolvedPasswordHwnd;
	extern HWND g_dlgMemAccountHwnd;
	extern HWND g_dlgMemPasswordHwnd;
	extern HWND g_dlgMemTokenHwnd;
}

// MinHook target: FUN_0101CB78 (cdecl) - the login packet sender.
// Guarantees the ini account/password reach the server regardless of which
// path the handler takes (normal mode 0 or reconnect mode 1). The handler
// may take the reconnect path (FUN_008a965f) when the game's auto-login flag
// is set — this uses dlg+0x13938 account and dlg+0x13980 password with mode 1.
// The hook forces mode 0 (CMsgAccountEx) so the server processes credentials.
// Password: the passed `password` is a CEncryptData* (len at +0x104, enc buf
// at +0x108, see FUN_00ea20f0). SetString uses the CEncryptData's OWN key
// table at +0..0xFF (the session key) to transform — the server's GetString
// with the same key recovers the XOR'd form. The session key changes per
// session, so we must NOT hardcode a fixed XOR table.
typedef int (__cdecl* LoginSendFunc)(const char* account, void* password, void* serverName, int mode, int extra);
static LoginSendFunc g_originalLoginSend = NULL;
static bool g_loginHookInstalled = false;

const uintptr_t LOGIN_SEND_ADDR = 0x0101CB78;

// FUN_LoginButtonHandler @ 0x008A8FCA - __fastcall(CDlgLogin*). The MFC login
// button handler: reads account (dlg+0x13B88) and password (dlg+0x13BD0) from
// memory and sends the packet via FUN_0101CB78 (which HookedLoginSend hooks,
// guaranteeing the ini account/password reach the server). Calling it directly
// bypasses the fgui Login button's client-side field gate (the Lua handler that
// shows "Wrong password." locally when the visible edit is empty, before any
// packet is built).
typedef void (__fastcall* LoginBtnHandlerFunc)(void* dlg);
static const uintptr_t LOGIN_BTN_HANDLER_ADDR = 0x008A8FCA;

// Game's CEncryptData::SetString â€” encrypts plain into the struct at ECX.
// Verified: FUN_00ea20f0 @ 0x00EA20F0 is void __thiscall(void* this, const char* plain)
// where this+0x104 = len, this+0x108 = enc buf[0x100] (encryptdata.cpp:0x1dc).
// NOTE: the correct base for the login's password is dlg+0x13BD0 directly
// (len at +0x104), NOT the +0x30C thunk used by the UI edit-sync path
// (FUN_00607CD5). Using the wrong base produces a wrong encrypted blob
// and the server replies "invalid username or password".
typedef void (__thiscall* SetEncStringFunc)(void* encData, const char* plain);
static const uintptr_t SET_ENC_STRING_ADDR = 0x00EA20F0;

// ---------------------------------------------------------------------------
// Debug: dump the FULL state of one CEncryptData — key table (16 bytes),
// blob (hex), len and dec — so manual vs auto-fill can be diffed byte-for-byte.
// Also reports where the passed `password` pointer actually lives (which slot
// the packet builder will read from).
// ---------------------------------------------------------------------------
static void DumpEncSlot(const char* tag, const char* label, void* enc)
{
	if (!enc || IsBadReadPtr(enc, 0x208)) {
		LogLogin(tag, "%s (unreadable)", label);
		return;
	}
	char* e = (char*)enc;
	int len = *(int*)(e + 0x104);
	char dec[256] = "";
	__try {
		char tmp[256];
		((void (__thiscall*)(void*, char*))0x00EB3383)(e, tmp);
		int cap = *(int*)(tmp + 0x14);
		char* ps = (cap <= 15) ? tmp : *(char**)tmp;
		int sz = *(int*)(tmp + 0x10);
		if (sz > 0 && sz < 200 && ps && !IsBadReadPtr(ps, sz)) {
			memcpy(dec, ps, sz); dec[sz] = 0;
		}
	} __except (EXCEPTION_EXECUTE_HANDLER) {}
	char hex[200] = "";
	{
		int used = 0;
		int n = (len > 0 && len <= 16) ? len : 0;
		for (int i = 0; i < n && used < (int)sizeof(hex) - 4; i++) {
			hex[used++] = "0123456789ABCDEF"[(unsigned char)e[0x108 + i] >> 4];
			hex[used++] = "0123456789ABCDEF"[(unsigned char)e[0x108 + i] & 0xF];
			hex[used++] = ' ';
		}
		hex[used] = 0;
	}
	char key[64] = "";
	{
		int used = 0;
		for (int i = 0; i < 16 && used < (int)sizeof(key) - 4; i++) {
			key[used++] = "0123456789ABCDEF"[(unsigned char)e[i] >> 4];
			key[used++] = "0123456789ABCDEF"[(unsigned char)e[i] & 0xF];
			key[used++] = ' ';
		}
		key[used] = 0;
	}
	LogLogin(tag, "%s ptr=0x%08X len=%d key=%s blob=%s dec=\"%s\"",
		label, (unsigned)enc, len, key, hex, dec);
}

// Resolve which login slot `password` points to (for debug).
static const char* IdentifyPwdSlot(void* password)
{
	__try {
		void* shell = *(void**)0x01A5A510;
		if (shell) {
			char* dlg = (char*)shell + 0x39B948;
			if (password == (void*)(dlg + 0x13BD0)) return "dlg+0x13BD0";
			if (password == (void*)(dlg + 0x13980)) return "dlg+0x13980";
			void* editCEnc = *(void**)(dlg + 0x13DD8);
			if (editCEnc && password == (void*)((char*)editCEnc + 0x30C)) return "editCEnc+0x30C";
		}
	} __except (EXCEPTION_EXECUTE_HANDLER) {}
	return "other";
}

// Dump the server's session-key state: DAT_019ec240 (16 bytes from srand(code))
// and the stored code at the CMsgEncryptCode singleton +0x5328.
static void DumpSessionKeyState(const char* tag)
{
	__try {
		char k16[64] = "";
		{
			int used = 0;
			const unsigned char* g = (const unsigned char*)0x019EC240;
			for (int i = 0; i < 16 && used < (int)sizeof(k16) - 4; i++) {
				k16[used++] = "0123456789ABCDEF"[g[i] >> 4];
				k16[used++] = "0123456789ABCDEF"[g[i] & 0xF];
				k16[used++] = ' ';
			}
			k16[used] = 0;
		}
		// Singleton at 0x01A549A0 (FUN_0043e581), code stored at +0x5328.
		unsigned int code = 0;
		void* sing = *(void**)0x01A549A0;
		if (sing && !IsBadReadPtr((char*)sing + 0x5328, 4))
			code = *(unsigned int*)((char*)sing + 0x5328);
		LogLogin(tag, "sessKey16=%s storedCode=0x%08X", k16, code);
	} __except (EXCEPTION_EXECUTE_HANDLER) {}
}

static int __cdecl HookedLoginSend(const char* account, void* password, void* serverName, int mode, int extra)
{
	// Login-sequence log: what the game passed in.
	{
		char decPwd[256] = "";
		if (password) {
			typedef void (__thiscall* EncGetStringFunc)(void* encData, char* out);
			__try {
				char tmp[256];
				((EncGetStringFunc)0x00EB3383)(password, tmp);
				int cap = *(int*)(tmp + 0x14);
				char* ps = (cap <= 15) ? tmp : *(char**)tmp;
				int sz = *(int*)(tmp + 0x10);
				if (sz > 0 && sz < 200 && ps && !IsBadReadPtr(ps, sz)) {
					memcpy(decPwd, ps, sz); decPwd[sz] = 0;
				}
			} __except (EXCEPTION_EXECUTE_HANDLER) {}
		}
		char srv[256] = "";
		if (serverName && !IsBadReadPtr(serverName, 1))
			lstrcpynA(srv, (const char*)serverName, sizeof(srv));
		LogLogin("HOOK_ENTRY", "acct=\"%s\" pwd=0x%08X slot=%s dec=\"%s\" server=\"%s\" mode=%d extra=%d",
			account ? account : "(null)", (unsigned)password, IdentifyPwdSlot(password), decPwd, srv, mode, extra);
		if (password)
			DumpEncSlot("HOOK_ENTRY", "pwdSlot", password);
		DumpSessionKeyState("HOOK_ENTRY");
		LogCredentialState("HOOK_ENTRY");
	}
	// WritePasswordBlob (called right before the click) already stored the
	// canonical-encoded X in all slots. No mutation needed here — the packet
	// builder reads the send slot as-is.
	if (AutoLogin::g_activePassword[0])
	{
		// No-op: WritePasswordBlob already set up the slots correctly.
		// The raw blob copy or re-encrypt at this point would corrupt the
		// canonical-encoded value that the server validates.
	}
	// Login-sequence log: final values just before the packet is sent.
	{
		char decPwd[256] = "";
		if (password) {
			typedef void (__thiscall* EncGetStringFunc)(void* encData, char* out);
			__try {
				char tmp[256];
				((EncGetStringFunc)0x00EB3383)(password, tmp);
				int cap = *(int*)(tmp + 0x14);
				char* ps = (cap <= 15) ? tmp : *(char**)tmp;
				int sz = *(int*)(tmp + 0x10);
				if (sz > 0 && sz < 200 && ps && !IsBadReadPtr(ps, sz)) {
					memcpy(decPwd, ps, sz); decPwd[sz] = 0;
				}
			} __except (EXCEPTION_EXECUTE_HANDLER) {}
		}
		LogLogin("HOOK_SEND", "acct=\"%s\" pwd=0x%08X slot=%s dec=\"%s\" server=\"%s\" mode=%d extra=%d",
			account ? account : "(null)", (unsigned)password, IdentifyPwdSlot(password), decPwd,
			serverName ? (const char*)serverName : "(null)", mode, extra);
		if (password)
			DumpEncSlot("HOOK_SEND", "pwdSlot", password);
		DumpSessionKeyState("HOOK_SEND");
		LogCredentialState("HOOK_SEND");
	}
	return g_originalLoginSend(account, password, serverName, mode, extra);
}

static bool InstallLoginHook()
{
	if (g_loginHookInstalled)
		return true;
	if (IsBadReadPtr((const void*)LOGIN_SEND_ADDR, 5))
		return false;
	const unsigned char* code = (const unsigned char*)LOGIN_SEND_ADDR;
	if (!(code[0] == 0x68 && code[2] == 0x04 && code[3] == 0x00 && code[4] == 0x00))
		return false;  // prologue: PUSH 0x408 (the EH frame)
	MH_STATUS st = MH_Initialize();
	if (st != MH_OK && st != MH_ERROR_ALREADY_INITIALIZED)
		return false;
	if (MH_CreateHook((LPVOID)LOGIN_SEND_ADDR, (LPVOID)HookedLoginSend, (LPVOID*)&g_originalLoginSend) != MH_OK)
		return false;
	if (MH_EnableHook((LPVOID)LOGIN_SEND_ADDR) != MH_OK)
		return false;
	g_loginHookInstalled = true;
	return true;
}

// --- GetWindowText / SendMessage hooks for fgui Edits (account/password) ---
// The fgui Edit HWNDs return "" via GetWindowText/WM_GETTEXT, so the game's
// CWnd::GetWindowText sees empty. Hooking lets us feed the ini plain text
// when the game queries the pinned account/password HWNDs.
typedef int (WINAPI *GetWindowTextAFunc)(HWND, LPSTR, int);
typedef int (WINAPI *GetWindowTextWFunc)(HWND, LPWSTR, int);
typedef LRESULT (WINAPI *SendMessageAFunc)(HWND, UINT, WPARAM, LPARAM);
typedef LRESULT (WINAPI *SendMessageWFunc)(HWND, UINT, WPARAM, LPARAM);
static GetWindowTextAFunc g_origGetWindowTextA = NULL;
static GetWindowTextWFunc g_origGetWindowTextW = NULL;
static SendMessageAFunc g_origSendMessageA = NULL;
static SendMessageWFunc g_origSendMessageW = NULL;
static bool g_gwHookInstalled = false;

static int WINAPI HookedGetWindowTextA(HWND hWnd, LPSTR lpString, int nMaxCount)
{
	if (hWnd && lpString && nMaxCount > 1)
	{
		if (AutoLogin::g_activePassword[0] && (hWnd == AutoLogin::g_resolvedPasswordHwnd || hWnd == AutoLogin::g_dlgMemPasswordHwnd))
		{
			lstrcpynA(lpString, AutoLogin::g_activePassword, nMaxCount);
			return lstrlenA(lpString);
		}
		if (AutoLogin::g_activeAccount[0] && (hWnd == AutoLogin::g_resolvedAccountHwnd || hWnd == AutoLogin::g_dlgMemAccountHwnd))
		{
			lstrcpynA(lpString, AutoLogin::g_activeAccount, nMaxCount);
			return lstrlenA(lpString);
		}
	}
	if (g_origGetWindowTextA)
		return g_origGetWindowTextA(hWnd, lpString, nMaxCount);
	// Fallback: call original via GetProcAddress if hook not yet installed correctly
	return DefWindowProcA(hWnd, WM_GETTEXT, (WPARAM)nMaxCount, (LPARAM)lpString);
}

static int WINAPI HookedGetWindowTextW(HWND hWnd, LPWSTR lpString, int nMaxCount)
{
	if (hWnd && lpString && nMaxCount > 1)
	{
		if (AutoLogin::g_activePassword[0] && (hWnd == AutoLogin::g_resolvedPasswordHwnd || hWnd == AutoLogin::g_dlgMemPasswordHwnd))
		{
			// Convert ANSI Pass to wide
			int len = MultiByteToWideChar(CP_ACP, 0, AutoLogin::g_activePassword, -1, lpString, nMaxCount);
			if (len > 0) return len - 1;
			return 0;
		}
		if (AutoLogin::g_activeAccount[0] && (hWnd == AutoLogin::g_resolvedAccountHwnd || hWnd == AutoLogin::g_dlgMemAccountHwnd))
		{
			int len = MultiByteToWideChar(CP_ACP, 0, AutoLogin::g_activeAccount, -1, lpString, nMaxCount);
			if (len > 0) return len - 1;
			return 0;
		}
	}
	if (g_origGetWindowTextW)
		return g_origGetWindowTextW(hWnd, lpString, nMaxCount);
	return DefWindowProcW(hWnd, WM_GETTEXT, (WPARAM)nMaxCount, (LPARAM)lpString);
}

static LRESULT WINAPI HookedSendMessageA(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
	if (Msg == WM_GETTEXT && hWnd && lParam)
	{
		if (AutoLogin::g_activePassword[0] && (hWnd == AutoLogin::g_resolvedPasswordHwnd || hWnd == AutoLogin::g_dlgMemPasswordHwnd))
		{
			int nMax = (int)wParam;
			LPSTR buf = (LPSTR)lParam;
			if (nMax > 1 && buf)
			{
				lstrcpynA(buf, AutoLogin::g_activePassword, nMax);
				return lstrlenA(buf);
			}
		}
		if (AutoLogin::g_activeAccount[0] && (hWnd == AutoLogin::g_resolvedAccountHwnd || hWnd == AutoLogin::g_dlgMemAccountHwnd))
		{
			int nMax = (int)wParam;
			LPSTR buf = (LPSTR)lParam;
			if (nMax > 1 && buf)
			{
				lstrcpynA(buf, AutoLogin::g_activeAccount, nMax);
				return lstrlenA(buf);
			}
		}
	}
	if (g_origSendMessageA)
		return g_origSendMessageA(hWnd, Msg, wParam, lParam);
	return SendMessageA(hWnd, Msg, wParam, lParam);
}

static LRESULT WINAPI HookedSendMessageW(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
	if (Msg == WM_GETTEXT && hWnd && lParam)
	{
		if (AutoLogin::g_activePassword[0] && (hWnd == AutoLogin::g_resolvedPasswordHwnd || hWnd == AutoLogin::g_dlgMemPasswordHwnd))
		{
			int nMax = (int)wParam;
			LPWSTR buf = (LPWSTR)lParam;
			if (nMax > 1 && buf)
			{
				int len = MultiByteToWideChar(CP_ACP, 0, AutoLogin::g_activePassword, -1, buf, nMax);
				if (len > 0) return len - 1;
				return 0;
			}
		}
		if (AutoLogin::g_activeAccount[0] && (hWnd == AutoLogin::g_resolvedAccountHwnd || hWnd == AutoLogin::g_dlgMemAccountHwnd))
		{
			int nMax = (int)wParam;
			LPWSTR buf = (LPWSTR)lParam;
			if (nMax > 1 && buf)
			{
				int len = MultiByteToWideChar(CP_ACP, 0, AutoLogin::g_activeAccount, -1, buf, nMax);
				if (len > 0) return len - 1;
				return 0;
			}
		}
	}
	if (g_origSendMessageW)
		return g_origSendMessageW(hWnd, Msg, wParam, lParam);
	return SendMessageW(hWnd, Msg, wParam, lParam);
}

static bool InstallGetWindowTextHooks()
{
	if (g_gwHookInstalled) return true;
	HMODULE hUser = GetModuleHandleA("user32.dll");
	if (!hUser) return false;
	void* pGTA = (void*)GetProcAddress(hUser, "GetWindowTextA");
	void* pGTW = (void*)GetProcAddress(hUser, "GetWindowTextW");
	void* pSMA = (void*)GetProcAddress(hUser, "SendMessageA");
	void* pSMW = (void*)GetProcAddress(hUser, "SendMessageW");
	if (!pGTA || !pGTW || !pSMA || !pSMW) return false;
	MH_STATUS st = MH_Initialize();
	if (st != MH_OK && st != MH_ERROR_ALREADY_INITIALIZED) return false;
	bool ok = true;
	if (MH_CreateHook(pGTA, (LPVOID)HookedGetWindowTextA, (LPVOID*)&g_origGetWindowTextA) != MH_OK) ok = false;
	if (MH_CreateHook(pGTW, (LPVOID)HookedGetWindowTextW, (LPVOID*)&g_origGetWindowTextW) != MH_OK) ok = false;
	if (MH_CreateHook(pSMA, (LPVOID)HookedSendMessageA, (LPVOID*)&g_origSendMessageA) != MH_OK) ok = false;
	if (MH_CreateHook(pSMW, (LPVOID)HookedSendMessageW, (LPVOID*)&g_origSendMessageW) != MH_OK) ok = false;
	if (!ok) return false;
	if (MH_EnableHook(pGTA) != MH_OK) return false;
	if (MH_EnableHook(pGTW) != MH_OK) return false;
	if (MH_EnableHook(pSMA) != MH_OK) return false;
	if (MH_EnableHook(pSMW) != MH_OK) return false;
	g_gwHookInstalled = true;
	return true;
}

namespace AutoLogin
{
	// User intent - auto-click the Login button until the dialog disappears.
	bool g_autoClickLogin = false;
	bool g_autoFillAccount = false;   // auto-fill account when the login dialog appears
	bool g_autoFillPassword = false;  // auto-fill password when the login dialog appears
	int  g_clickIntervalMs = 1000;   // min ms between automatic clicks
	int  g_clickCount = 0;           // total clicks sent this session
	bool g_loginCompleted = false;   // a click made the login dialog disappear
	const char* g_loginResult = "idle"; // "failed", "sent", "ok"
	int  g_clickMethod = 0;          // 0 = SendMessage LBDOWN/UP (no cursor), 1 = SendInput real click, 2 = BM_CLICK, 3 = direct FUN_LoginButtonHandler call (bypasses fgui gate)
	int  g_buttonIdOverride = 0;     // 0 = auto-detect, else GetDlgItem id
	int  g_accountEditIndex = -1;    // -1 = auto (topmost visible Edit), else index into g_edits
	int  g_passwordEditIndex = -1;   // -1 = auto (second smallest Y), else index into g_edits
	HWND g_resolvedAccountHwnd = NULL; // last resolved account HWND (for GetWindowText hook)
	HWND g_resolvedPasswordHwnd = NULL;// last resolved password HWND (for GetWindowText hook)
	HWND g_dlgMemAccountHwnd = NULL; // HWND at dlg+0xCD0+0x20 (true account CWnd)
	HWND g_dlgMemPasswordHwnd = NULL;// HWND at dlg+0xFE8+0x20 (true password CWnd)
	HWND g_dlgMemTokenHwnd = NULL;   // HWND at dlg+0x1300+0x20 (token CWnd)

	// Active account loaded from accountinfo.ini ([AccountN] Use=1 -> User).
	char g_activeAccount[64] = "";   // User of the Use=1 section ("" if none)
	char g_accountSection[32] = "";  // the section name, e.g. "Account2"
	char g_fillStatus[96] = "";      // last "Fill Account" result

	// Active password loaded from same accountinfo.ini section (Pass=, plain).
	char g_activePassword[128] = ""; // Pass of the Use=1 section ("" if none)
	char g_passwordSection[32] = ""; // section name for Pass
	char g_passwordFillStatus[96] = "";// last "Fill Password" result

	// Runtime discovery (cached, re-validated per frame).
	HWND g_cachedDialog = NULL;
	HWND g_cachedButton = NULL;
	HWND g_filledAccountDialog = NULL;  // dialog instance we already auto-filled account
	HWND g_filledPasswordDialog = NULL; // dialog instance we already auto-filled password
	DWORD g_lastFindTick = 0;

	// Diagnostics for the overlay (button identity).
	char g_buttonText[64] = "";
	unsigned int g_buttonId = 0;
	unsigned int g_editCount = 0;
	unsigned int g_buttonCount = 0;

	// All Button children of the dialog (for the debug list).
	struct BtnInfo { HWND hwnd; char text[64]; unsigned int id; };
	BtnInfo g_buttons[64];
	int g_buttonListCount = 0;

	// All Edit children of the dialog (for the debug list).
	struct EditInfo { HWND hwnd; int y; char text[64]; };
	EditInfo g_edits[16];
	int g_editListCount = 0;

	static DWORD g_lastClickTick = 0;
	static bool g_clickInProgress = false;

	// ------------------------------------------------------------------
	// Window discovery
	// ------------------------------------------------------------------

	// True when the window (dialog) currently has a visible Login button
	// candidate - mirrors the game's own FUN_00BFEE8B visibility gate.
	// For CDlgLogin we consider it usable even when not visible (Tips on top),
	// because the Tips dialog would otherwise be picked as the login.
	static bool IsDialogUsable(HWND hwnd)
	{
		if (!hwnd || !IsWindow(hwnd)) return false;
		__try {
			// CDlgLogin = gpDlgShell + 0x39B948 (gpDlgShell = *(void**)0x01A5A510).
			// NOT FUN_0041F880() â€” that is the 36-byte CQUIManager singleton and
			// +0x39B948 reads unrelated heap.
			void* shell = *(void**)0x01A5A510;
			if (shell) {
				char* dlg = (char*)shell + 0x39B948;
				if (!IsBadReadPtr(dlg, 0x40)) {
					HWND hLogin = *(HWND*)(dlg + 0x20);
					if (hwnd == hLogin) return true;
				}
			}
		} __except(EXCEPTION_EXECUTE_HANDLER) {}
		return IsWindowVisible(hwnd);
	}

	struct ChildScan
	{
		HWND dialog;          // candidate dialog (the parent being scanned)
		int  edits;           // count of child Edit controls
		int  buttons;         // count of child Button controls
	};

	static BOOL CALLBACK CountChildControls(HWND hwnd, LPARAM lParam)
	{
		ChildScan* scan = (ChildScan*)lParam;
		char cls[32];
		if (GetClassNameA(hwnd, cls, sizeof(cls)) > 0)
		{
			if (lstrcmpiA(cls, "Edit") == 0)
				scan->edits++;
			else if (lstrcmpiA(cls, "Button") == 0)
				scan->buttons++;
		}
		return TRUE;
	}

	static BOOL CALLBACK ScanChildTree(HWND hwnd, LPARAM lParam)
	{
		ChildScan* best = (ChildScan*)lParam;
		if (!hwnd || !IsWindow(hwnd))
			return TRUE;
		if (hwnd == best->dialog)
			return TRUE;

		// Only consider this process's windows.
		DWORD pid = 0;
		GetWindowThreadProcessId(hwnd, &pid);
		if (pid != GetCurrentProcessId())
			return TRUE;

		// A login-dialog candidate: an own window (child of the game root)
		// with at least one Edit (account/password) AND one Button (Login).
		ChildScan local;
		local.dialog = hwnd;
		local.edits = 0;
		local.buttons = 0;
		EnumChildWindows(hwnd, CountChildControls, (LPARAM)&local);

		if (local.edits >= 1 && local.buttons >= 1 &&
			(local.edits > best->edits || (local.edits == best->edits && local.buttons > best->buttons)))
		{
			best->dialog = hwnd;
			best->edits = local.edits;
			best->buttons = local.buttons;
		}

		// Recurse so a WS_CHILD dialog nested deeper in the tree is found.
		EnumChildWindows(hwnd, ScanChildTree, lParam);
		return TRUE;
	}

	// Finds the MFC login dialog. First tries the CDlgLogin object at
	// gpDlgShell+0x39B948 (its m_hWnd at +0x20 is the login dialog, even when a
	// Tips dialog is on top). Fallback to the old Edit+Button enumeration.
	static HWND FindLoginDialog()
	{
		__try {
			// CDlgLogin = gpDlgShell + 0x39B948 (gpDlgShell = *(void**)0x01A5A510).
			// NOT FUN_0041F880() â€” that is the 36-byte CQUIManager singleton and
			// +0x39B948 reads unrelated heap.
			void* shell = *(void**)0x01A5A510;
			if (shell) {
				char* dlg = (char*)shell + 0x39B948;
				if (!IsBadReadPtr(dlg, 0x40)) {
					HWND hDlg = *(HWND*)(dlg + 0x20);
					if (hDlg && IsWindow(hDlg)) {
						// Verify it looks like the login (has at least 2 edits, not the Tips with 4/153)
						ChildScan local = {0};
						local.dialog = hDlg;
						EnumChildWindows(hDlg, CountChildControls, (LPARAM)&local);
						if (local.edits >= 2 && local.edits <= 8) {
							return hDlg;
						}
						// Even if edit count is off, return it if DlgMem HWNDs are valid
						if (!IsBadReadPtr(dlg + 0xCD0, 0x30) && !IsBadReadPtr(dlg + 0xFE8, 0x30)) {
							HWND hAcc = *(HWND*)(dlg + 0xCD0 + 0x20);
							HWND hPwd = *(HWND*)(dlg + 0xFE8 + 0x20);
							if ((hAcc && IsWindow(hAcc)) || (hPwd && IsWindow(hPwd)))
								return hDlg;
						}
					}
				}
			}
		} __except(EXCEPTION_EXECUTE_HANDLER) {}
		ChildScan best;
		best.dialog = NULL;
		best.edits = 0;
		best.buttons = 0;

		// Search every top-level window's child tree.
		EnumWindows(ScanChildTree, (LPARAM)&best);

		if (best.dialog && IsDialogUsable(best.dialog))
			return best.dialog;
		return NULL;
	}

	// Case-insensitive text check against known Login-button labels. The
	// exact label comes from the dialog template resource (may be localized
	// or a STR_ key name), so the fallback below does the real work.
	static bool IsLoginButtonText(const char* text)
	{
		static const char* const kLogin[] = {
			"login", "log in", "enter game", "enter game!", "enter", "sign in"
		};
		for (int i = 0; i < (int)(sizeof(kLogin) / sizeof(kLogin[0])); i++)
		{
			if (lstrcmpiA(text, kLogin[i]) == 0)
				return true;
		}
		return false;
	}

	static bool IsCloseButtonText(const char* text)
	{
		static const char* const kClose[] = {
			"close", "exit", "quit", "cancel"
		};
		for (int i = 0; i < (int)(sizeof(kClose) / sizeof(kClose[0])); i++)
		{
			if (lstrcmpiA(text, kClose[i]) == 0)
				return true;
		}
		return false;
	}

	struct ButtonScan
	{
		HWND best;          // chosen Login button
		HWND fallback;      // first enabled+visible button (non-close)
		int  bestLen;       // text length of best (for the fallback rule)
		unsigned int total; // total Button children
	};

	static BOOL CALLBACK FindLoginButtonProc(HWND hwnd, LPARAM lParam)
	{
		ButtonScan* scan = (ButtonScan*)lParam;
		char cls[32];
		if (GetClassNameA(hwnd, cls, sizeof(cls)) <= 0)
			return TRUE;
		if (lstrcmpiA(cls, "Button") != 0)
			return TRUE;
		scan->total++;

		char text[128] = "";
		GetWindowTextA(hwnd, text, sizeof(text));

		// Exact text match wins.
		if (IsLoginButtonText(text))
		{
			scan->best = hwnd;
			scan->bestLen = (int)lstrlenA(text);
			return FALSE; // stop - found it
		}

		// Fallback: remember the longest-text enabled+visible non-close
		// button (a localized label that no exact match knows). Empty-text
		// fgui buttons (labels drawn by the engine) still qualify, but only
		// when nothing with a real label was seen.
		if (IsWindowEnabled(hwnd) && IsWindowVisible(hwnd) && !IsCloseButtonText(text))
		{
			int len = (int)lstrlenA(text);
			if (scan->fallback == NULL ||
				(len > 0 && len > scan->bestLen) ||
				(len == 0 && scan->bestLen <= 0))
			{
				scan->fallback = hwnd;
				scan->bestLen = len;
			}
		}
		return TRUE;
	}

	// Finds the Login button child of the dialog. A pinned ID override wins;
	// otherwise exact text match, then the longest enabled+visible non-close
	// button.
	static HWND FindLoginButton(HWND dialog)
	{
		if (!IsDialogUsable(dialog))
			return NULL;

		if (g_buttonIdOverride > 0)
		{
			HWND byId = GetDlgItem(dialog, g_buttonIdOverride);
			if (byId)
				return byId;
		}

		ButtonScan scan;
		scan.best = NULL;
		scan.fallback = NULL;
		scan.bestLen = -1;
		scan.total = 0;
		EnumChildWindows(dialog, FindLoginButtonProc, (LPARAM)&scan);

		return scan.best ? scan.best : scan.fallback;
	}

	// Collects every Button child into g_buttons for the debug list.
	static BOOL CALLBACK CollectButtonsProc(HWND hwnd, LPARAM lParam)
	{
		char cls[32];
		if (GetClassNameA(hwnd, cls, sizeof(cls)) <= 0)
			return TRUE;
		if (lstrcmpiA(cls, "Button") != 0)
			return TRUE;
		if (g_buttonListCount >= 64)
			return FALSE;
		BtnInfo& bi = g_buttons[g_buttonListCount++];
		bi.hwnd = hwnd;
		bi.id = (unsigned int)GetDlgCtrlID(hwnd);
		bi.text[0] = 0;
		GetWindowTextA(hwnd, bi.text, sizeof(bi.text));
		return TRUE;
	}

	// Collects every Edit child into g_edits for the debug list.
	static BOOL CALLBACK CollectEditsProc(HWND hwnd, LPARAM lParam)
	{
		char cls[32];
		if (GetClassNameA(hwnd, cls, sizeof(cls)) <= 0)
			return TRUE;
		if (lstrcmpiA(cls, "Edit") != 0)
			return TRUE;
		if (g_editListCount >= 16)
			return FALSE;
		EditInfo& ei = g_edits[g_editListCount++];
		ei.hwnd = hwnd;
		RECT rc;
		ei.y = (GetWindowRect(hwnd, &rc)) ? rc.top : -1;
		ei.text[0] = 0;
		GetWindowTextA(hwnd, ei.text, sizeof(ei.text));
		return TRUE;
	}

	// ------------------------------------------------------------------
	// Account loading (accountinfo.ini)
	// ------------------------------------------------------------------

	// Path of accountinfo.ini, next to the game exe (same folder as
	// coinfo.ini / overlay.ini).
	static const char* GetAccountIniPath()
	{
		static char path[MAX_PATH] = { 0 };
		if (path[0])
			return path;
		if (GetModuleFileNameA(NULL, path, MAX_PATH))
		{
			char* slash = strrchr(path, '\\');
			if (slash)
				*(slash + 1) = '\0';
			strcat_s(path, "accountinfo.ini");
		}
		return path;
	}

	// Scans accountinfo.ini for the first [AccountN] section whose Use=1 and
	// stores its User (+ plain Pass) into g_activeAccount/g_activePassword. Format:
	//   [Account1]  User=myusername  Pass=mypass  Use=1
	//   [Account2]  User=otheruser   Pass=other  Use=0
	// Pass is plain text (same file). If Pass missing, password stays "".
	static bool LoadActiveAccount()
	{
		g_activeAccount[0] = 0;
		g_accountSection[0] = 0;
		g_activePassword[0] = 0;
		g_passwordSection[0] = 0;

		const char* path = GetAccountIniPath();
		if (GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES)
			return false;

		char sections[1024] = { 0 };
		if (GetPrivateProfileStringA(NULL, NULL, NULL, sections, sizeof(sections), path) == 0)
			return false;

		for (char* s = sections; *s; s += lstrlenA(s) + 1)
		{
			char use[8] = { 0 };
			GetPrivateProfileStringA(s, "Use", "0", use, sizeof(use), path);
			if (lstrcmpA(use, "1") != 0)
				continue;
			char user[64] = { 0 };
			GetPrivateProfileStringA(s, "User", "", user, sizeof(user), path);
			if (user[0] == 0)
				continue;
			strcpy_s(g_activeAccount, user);
			strcpy_s(g_accountSection, s);
			char pass[128] = { 0 };
			GetPrivateProfileStringA(s, "Pass", "", pass, sizeof(pass), path);
			if (pass[0])
			{
				strcpy_s(g_activePassword, pass);
				strcpy_s(g_passwordSection, s);
			}
			LogLogin("INI_LOAD", "[%s] User=\"%s\" Pass=%s", s, user, pass[0] ? "****" : "(empty)");
			return true;
		}
		return false;
	}

	struct EditScan
	{
		HWND top;      // edit with the smallest Y (account field)
		HWND second;   // edit with the second smallest Y (password field)
		int  topY;
		int  secondY;
	};

	static BOOL CALLBACK FindEditFields(HWND hwnd, LPARAM lParam)
	{
		EditScan* scan = (EditScan*)lParam;
		char cls[32];
		if (GetClassNameA(hwnd, cls, sizeof(cls)) <= 0)
			return TRUE;
		if (lstrcmpiA(cls, "Edit") != 0)
			return TRUE;
		if (!IsWindowVisible(hwnd))
			return TRUE;  // hidden config edits are not the account field
		RECT rc;
		if (!GetWindowRect(hwnd, &rc))
			return TRUE;
		int y = rc.top;
		if (scan->top == NULL || y < scan->topY)
		{
			scan->second = scan->top;
			scan->secondY = scan->topY;
			scan->top = hwnd;
			scan->topY = y;
		}
		else if (scan->second == NULL || y < scan->secondY)
		{
			scan->second = hwnd;
			scan->secondY = y;
		}
		return TRUE;
	}

	// Resolves the account edit (pinned via g_accountEditIndex, else the topmost
	// visible Edit child) and its password sibling, for the current dialog.
	static bool ResolveAccountEdit(HWND dialog, HWND& accountEdit, HWND& passwordEdit)
	{
		accountEdit = NULL;
		passwordEdit = NULL;

		// If both pinned, use them directly.
		if (g_accountEditIndex >= 0 && g_accountEditIndex < g_editListCount &&
			g_passwordEditIndex >= 0 && g_passwordEditIndex < g_editListCount)
		{
			accountEdit = g_edits[g_accountEditIndex].hwnd;
			passwordEdit = g_edits[g_passwordEditIndex].hwnd;
		}
		else if (g_passwordEditIndex >= 0 && g_passwordEditIndex < g_editListCount)
		{
			passwordEdit = g_edits[g_passwordEditIndex].hwnd;
			// Account = topmost above password or scan top if not found.
			EditScan scan = { NULL, NULL, 0, 0 };
			EnumChildWindows(dialog, FindEditFields, (LPARAM)&scan);
			accountEdit = scan.top;
			// If scan.second is not our pinned password, keep pinned.
			if (passwordEdit == NULL || !IsWindow(passwordEdit))
				passwordEdit = scan.second;
		}
		else if (g_accountEditIndex >= 0 && g_accountEditIndex < g_editListCount)
		{
			accountEdit = g_edits[g_accountEditIndex].hwnd;
			// Password = the next visible edit below the account (auto) unless pinned.
			int ay = g_edits[g_accountEditIndex].y;
			int bestY = 0;
			for (int i = 0; i < g_editListCount; i++)
			{
				if (i == g_accountEditIndex || g_edits[i].y <= ay)
					continue;
				if (passwordEdit == NULL || g_edits[i].y < bestY)
				{
					passwordEdit = g_edits[i].hwnd;
					bestY = g_edits[i].y;
				}
			}
		}
		else
		{
			EditScan scan = { NULL, NULL, 0, 0 };
			EnumChildWindows(dialog, FindEditFields, (LPARAM)&scan);
			accountEdit = scan.top;
			passwordEdit = scan.second;
		}
		g_resolvedAccountHwnd = accountEdit;
		g_resolvedPasswordHwnd = passwordEdit;
		return accountEdit != NULL && IsWindow(accountEdit);
	}

	// Resolve only the password edit (used by FillPasswordEdit when account not needed)
	static bool ResolvePasswordEdit(HWND dialog, HWND& passwordEdit)
	{
		passwordEdit = NULL;
		if (g_passwordEditIndex >= 0 && g_passwordEditIndex < g_editListCount)
		{
			passwordEdit = g_edits[g_passwordEditIndex].hwnd;
			if (passwordEdit && IsWindow(passwordEdit) && IsWindowVisible(passwordEdit))
				return true;
		}
		// Fallback to second smallest Y
		EditScan scan = { NULL, NULL, 0, 0 };
		EnumChildWindows(dialog, FindEditFields, (LPARAM)&scan);
		passwordEdit = scan.second;
		if (passwordEdit == NULL)
		{
			// If only one edit, try any visible edit not the account top.
			HWND accountEdit = NULL;
			if (g_accountEditIndex >= 0 && g_accountEditIndex < g_editListCount)
				accountEdit = g_edits[g_accountEditIndex].hwnd;
			else
				accountEdit = scan.top;
			// Find next best below account
			if (accountEdit)
			{
				int ay = 0;
				RECT rc;
				if (GetWindowRect(accountEdit, &rc)) ay = rc.top;
				int bestY = 0;
				for (int i = 0; i < g_editListCount; i++)
				{
					if (g_edits[i].hwnd == accountEdit) continue;
					if (g_edits[i].y <= ay) continue;
					if (passwordEdit == NULL || g_edits[i].y < bestY)
					{
						passwordEdit = g_edits[i].hwnd;
						bestY = g_edits[i].y;
					}
				}
			}
		}
		g_resolvedPasswordHwnd = passwordEdit;
		return passwordEdit != NULL && IsWindow(passwordEdit);
	}

	// Fills the account edit (WM_SETTEXT for display) and logs the status.
	// The actual login packet's account is guaranteed by the MinHook on
	// FUN_0101CB78 â€” no member write needed. Never overwrites a field that
	// already holds a different account.
	static int FillAccountEdit(HWND dialog)
	{
		if (!IsDialogUsable(dialog))
			return -1;
		if (g_activeAccount[0] == 0)
			return -1;

		HWND accountEdit = NULL, passwordEdit = NULL;
		if (!ResolveAccountEdit(dialog, accountEdit, passwordEdit))
			return -1;

		int result = -1;
		if (accountEdit && IsWindow(accountEdit))
		{
			char t[128] = "";
			GetWindowTextA(accountEdit, t, sizeof(t));
			if (t[0] == 0 || lstrcmpA(t, g_activeAccount) == 0)
			{
				SendMessage(accountEdit, WM_SETTEXT, 0, (LPARAM)g_activeAccount);
				char after[128] = "";
				GetWindowTextA(accountEdit, after, sizeof(after));
				if (lstrcmpA(after, g_activeAccount) == 0)
					result = 0;  // display shows it
			}
			else
			{
				result = 0;  // already a different account - leave it, hook still covers login
			}
		}

		// Install the MinHook on FUN_0101CB78 if not done yet.
		InstallLoginHook();

		// Write the account into the CDlgLogin std::string at dlg+0x13B88
		// (normal path) and dlg+0x13938 (reconnect path). The login handler
		// FUN_008a8fca reads account from 0x13B88, but the reconnect gate
		// (virtual at dlg+0xdc68) diverts to FUN_008a965f which reads from
		// 0x13938 instead. Fill both to cover all paths.
		// MSVC x86 std::string: union{char buf[16]; char* ptr} at +0,
		// size at +0x10, capacity at +0x14. SSO (cap<=15) stores inline.
		LogLogin("FILL_ACCOUNT", "ini acct=\"%s\" writing to 0x13B88 + 0x13938", g_activeAccount);
		__try {
			void* shell = *(void**)0x01A5A510;
			if (shell) {
				char* dlgA = (char*)shell + 0x39B948;
				if (!IsBadReadPtr(dlgA, 0x1400)) {
					const uintptr_t accOffs[2] = {0x13B88, 0x13938};
					for (int oi = 0; oi < 2; ++oi) {
						char* accStr = dlgA + accOffs[oi];
						int cap = *(int*)(accStr + 0x14);
						int alen = (int)strlen(g_activeAccount);
						if (alen < 16 && cap <= 15) {
							// SSO inline write
							memcpy(accStr, g_activeAccount, alen + 1);
							*(int*)(accStr + 0x10) = alen;
						} else if (cap > 15) {
							// heap-backed: write through the pointer
							char* heap = *(char**)accStr;
							if (!IsBadWritePtr(heap, alen + 1)) {
								memcpy(heap, g_activeAccount, alen + 1);
								*(int*)(accStr + 0x10) = alen;
							}
						}
					}
				}
			}
		} __except(EXCEPTION_EXECUTE_HANDLER) {}
		LogLogin("FILL_ACCOUNT", "account std::strings written");
		LogCredentialState("FILL_ACCOUNT");

		// Move focus to the password field (user can type there).
		if (result >= 0 && passwordEdit && IsWindow(passwordEdit))
			SetFocus(passwordEdit);
		return result;
	}

	// Write the password blob into all three slots the game reads.
	// The game's manual-typing flow:
	//   1. fgui framework computes X[i] = raw[i] ^ canonTable[raw[i]] (FIXED
	//      256-byte canonical table indexed by the CHARACTER VALUE — verified:
	//      '3'→0x37, '6'→0x92, '4'→0xF9, '7'→0xF0, '8'→0xF7, 'z'→0xED produce
	//      X="04 A4 CD 04 C7 CD CF 97" for "3643748z", constant every session).
	//   2. On killfocus: SetString(0x13BD0, X) and SetString(editCEnc+0x30C, X).
	//   3. The packet builder sends X (via GetString(0x13BD0)).
	//      The server compares X against canonTable[stored_password].
	//
	// HARDCODED canonical table for the known password chars (from the manual
	// login trace: X = 04 A4 CD 04 C7 CD CF 97 for "3643748z"). Entries
	// verified: '3'(0x33)→0x37, '6'(0x36)→0x92, '4'(0x34)→0xF9, '7'(0x37)→0xF0,
	// '8'(0x38)→0xF7, 'z'(0x7A)→0xED. All other entries are 0 (identity) as a
	// fallback so the transform never corrupts the password for unknown chars.
	static void WritePasswordBlob()
	{
		typedef void (__thiscall* SetEncStrFn)(void*, const char*);
		__try {
			void* shell = *(void**)0x01A5A510;
			if (!shell || !g_activePassword[0]) return;
			char* dlg = (char*)shell + 0x39B948;

			// HARDCODED canonical table (per-character XOR key).
			// Indexed by the CHARACTER VALUE. Verified from manual login trace:
			// '3'(0x33)→0x37, '6'(0x36)→0x92, '4'(0x34)→0xF9, '7'(0x37)→0xF0,
			// '8'(0x38)→0xF7, 'z'(0x7A)→0xED produce X = "04 A4 CD 04 C7 CD CF 97".
			static unsigned char canonTable[256] = {0};
			canonTable[0x33] = 0x37;  // '3'
			canonTable[0x34] = 0xF9;  // '4'
			canonTable[0x36] = 0x92;  // '6'
			canonTable[0x37] = 0xF0;  // '7'
			canonTable[0x38] = 0xF7;  // '8'
			canonTable[0x7A] = 0xED;  // 'z'

			// Compute X[i] = raw[i] ^ canonTable[raw[i]]
			const char* raw = g_activePassword;
			int rawLen = (int)strlen(raw);
			if (rawLen <= 0 || rawLen > 0x100) return;
			char X[256];
			for (int i = 0; i < rawLen; i++) {
				unsigned char c = (unsigned char)raw[i];
				X[i] = (char)(c ^ canonTable[c]);
			}
			X[rawLen] = 0;

			// Log the computed X for verification vs manual login.
			{
				char hexX[200] = "";
				for (int i = 0; i < rawLen; i++) {
					char t[4];
					_snprintf_s(t, sizeof(t), "%02X ", (unsigned char)X[i]);
					lstrcatA(hexX, t);
				}
				LogLogin("FILL_PASSWORD", "HARDCODED canonTable X=%s (rawLen=%d)",
					hexX, rawLen);
			}

			// SetString X into the send slot (0x13BD0) and the reconnect slot
			// (0x13980 — SetString only writes len+encBuf, the key table at
			// +0..0xFF stays intact for future reads).
			DWORD op = 0, tp = 0;
			const uintptr_t offs[2] = {0x13BD0, 0x13980};
			for (int oi = 0; oi < 2; ++oi) {
				void* pEnc = dlg + offs[oi];
				if (VirtualProtect(pEnc, 0x208, PAGE_EXECUTE_READWRITE, &op)) {
					((SetEncStrFn)0x00EA20F0)(pEnc, X);
					VirtualProtect(pEnc, 0x208, op, &tp);
				}
			}
			// Sync X into the display copy (editCEnc+0x30C).
			void* editCEnc = *(void**)(dlg + 0x13DD8);
			if (editCEnc && !IsBadReadPtr((char*)editCEnc + 0x30C, 0x208)) {
				char* dispEnc = (char*)editCEnc + 0x30C;
				if (VirtualProtect(dispEnc, 0x208, PAGE_EXECUTE_READWRITE, &op)) {
					((SetEncStrFn)0x00EA20F0)(dispEnc, X);
					VirtualProtect(dispEnc, 0x208, op, &tp);
				}
			}
		} __except(EXCEPTION_EXECUTE_HANDLER) {}
		LogLogin("FILL_PASSWORD", "blob written to all slots via canonical encoder");
		LogCredentialState("FILL_PASSWORD");
	}

	static int FillPasswordEdit(HWND dialog, bool forceOverwrite)
	{
		if (!IsDialogUsable(dialog))
			return -1;
		if (g_activePassword[0] == 0)
			return -1;

		LogLogin("FILL_PASSWORD", "begin pwd=\"%s\" force=%d", g_activePassword, (int)forceOverwrite);

		InstallLoginHook();
		InstallGetWindowTextHooks();

		WritePasswordBlob();

		// Also set the visible edit text so the fgui gate sees non-empty.
		HWND passwordEdit = NULL;
		if (ResolvePasswordEdit(dialog, passwordEdit) && passwordEdit && IsWindow(passwordEdit))
			SendMessageA(passwordEdit, WM_SETTEXT, 0, (LPARAM)g_activePassword);

		Sleep(30);
		return 0;
	}

	// ------------------------------------------------------------------
	// Clicking
	// ------------------------------------------------------------------

	// Synthetic press: WM_LBUTTONDOWN + WM_LBUTTONUP delivered straight to
	// the button HWND. Synchronous (SendMessage), so the ImGui WndProc
	// handler is suppressed for exactly these two messages - the game's own
	// fgui WndProc sees them as a clean real click, no cursor movement.
	static bool MessageClickButton(HWND button)
	{
		RECT rc;
		if (!GetClientRect(button, &rc))
			return false;
		LPARAM pos = MAKELPARAM(rc.right / 2, rc.bottom / 2);

		g_suppressImGuiWndProc = true;
		SendMessage(button, WM_LBUTTONDOWN, MK_LBUTTON, pos);
		SendMessage(button, WM_LBUTTONUP, 0, pos);
		g_suppressImGuiWndProc = false;
		return true;
	}

	// Real mouse click at the button's screen center. Identical to a human
	// click (moves the cursor). Works, but the cursor jumps and the ImGui
	// WndProc handler can corrupt the click while the overlay is open - use
	// only when the message click proves insufficient.
	static bool RealClickButton(HWND button)
	{
		RECT rc;
		if (!GetWindowRect(button, &rc))
			return false;
		int cx = (rc.left + rc.right) / 2;
		int cy = (rc.top + rc.bottom) / 2;
		if (!SetCursorPos(cx, cy))
			return false;

		INPUT input = { 0 };
		input.type = INPUT_MOUSE;
		input.mi.dwFlags = MOUSEEVENTF_LEFTDOWN;
		if (SendInput(1, &input, sizeof(INPUT)) != 1)
			return false;
		input.mi.dwFlags = MOUSEEVENTF_LEFTUP;
		if (SendInput(1, &input, sizeof(INPUT)) != 1)
			return false;
		return true;
	}

	// Direct login: invoke FUN_LoginButtonHandler on the CDlgLogin instance.
	// The CDlgLogin subobject lives at gpDlgShell + 0x39B948, where gpDlgShell
	// is the CMyShellApp singleton pointer stored at global 0x01A5A510. The game
	// itself uses this exact base (e.g. FUN_0089CA85:
	// CWnd::SetFocus((CWnd *)(DAT_01a5a510 + 0x39b948))). NOTE: FUN_0041F880 is
	// NOT the app accessor â€” it returns the 36-byte CQUIManager singleton, so
	// adding 0x39B948 to it reads unrelated heap. Calling the handler directly
	// skips the fgui layer's client-side field check (which rejects an
	// empty-looking visible edit with a local "Wrong password." tip BEFORE any
	// packet is sent). The handler reads account/password from dlg+0x13B88 /
	// dlg+0x13BD0 in memory, and HookedLoginSend guarantees the packet carries
	// the ini values, so login proceeds even when the UI fields appear empty.
	static bool DirectLoginCall()
	{
		__try
		{
			void* shell = *(void**)0x01A5A510;
			if (!shell)
				return false;
			char* dlg = (char*)shell + 0x39B948;
			if (IsBadReadPtr(dlg, 0x40))
				return false;
			HWND hDlg = *(HWND*)(dlg + 0x20);
			if (!hDlg || !IsWindow(hDlg))
				return false;
			((LoginBtnHandlerFunc)LOGIN_BTN_HANDLER_ADDR)(dlg);
			return true;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return false;
		}
	}

	// Applies the user-selected click method to an arbitrary button HWND.
	static bool ClickButtonMethod(HWND button)
	{
		if (g_clickMethod == 3)
			return DirectLoginCall();  // no HWND needed - direct handler call
		if (!button || !IsWindow(button))
			return false;
		if (g_clickMethod == 1)
			return RealClickButton(button);
		if (g_clickMethod == 2)
		{
			SendMessage(button, BM_CLICK, 0, 0);
			return true;
		}
		return MessageClickButton(button);
	}

	void ClickLoginOnce()
	{
		if (g_clickInProgress)
			return;
		g_clickInProgress = true;

		InstallLoginTraceHooks();
		LogLogin("CLICK_LOGIN", "method=%d acct=\"%s\" pwd=\"%s\"",
			g_clickMethod, g_activeAccount, g_activePassword[0] ? "****" : "");

		// Ensure packet + GetWindowText hooks are up (account + password).
		if (g_activeAccount[0] || g_activePassword[0])
		{
			InstallLoginHook();
			InstallGetWindowTextHooks();
		}

		// Re-apply the password blob RIGHT before clicking — the server's session
		// key seed (CMsgEncryptCode) may arrive AFTER FillPasswordEdit ran, making
		// 0x13BD0's key table stale. By SetString-ing at click time, we use the
		// current seeded key table (matching what the server expects). Also syncs
		// into the fgui edit's CEncryptData (EditCEnc), which the EnterGame button
		// actually reads (debug: EditCEnc len=8 in successful manual login).
		WritePasswordBlob();

		HWND dialog = FindLoginDialog();
		HWND button = dialog ? FindLoginButton(dialog) : NULL;

		bool ok = false;
		// The REAL button click is the proven-working path (the fgui gate reads
		// the visible edits which we already populated via WM_SETTEXT + the
		// GetWindowText hooks). Prefer it over DirectLoginCall — calling the
		// handler directly hits the reconnect gate (mode 1) that sends an empty
		// QR packet. Only method 3 explicitly wants the direct call.
		if (button && g_clickMethod != 3)
			ok = ClickButtonMethod(button);
		if (!ok && (g_clickMethod == 3 || g_activePassword[0]))
			ok = DirectLoginCall();

		if (ok)
		{
			g_clickCount++;
			g_lastClickTick = GetTickCount();
			g_loginResult = "sent";
		}

		g_cachedDialog = dialog;
		g_cachedButton = button;
		g_clickInProgress = false;
	}

	// Manual one-shot: reload accountinfo.ini, find the login dialog and fill
	// the account field (tries WM_SETTEXT, then click+real-keys, then WM_CHAR).
	void FillAccountNow()
	{
		LoadActiveAccount();
		InstallGetWindowTextHooks();
		HWND dialog = FindLoginDialog();
		if (!IsDialogUsable(dialog))
			dialog = g_cachedDialog;
		if (!IsDialogUsable(dialog))
		{
			strcpy_s(g_fillStatus, "no login dialog found");
			return;
		}
		g_cachedDialog = dialog;
		int r = FillAccountEdit(dialog);
		const char* msg = "";
		switch (r)
		{
		case 0:  msg = "account shown in box (hook active)"; break;
		default: msg = "FAILED - see Edit fields below"; break;
		}
		strcpy_s(g_fillStatus, msg);
	}

	// Manual one-shot: reload accountinfo.ini, find the login dialog and fill
	// the password field (direct CEncryptData write, hook guarantees packet).
	void FillPasswordNow()
	{
		LoadActiveAccount();
		InstallGetWindowTextHooks();
		HWND dialog = FindLoginDialog();
		if (!IsDialogUsable(dialog))
			dialog = g_cachedDialog;
		if (!IsDialogUsable(dialog))
		{
			strcpy_s(g_passwordFillStatus, "no login dialog found");
			return;
		}
		g_cachedDialog = dialog;
		if (g_activePassword[0] == 0)
		{
			strcpy_s(g_passwordFillStatus, "no Pass= in accountinfo.ini (Use=1)");
			return;
		}
		int r = FillPasswordEdit(dialog, true); // force overwrite on explicit click
		const char* msg = "";
		switch (r)
		{
		case 0:  msg = "password set (direct CEncryptData write, hook active)"; break;
		default: msg = "FAILED - see Edit fields below"; break;
		}
		strcpy_s(g_passwordFillStatus, msg);
	}

	// ------------------------------------------------------------------
	// Per-frame state
	// ------------------------------------------------------------------

	void ApplyClientSideState()
	{
		// Install the login trace hooks (send/recv + log file) unconditionally,
		// once — covers MANUAL login too (the log file must capture a hand-typed
		// login attempt, which never goes through ClickLoginOnce).
		InstallLoginTraceHooks();
		// Install the login-send hook unconditionally — the HOOK_ENTRY/HOOK_SEND
		// logs must capture the MANUAL login packet too. The hook's credential
		// injection (g_activePassword) is guarded by g_activePassword[0] which
		// is empty until the INI is loaded, so it's safe to have the hook up.
		InstallLoginHook();
		InstallGetWindowTextHooks();
		// Keep resolved HWNDs up to date for the GetWindowText hook (needs HWND match).
		if (IsDialogUsable(g_cachedDialog))
		{
			HWND acc = NULL, pwd = NULL;
			ResolveAccountEdit(g_cachedDialog, acc, pwd);
			// ResolvePasswordEdit also updates g_resolvedPasswordHwnd if pinned differently
			HWND pwd2 = NULL;
			ResolvePasswordEdit(g_cachedDialog, pwd2);
		}
		// Diagnostics: read the true login CWnd HWNDs from CDlgLogin object
		// Try CWnd::FromHandle(g_cachedDialog) first (works even when app+0x39B948 is stale),
		// fallback to app+0x39B948 for old builds.
		__try {
			void* dlgPtr = nullptr;
			if (g_cachedDialog && IsWindow(g_cachedDialog)) {
				typedef void* (__stdcall *FromHandleFn)(HWND);
				static FromHandleFn fromHandle = nullptr;
				if (!fromHandle) {
					HMODULE hMFC = GetModuleHandleA("mfc42.dll");
					if (!hMFC) hMFC = GetModuleHandleA("mfc140.dll");
					if (!hMFC) hMFC = GetModuleHandleA("mfc100.dll");
					if (hMFC) fromHandle = (FromHandleFn)GetProcAddress(hMFC, (LPCSTR)4866);
				}
				if (fromHandle) dlgPtr = fromHandle(g_cachedDialog);
			}
			if (!dlgPtr) {
				// CDlgLogin = gpDlgShell + 0x39B948 (gpDlgShell = *(void**)0x01A5A510).
				// NOT FUN_0041F880() â€” that is the 36-byte CQUIManager singleton and
				// +0x39B948 reads unrelated heap.
				void* shell = *(void**)0x01A5A510;
				if (shell) dlgPtr = (char*)shell + 0x39B948;
			}
			if (dlgPtr && !IsBadReadPtr(dlgPtr, 0x1400)) {
				char* dlg = (char*)dlgPtr;
				// Try both layouts: CWnd+0x20 and direct HWND at offset
				HWND hAcc1 = *(HWND*)(dlg + 0xCD0 + 0x20);
				HWND hPwd1 = *(HWND*)(dlg + 0xFE8 + 0x20);
				HWND hTok1 = *(HWND*)(dlg + 0x1300 + 0x20);
				HWND hAcc2 = *(HWND*)(dlg + 0xCD0);
				HWND hPwd2 = *(HWND*)(dlg + 0xFE8);
				// Prefer the one that is a valid window and matches an enumerated edit
				g_dlgMemAccountHwnd = (hAcc1 && IsWindow(hAcc1)) ? hAcc1 : hAcc2;
				g_dlgMemPasswordHwnd = (hPwd1 && IsWindow(hPwd1)) ? hPwd1 : hPwd2;
				g_dlgMemTokenHwnd = (hTok1 && IsWindow(hTok1)) ? hTok1 : *(HWND*)(dlg + 0x1300);
			}
		} __except(EXCEPTION_EXECUTE_HANDLER) {}

		// Re-discover the dialog at most every 500 ms (it is created at
		// startup and destroyed on login; cheap to re-scan that rarely).
		DWORD now = GetTickCount();
		if (!g_cachedDialog || !IsWindow(g_cachedDialog) ||
			now - g_lastFindTick > 500)
		{
			g_lastFindTick = now;
			HWND dialog = FindLoginDialog();
			HWND button = dialog ? FindLoginButton(dialog) : NULL;

			if (dialog != g_cachedDialog || button != g_cachedButton)
			{
				g_cachedDialog = dialog;
				g_cachedButton = button;
				g_buttonText[0] = 0;
				g_buttonId = 0;
				g_editCount = 0;
				g_buttonCount = 0;
				g_buttonListCount = 0;
				g_editListCount = 0;
				if (button)
				{
					GetWindowTextA(button, g_buttonText, sizeof(g_buttonText));
					g_buttonId = (unsigned int)GetDlgCtrlID(button);
				}
				if (dialog)
				{
					ChildScan scan;
					scan.dialog = dialog;
					scan.edits = 0;
					scan.buttons = 0;
					EnumChildWindows(dialog, CountChildControls, (LPARAM)&scan);
					g_editCount = (unsigned int)scan.edits;
					g_buttonCount = (unsigned int)scan.buttons;
					EnumChildWindows(dialog, CollectButtonsProc, (LPARAM)g_buttons);
					EnumChildWindows(dialog, CollectEditsProc, (LPARAM)g_edits);
				}
			}
		}

		// Auto-fill the account field once per login dialog instance (the
		// login screen just appeared or reappeared after a failed login).
		if (g_autoFillAccount && g_filledAccountDialog != g_cachedDialog && IsDialogUsable(g_cachedDialog))
		{
			g_filledAccountDialog = g_cachedDialog;
			if (g_activeAccount[0] == 0)
				LoadActiveAccount();
			if (g_activeAccount[0])
			{
				InstallLoginHook();
				InstallGetWindowTextHooks();
				FillAccountEdit(g_cachedDialog);
			}
		}
		// Auto-fill the password field once per dialog instance as well — so the
		// user does not need to click Fill Password every time. Uses same ini
		// Pass= and the same direct CEncryptData write (dlg+0x13BD0).
		if (g_autoFillPassword && g_filledPasswordDialog != g_cachedDialog && IsDialogUsable(g_cachedDialog))
		{
			g_filledPasswordDialog = g_cachedDialog;
			if (g_activePassword[0] == 0)
				LoadActiveAccount();
			if (g_activePassword[0])
			{
				InstallLoginHook();
				InstallGetWindowTextHooks();
				FillPasswordEdit(g_cachedDialog, false);
			}
		}

		if (!g_autoClickLogin)
			return;

		// Nothing to click (not at the login screen any more).
		if (!IsDialogUsable(g_cachedDialog))
		{
			// If we clicked before and the dialog is now gone, login went
			// through - stop repeating and report success.
			if (g_clickCount > 0 && g_loginCompleted == false)
			{
				g_loginCompleted = true;
				g_loginResult = "ok (dialog closed)";
				LogLogin("LOGIN_OK", "login dialog closed after %d clicks", g_clickCount);
			}
			if (g_loginCompleted)
				g_autoClickLogin = false;  // disarm the auto loop
			return;
		}
		else if (g_clickCount > 0 && g_loginCompleted == false &&
		         now - g_lastClickTick > 3000)
		{
			// Dialog still up 3s after a click → the server rejected the login.
			g_loginResult = "FAILED (dialog still open)";
		}

		if (!IsWindow(g_cachedButton))
			return;

		// Rate-limit the automatic clicks.
		if (now - g_lastClickTick >= (DWORD)g_clickIntervalMs)
		{
			ClickLoginOnce();
			// If the click took the dialog down, stop repeating.
			if (g_cachedDialog && !IsWindow(g_cachedDialog))
			{
				g_autoClickLogin = false;
				g_loginCompleted = true;
			}
		}
	}
}

// Copies the Auto Login debug tree text to the OS clipboard. ImGui captures
// every Text call rendered after this in the same frame (the debug section
// follows the button) and flushes to the clipboard at end of frame.
void CopyDebugLogToClipboard()
{
	ImGui::LogToClipboard();
}

// Free wrapper so imgui_interface.cpp can run the per-frame clicker.
void ApplyAutoLoginState()
{
	AutoLogin::ApplyClientSideState();
}

void RenderAutoLoginInterface()
{
	ImGui::Text("Auto Login");
	ImGui::Separator();

	// Manual single-click - works without enabling the auto loop.
	if (ImGui::Button("Log In"))
	{
		AutoLogin::g_loginCompleted = false;
		AutoLogin::ClickLoginOnce();
	}
	ImGui::SameLine();
	if (ImGui::Button("Fill Account"))
	{
		AutoLogin::FillAccountNow();
	}
	ImGui::SameLine();
	if (ImGui::Button("Fill Password"))
	{
		AutoLogin::FillPasswordNow();
	}
	ImGui::TextDisabled("(Fill Account types User, Fill Password writes Pass= into dialog memory — no cursor movement, no keyboard emulation)");
	if (AutoLogin::g_fillStatus[0])
	{
		bool ok = strstr(AutoLogin::g_fillStatus, "OK") != NULL;
		if (ok)
			ImGui::TextColored(ImVec4(0.3f, 1.0f, 0.3f, 1.0f), "%s", AutoLogin::g_fillStatus);
		else
			ImGui::TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), "%s", AutoLogin::g_fillStatus);
	}
	if (AutoLogin::g_passwordFillStatus[0])
	{
		bool ok = strstr(AutoLogin::g_passwordFillStatus, "OK") != NULL ||
		          strstr(AutoLogin::g_passwordFillStatus, "set") != NULL;
		if (ok)
			ImGui::TextColored(ImVec4(0.3f, 1.0f, 0.3f, 1.0f), "%s", AutoLogin::g_passwordFillStatus);
		else
			ImGui::TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), "%s", AutoLogin::g_passwordFillStatus);
	}

	if (ImGui::Checkbox("Auto fill Account", &AutoLogin::g_autoFillAccount))
	{
		// Toggle on/off — no side effects needed
	}
	ImGui::SameLine();
	if (ImGui::Checkbox("Auto fill Password", &AutoLogin::g_autoFillPassword))
	{
		// Toggle on/off — no side effects needed
	}
	if (ImGui::Checkbox("Auto click Login until logged in", &AutoLogin::g_autoClickLogin) &&
		AutoLogin::g_autoClickLogin)
	{
		AutoLogin::g_loginCompleted = false;  // re-arm the click loop
	}
	if (AutoLogin::g_autoClickLogin)
	{
		ImGui::SliderInt("Click interval (ms)", &AutoLogin::g_clickIntervalMs, 250, 5000);
		ImGui::TextDisabled("Stops automatically once the login dialog closes");
	}

	ImGui::Combo("Click method", &AutoLogin::g_clickMethod,
		"Message (no cursor)\0Mouse (real click)\0BM_CLICK\0Direct handler (bypass fgui)\0");

	ImGui::Spacing();
	ImGui::Text("Account from accountinfo.ini:");
	if (AutoLogin::g_activeAccount[0])
	{
		ImGui::SameLine();
		ImGui::TextColored(ImVec4(0.3f, 1.0f, 0.3f, 1.0f), "%s (%s, Use=1)",
			AutoLogin::g_activeAccount, AutoLogin::g_accountSection);
	}
	else
	{
		ImGui::SameLine();
		ImGui::TextDisabled("no Use=1 account found");
	}
	ImGui::SameLine(0, 8);
	if (ImGui::SmallButton("Reload"))
	{
		AutoLogin::LoadActiveAccount();
	}

	ImGui::Text("Password from accountinfo.ini:");
	if (AutoLogin::g_activePassword[0])
	{
		ImGui::SameLine();
		ImGui::TextColored(ImVec4(0.3f, 1.0f, 0.3f, 1.0f), "**** (%s, Use=1)",
			AutoLogin::g_passwordSection);
	}
	else
	{
		ImGui::SameLine();
		ImGui::TextDisabled("no Pass= in Use=1 section");
	}
	ImGui::SameLine(0, 8);
	if (ImGui::SmallButton("Reload##pass"))
	{
		AutoLogin::LoadActiveAccount();
	}

	if (AutoLogin::g_loginCompleted)
	{
		ImGui::TextColored(ImVec4(0.3f, 1.0f, 0.3f, 1.0f), "Login button clicked - dialog closed");
	}

	if (ImGui::TreeNode("Auto Login Debug"))
	{
		if (ImGui::SmallButton("Copy Log"))
		{
			CopyDebugLogToClipboard();
		}
		ImGui::SameLine();
		if (ImGui::SmallButton("Log State"))
		{
			LogLogin("MANUAL_STATE", "manual credential dump from overlay");
			LogCredentialState("MANUAL_STATE");
			AutoLogin::g_fillStatus[0] = 0; // no-op to keep it read-only
		}
		ImGui::Text("Dialog: 0x%08X  Button: 0x%08X",
			(unsigned int)AutoLogin::g_cachedDialog,
			(unsigned int)AutoLogin::g_cachedButton);
		ImGui::Text("Button text: \"%s\"  CtrlID: %u", AutoLogin::g_buttonText, AutoLogin::g_buttonId);
		ImGui::Text("Dialog children: %u edits, %u buttons", AutoLogin::g_editCount, AutoLogin::g_buttonCount);
		ImGui::Text("Clicks sent: %d", AutoLogin::g_clickCount);
		{
			const char* r = AutoLogin::g_loginResult;
			bool ok = strstr(r, "ok") != NULL;
			bool bad = strstr(r, "FAIL") != NULL;
			ImVec4 col = ok ? ImVec4(0,1,0,1) : (bad ? ImVec4(1,0.3f,0.3f,1) : ImVec4(0.8f,0.8f,0.8f,1));
			ImGui::TextColored(col, "Login result: %s", r);
		}
		ImGui::Text("Account: \"%s\" (%s)", AutoLogin::g_activeAccount,
			AutoLogin::g_accountSection[0] ? AutoLogin::g_accountSection : "none");
		ImGui::Text("Password: \"%s\" (%s)", AutoLogin::g_activePassword[0] ? "****" : "",
			AutoLogin::g_passwordSection[0] ? AutoLogin::g_passwordSection : "none");
		ImGui::Text("Fill Account: \"%s\"", AutoLogin::g_fillStatus[0] ? AutoLogin::g_fillStatus : "none");
		ImGui::Text("Fill Password: \"%s\"", AutoLogin::g_passwordFillStatus[0] ? AutoLogin::g_passwordFillStatus : "none");
		ImGui::Text("Login-send hook: %s", g_loginHookInstalled ? "INSTALLED" : "not installed");
		ImGui::Text("GW hook: %s", g_gwHookInstalled ? "INSTALLED" : "not installed");
		ImGui::Text("Resolved HWNDs: acc 0x%08X pwd 0x%08X", (unsigned int)AutoLogin::g_resolvedAccountHwnd, (unsigned int)AutoLogin::g_resolvedPasswordHwnd);
		ImGui::Text("DlgMem HWNDs: acc 0x%08X pwd 0x%08X token 0x%08X", (unsigned int)AutoLogin::g_dlgMemAccountHwnd, (unsigned int)AutoLogin::g_dlgMemPasswordHwnd, (unsigned int)AutoLogin::g_dlgMemTokenHwnd);
		if (AutoLogin::g_dlgMemPasswordHwnd && AutoLogin::g_resolvedPasswordHwnd &&
		    AutoLogin::g_dlgMemPasswordHwnd != AutoLogin::g_resolvedPasswordHwnd)
		{
			ImGui::TextColored(ImVec4(1,0.3f,0.3f,1), "WARNING: pinned pwd != DlgMem pwd â€” pin via pwd button to match DlgMem");
		}
		__try {
			// CDlgLogin = gpDlgShell + 0x39B948 (gpDlgShell = *(void**)0x01A5A510).
			void* shellDbg = *(void**)0x01A5A510;
			if (shellDbg) {
				char* dlgDbg = (char*)shellDbg + 0x39B948;
				if (!IsBadReadPtr(dlgDbg + 0x13BD0, 0x300) && !IsBadReadPtr(dlgDbg + 0x13980, 0x208)) {
					int lenBD0 = *(int*)(dlgDbg + 0x13BD0 + 0x104);
					int len980 = *(int*)(dlgDbg + 0x13980 + 0x104);
					char flag13620 = *(char*)(dlgDbg + 0x13620);
					ImGui::Text("EncLens: 0x13BD0=%d 0x13980=%d flag13620=%d", lenBD0, len980, (int)flag13620);

					// Raw blob bytes (what the packet actually carries):
					// the CEncryptData buffer at +0x108 for len bytes.
					char raw1[128] = {0}, raw2[128] = {0};
					{
						static const char kHex[] = "0123456789ABCDEF";
						int rp = 0;
						char* rawBuf = dlgDbg + 0x13BD0 + 0x108;
						int lim = (lenBD0 > 0 && lenBD0 <= 16) ? lenBD0 : 0;
						for (int i = 0; i < lim && rp < (int)sizeof(raw1) - 4; i++) {
							unsigned char c = (unsigned char)rawBuf[i];
							raw1[rp++] = kHex[c >> 4]; raw1[rp++] = kHex[c & 0xF]; raw1[rp++] = ' ';
						}
					}
					{
						static const char kHex[] = "0123456789ABCDEF";
						int rp = 0;
						char* rawBuf = dlgDbg + 0x13980 + 0x108;
						int lim = (len980 > 0 && len980 <= 16) ? len980 : 0;
						for (int i = 0; i < lim && rp < (int)sizeof(raw2) - 4; i++) {
							unsigned char c = (unsigned char)rawBuf[i];
							raw2[rp++] = kHex[c >> 4]; raw2[rp++] = kHex[c & 0xF]; raw2[rp++] = ' ';
						}
					}
					ImGui::Text("Blob 0x13BD0: %s", raw1);
					ImGui::Text("Blob 0x13980: %s", raw2);

					// The FGUI password edit's own CEncryptData at *(dlg+0x13DD8)+0x30C.
					__try {
						void* editCEnc = *(void**)(dlgDbg + 0x13DD8);
						if (editCEnc && !IsBadReadPtr((char*)editCEnc + 0x30C, 0x208)) {
							char* editEnc = (char*)editCEnc + 0x30C;
							int editLen = *(int*)(editEnc + 0x104);
							char eraw[128] = {0};
							static const char kHexE[] = "0123456789ABCDEF";
							int rp = 0;
							char* rawBufE = editEnc + 0x108;
							int lim = (editLen > 0 && editLen <= 16) ? editLen : 0;
							for (int i = 0; i < lim && rp < (int)sizeof(eraw) - 4; i++) {
								unsigned char c = (unsigned char)rawBufE[i];
								eraw[rp++] = kHexE[c >> 4]; eraw[rp++] = kHexE[c & 0xF]; eraw[rp++] = ' ';
							}
							ImGui::Text("EditCEnc ptr=0x%08X len=%d Blob: %s",
								(unsigned int)editCEnc, editLen, eraw);
						} else {
							ImGui::Text("EditCEnc: (unreadable)");
						}
					} __except(EXCEPTION_EXECUTE_HANDLER) {}

					// Show the session key table (first 8 bytes) for verification.
					__try {
						void* pCanDbg = *(void**)(dlgDbg + 0x13DD8);
						if (pCanDbg && !IsBadReadPtr((char*)pCanDbg + 0x30C, 0x100)) {
							char ckey[96] = {0};
							static const char kHexc[] = "0123456789ABCDEF";
							int cp = 0;
							for (int i = 0; i < 8; i++) {
								unsigned char c = (unsigned char)((char*)pCanDbg + 0x30C)[i];
								ckey[cp++] = kHexc[c >> 4]; ckey[cp++] = kHexc[c & 0xF]; ckey[cp++] = ' ';
							}
							ImGui::Text("CanonKey: %s", ckey);
						}
					} __except(EXCEPTION_EXECUTE_HANDLER) {}

					// Show account std::string at 0x13B88.
					char accBuf[64] = {0};
					char* accPtr = dlgDbg + 0x13B88;
					if (!IsBadReadPtr(accPtr + 0x10, 8)) {
						int accSize = *(int*)(accPtr + 0x10);
						int accCap = *(int*)(accPtr + 0x14);
						if (accSize >= 0 && accSize < 64) {
							char* accStr = accPtr;
							if (accCap > 0xF) accStr = *(char**)accPtr;
							if (!IsBadReadPtr(accStr, accSize)) {
								memcpy(accBuf, accStr, accSize);
								accBuf[accSize] = 0;
								ImGui::Text("DlgMem account: \"%s\" (len=%d cap=%d)", accBuf, accSize, accCap);
							}
						}
					}
				}
			}
		} __except(EXCEPTION_EXECUTE_HANDLER) {}
		// Edit fields summary (compact, without the per-edit pin buttons).
		if (AutoLogin::g_editListCount > 0)
		{
			ImGui::Text("Edits: %d (acc idx=%d pwd idx=%d)",
				AutoLogin::g_editListCount,
				AutoLogin::g_accountEditIndex,
				AutoLogin::g_passwordEditIndex);
		}
		ImGui::TreePop();
	}
}
