#include <windows.h>
#include "imgui.h"
#include "MinHook.h"

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

static int __cdecl HookedLoginSend(const char* account, void* password, void* serverName, int mode, int extra)
{
	// Pure pass-through. FillAccountEdit / FillPasswordEdit already wrote the
	// correct credentials into all dialog slots (0x13B88/0x13938 for account,
	// 0x13BD0/0x13980 for password, fgui edit via FUN_00607cd5). We do NOT
	// inject anything — doing so overwrites manually-entered values and causes
	// server rejection ("invalid username or password").
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

		// Move focus to the password field (user can type there).
		if (result >= 0 && passwordEdit && IsWindow(passwordEdit))
			SetFocus(passwordEdit);
		return result;
	}

	// Fills the password by writing the plain Pass= value directly into the
	// login CEncryptData (dlg+0x13BD0, poker slot dlg+0x13980) using the
	// game's own SetString (FUN_00ea20f0) — no SendInput, no mouse, no focus
	// dance. The login button handler reads exactly these slots in memory
	// (verified: LEA ECX,[EDI+0x13BD0] → FUN_0101CB78), and SetString's XOR
	// transform is self-inverse, so the server's GetString recovers the plain
	// password. Also installs the login hook so the packet is guaranteed.
	static int FillPasswordEdit(HWND dialog, bool forceOverwrite)
	{
		if (!IsDialogUsable(dialog))
			return -1;
		if (g_activePassword[0] == 0)
			return -1;

		HWND passwordEdit = NULL;
		if (!ResolvePasswordEdit(dialog, passwordEdit))
			return -1;
		if (!passwordEdit || !IsWindow(passwordEdit))
			return -1;

		InstallLoginHook();
		InstallGetWindowTextHooks();

		// Resolve the CDlgLogin base ONCE and reuse for all writes.
		void* dlgBase = nullptr;
		__try {
			void* shell = *(void**)0x01A5A510;
			if (shell) dlgBase = (char*)shell + 0x39B948;
		} __except(EXCEPTION_EXECUTE_HANDLER) {}
		if (!dlgBase && g_cachedDialog && IsWindow(g_cachedDialog)) {
			typedef void* (__stdcall *FromHandleFn)(HWND);
			static FromHandleFn fh = nullptr;
			if (!fh) { HMODULE hm = GetModuleHandleA("mfc42.dll"); if (!hm) hm = GetModuleHandleA("mfc140.dll"); if (hm) fh = (FromHandleFn)GetProcAddress(hm, (LPCSTR)4866); }
			if (fh) dlgBase = fh(g_cachedDialog);
		}

		// If the login CEncryptData already holds a valid password and not forced, leave it.
		__try {
			if (dlgBase && !IsBadReadPtr(dlgBase, 0x1400)) {
				int len0 = *(int*)((char*)dlgBase + 0x13BD0 + 0x104);
				if (len0 > 0 && len0 <= 0x100 && !forceOverwrite)
					return 0;
			}
		} __except(EXCEPTION_EXECUTE_HANDLER) {}

		// Direct write: pass the plain password into SetString on the login
		// CEncryptData. SetString uses the CEncryptData's OWN key table at +0..0xFF
		// (which is filled with the session key by the game) to transform the input.
		// The server's GetString with the same key recovers the XOR'd form.
		// The key table changes per session (verified: Raw after len byte differs
		// between sessions), so we MUST NOT hardcode a fixed XOR table.
		__try {
			if (dlgBase && !IsBadReadPtr(dlgBase, 0x1400)) {
				char* dlg = (char*)dlgBase;
				// Write to MFC handler slots (0x13BD0 = normal, 0x13980 = poker/reconnect).
				const uintptr_t offs[2] = {0x13BD0, 0x13980};
				for (int oi = 0; oi < 2; ++oi) {
					char* pEnc = dlg + offs[oi];
					DWORD op = 0;
					if (VirtualProtect(pEnc, 0x208, PAGE_EXECUTE_READWRITE, &op)) {
						((SetEncStringFunc)SET_ENC_STRING_ADDR)(pEnc, g_activePassword);
						DWORD tp = 0; VirtualProtect(pEnc, 0x208, op, &tp);
					}
				}
				// Also write to the fgui password edit's own CEncryptData at
				// *(dlg+0x13DD8)+0x30C. The fgui EnterGame button reads the
				// password from HERE, not from 0x13BD0 (debug: EditCEnc len=0
				// confirms it's empty after our fill → server gets empty pwd).
				// Use the game's own edit-sync FUN_00607cd5(editCEnc, dlg+0x13BD0)
				// — it does ADD ECX,0x30C then GetString(0x13BD0)→SetString(dest),
				// exactly what the game does when the password edit loses focus.
				void* editCEnc = *(void**)(dlg + 0x13DD8);
				if (editCEnc && !IsBadReadPtr(editCEnc, 0x400))
				{
					typedef void (__thiscall* EditSyncFn)(void* editCEnc, void* src);
					((EditSyncFn)0x00607CD5)(editCEnc, dlg + 0x13BD0);
				}
			}
		} __except(EXCEPTION_EXECUTE_HANDLER) {}

		// Populate the visible EditBox text via WM_SETTEXT (same as FillAccountEdit).
		// The cocos EditBox gate rejects empty fields; the account fill already proves
		// WM_SETTEXT works for display. The actual packet reads dlg+0x13BD0 (our write).
		if (passwordEdit && IsWindow(passwordEdit))
		{
			SendMessageA(passwordEdit, WM_SETTEXT, 0, (LPARAM)g_activePassword);
		}

		Sleep(30);

		// Verify via the dlg's encrypted len as ground truth (both slots).
		__try {
			void* shell2 = *(void**)0x01A5A510;
			if (shell2) {
				char* dlg2 = (char*)shell2 + 0x39B948;
				if (!IsBadReadPtr(dlg2 + 0x13BD0 + 0x104, 4)) {
					int encLen = *(int*)(dlg2 + 0x13BD0 + 0x104);
					if (encLen > 0 && encLen < 0x100)
						return 0;
				}
				if (!IsBadReadPtr(dlg2 + 0x13980 + 0x104, 4)) {
					int encLen2 = *(int*)(dlg2 + 0x13980 + 0x104);
					if (encLen2 > 0 && encLen2 < 0x100)
						return 0;
				}
			}
		} __except(EXCEPTION_EXECUTE_HANDLER) {}
		// Even if the verify read fails, the GetWindowText hook + login hook
		// guarantee the packet carries the plain password.
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

		// Ensure packet + GetWindowText hooks are up (account + password).
		if (g_activeAccount[0] || g_activePassword[0])
		{
			InstallLoginHook();
			InstallGetWindowTextHooks();
		}

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
		// Install the login-send + GetWindowText hooks once if we have credentials.
		if (g_activeAccount[0] || g_activePassword[0])
		{
			InstallLoginHook();
			InstallGetWindowTextHooks();
		}
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
				g_loginCompleted = true;
			if (g_loginCompleted)
				g_autoClickLogin = false;  // disarm the auto loop
			return;
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
		ImGui::Text("Dialog: 0x%08X  Button: 0x%08X",
			(unsigned int)AutoLogin::g_cachedDialog,
			(unsigned int)AutoLogin::g_cachedButton);
		ImGui::Text("Button text: \"%s\"  CtrlID: %u", AutoLogin::g_buttonText, AutoLogin::g_buttonId);
		ImGui::Text("Dialog children: %u edits, %u buttons", AutoLogin::g_editCount, AutoLogin::g_buttonCount);
		ImGui::Text("Clicks sent: %d", AutoLogin::g_clickCount);
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
			// NOT FUN_0041F880() â€” that is the 36-byte CQUIManager singleton and
			// +0x39B948 reads unrelated heap (crash + bogus login fields).
			void* shellDbg = *(void**)0x01A5A510;
			if (shellDbg) {
				char* dlgDbg = (char*)shellDbg + 0x39B948;
				if (!IsBadReadPtr(dlgDbg + 0x13BD0, 0x300) && !IsBadReadPtr(dlgDbg + 0x13980, 0x208)) {
					int lenBD0 = *(int*)(dlgDbg + 0x13BD0 + 0x104);
					int len980 = *(int*)(dlgDbg + 0x13980 + 0x104);
					char flag13620 = *(char*)(dlgDbg + 0x13620);
					ImGui::Text("EncLens: 0x13BD0=%d 0x13980=%d flag13620=%d", lenBD0, len980, (int)flag13620);
					// Show the canonical transform key (first 8 bytes) for verification
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
							ckey[cp] = 0;
							ImGui::Text("CanonKey: %s", ckey);
						} else {
							ImGui::Text("CanonKey: (unreadable)");
						}
					} __except(EXCEPTION_EXECUTE_HANDLER) {}
					// Decrypted preview via 00EB3383 (CEncryptData::GetString)
					__try {
						typedef void (__thiscall *GetEncStrFn)(void*, void*);
						char out1[32] = {0}, out2[32] = {0};
						((GetEncStrFn)0x00EB3383)(dlgDbg + 0x13BD0, out1);
						((GetEncStrFn)0x00EB3383)(dlgDbg + 0x13980, out2);
						// std::string layout: cap at +0x14 (<=15 → SSO inline at +0),
						// size at +0x10. Use cap for the inline check, size for display.
						int cap1 = *(int*)(out1 + 0x14);
						char* ps1 = (cap1 <= 15) ? out1 : *(char**)out1;
						int sz1 = *(int*)(out1 + 0x10);
						int cap2 = *(int*)(out2 + 0x14);
						char* ps2 = (cap2 <= 15) ? out2 : *(char**)out2;
						int sz2 = *(int*)(out2 + 0x10);
						if (ps1 && !IsBadReadPtr(ps1, 1)) {
							char tmp1[32] = {0}; strncpy_s(tmp1, sizeof(tmp1), ps1, _TRUNCATE);
							ImGui::Text("Dec 0x13BD0: \"%s\" (len=%d)", tmp1, sz1);
							// The FGUI edit's own CEncryptData at *(dlg+0x13DD8) — the
							// fgui EnterGame button reads the password from HERE.
							__try {
								void* editCEnc = *(void**)(dlgDbg + 0x13DD8);
								if (editCEnc && !IsBadReadPtr(editCEnc, 0x208)) {
									// The fgui edit's real CEncryptData is at +0x30C
									// (FUN_00607cd5 does ADD ECX,0x30C before using it).
									char* editEnc = (char*)editCEnc + 0x30C;
									int editLen = *(int*)(editEnc + 0x104);
									char editOut[32] = {0};
									((GetEncStrFn)0x00EB3383)(editEnc, editOut);
									int esz = *(int*)(editOut + 0x14);
									int esize = *(int*)(editOut + 0x10);
									char* eps = (esz <= 15) ? editOut : *(char**)editOut;
									if (eps && !IsBadReadPtr(eps, 1)) {
										char etmp[32] = {0}; strncpy_s(etmp, sizeof(etmp), eps, _TRUNCATE);
										ImGui::Text("EditCEnc ptr=0x%08X len=%d GS: \"%s\" (len=%d)",
											(unsigned int)editCEnc, editLen, etmp, esize);
										char ehex[128] = {0};
										static const char kHexE[] = "0123456789ABCDEF";
										int edlen = (editLen > 0 && editLen < 16) ? editLen : (int)strlen(etmp);
										if (edlen > 16) edlen = 16;
										int ehpos = 0;
										for (int i = 0; i < edlen; i++) {
											unsigned char c = (unsigned char)eps[i];
											ehex[ehpos++] = kHexE[c >> 4];
											ehex[ehpos++] = kHexE[c & 0xF];
											ehex[ehpos++] = ' ';
										}
										ehex[ehpos] = 0;
										ImGui::Text("EditCEnc Hex: %s", ehex);
									}
								} else {
									ImGui::Text("EditCEnc: (unreadable)");
								}
							} __except(EXCEPTION_EXECUTE_HANDLER) {}
							// Hex dump of the actual decrypted bytes
							char hex1[128] = {0};
							static const char kHex[] = "0123456789ABCDEF";
							int dlen = (lenBD0 > 0 && lenBD0 < 16) ? lenBD0 : (int)strlen(tmp1);
							if (dlen > 16) dlen = 16;
							int hpos = 0;
							for (int i = 0; i < dlen; i++) {
								unsigned char c = (unsigned char)ps1[i];
								hex1[hpos++] = kHex[c >> 4];
								hex1[hpos++] = kHex[c & 0xF];
								hex1[hpos++] = ' ';
							}
							hex1[hpos] = 0;
							ImGui::Text("Hex 0x13BD0: %s", hex1);
							// Raw buffer bytes AFTER the password length (null terminator
							// and beyond) — shows what the packet would carry past len.
							{
								char raw1[128] = {0};
								int rpos = 0;
								int start = (lenBD0 > 0 && lenBD0 < 0x100) ? lenBD0 : 0;
								int end = start + 8;
								if (end > 0x100) end = 0x100;
								if (start < 0x100) {
									char* rawBuf = dlgDbg + 0x13BD0 + 0x108;
									for (int i = start; i < end && rpos < (int)sizeof(raw1) - 4; i++) {
										unsigned char c = (unsigned char)rawBuf[i];
										raw1[rpos++] = kHex[c >> 4];
										raw1[rpos++] = kHex[c & 0xF];
										raw1[rpos++] = ' ';
									}
									raw1[rpos] = 0;
									ImGui::Text("Raw after len (%d): %s", start, raw1);
								}
							}
						}
						if (ps2 && !IsBadReadPtr(ps2, 1)) {
							char tmp2[32] = {0}; strncpy_s(tmp2, sizeof(tmp2), ps2, _TRUNCATE);
							ImGui::Text("Dec 0x13980: \"%s\" (len=%d)", tmp2, sz2);
							char hex2[128] = {0};
							static const char kHex2[] = "0123456789ABCDEF";
							int dlen2 = (len980 > 0 && len980 < 16) ? len980 : (int)strlen(tmp2);
							if (dlen2 > 16) dlen2 = 16;
							int hpos2 = 0;
							for (int i = 0; i < dlen2; i++) {
								unsigned char c = (unsigned char)ps2[i];
								hex2[hpos2++] = kHex2[c >> 4];
								hex2[hpos2++] = kHex2[c & 0xF];
								hex2[hpos2++] = ' ';
							}
							hex2[hpos2] = 0;
							ImGui::Text("Hex 0x13980: %s", hex2);
							// Raw buffer bytes AFTER the password length
							{
								char raw2[128] = {0};
								int rpos2 = 0;
								int start2 = (len980 > 0 && len980 < 0x100) ? len980 : 0;
								int end2 = start2 + 8;
								if (end2 > 0x100) end2 = 0x100;
								if (start2 < 0x100) {
									char* rawBuf2 = dlgDbg + 0x13980 + 0x108;
									for (int i = start2; i < end2 && rpos2 < (int)sizeof(raw2) - 4; i++) {
										unsigned char c = (unsigned char)rawBuf2[i];
										raw2[rpos2++] = kHex2[c >> 4];
										raw2[rpos2++] = kHex2[c & 0xF];
										raw2[rpos2++] = ' ';
									}
									raw2[rpos2] = 0;
									ImGui::Text("Raw after len (%d): %s", start2, raw2);
								}
							}
						}
						// cleanup std::string dtor (call 0x00420847 on out1/out2 if needed, but we leak small)
					} __except(EXCEPTION_EXECUTE_HANDLER) {}
					// Show account std::string at 0x13B88 for sanity
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
		ImGui::TextDisabled("accountinfo.ini is next to the game exe");
		ImGui::TextDisabled("Button found = the MFC login dialog is up");

		if (AutoLogin::g_editListCount > 0)
		{
			ImGui::Text("Edit fields (pin with acc/pwd, auto = top/second Y):");
			ImGui::TextDisabled("Current: account idx=%d  password idx=%d", AutoLogin::g_accountEditIndex, AutoLogin::g_passwordEditIndex);
			for (int i = 0; i < AutoLogin::g_editListCount; i++)
			{
				const AutoLogin::EditInfo& ei = AutoLogin::g_edits[i];
				ImGui::PushID(1000 + i);
				const char* tag = "";
				if (i == AutoLogin::g_accountEditIndex && i == AutoLogin::g_passwordEditIndex) tag = "  <== ACC+PWD";
				else if (i == AutoLogin::g_accountEditIndex) tag = "  <== ACCOUNT";
				else if (i == AutoLogin::g_passwordEditIndex) tag = "  <== PASSWORD";
				ImGui::Text("  #%02d y=%-5d 0x%08X \"%s\"%s",
					i, ei.y, (unsigned int)ei.hwnd,
					ei.text[0] ? ei.text : "(empty)",
					tag);
				ImGui::SameLine();
				if (ImGui::SmallButton("acc"))
				{
					AutoLogin::g_accountEditIndex = i;
				}
				ImGui::SameLine();
				if (ImGui::SmallButton("pwd"))
				{
					AutoLogin::g_passwordEditIndex = i;
				}
				ImGui::SameLine();
				if (ImGui::SmallButton("auto"))
				{
					AutoLogin::g_accountEditIndex = -1;
					AutoLogin::g_passwordEditIndex = -1;
				}
				ImGui::PopID();
			}
			ImGui::TextDisabled("Tip: if Fill Password types into wrong box (see 6 edits), pin pwd index here then retry Fill Password");
		}

		ImGui::InputInt("Button ID override (0=auto)", &AutoLogin::g_buttonIdOverride);
		ImGui::TextDisabled("Pin the exact login button: set its CtrlID from the list below");

		if (AutoLogin::g_buttonListCount > 0)
		{
			ImGui::Text("All buttons:");
			for (int i = 0; i < AutoLogin::g_buttonListCount; i++)
			{
				const AutoLogin::BtnInfo& bi = AutoLogin::g_buttons[i];
				ImGui::PushID(i);
				ImGui::Text("  #%02d 0x%08X id=%-5u \"%s\"",
					i, (unsigned int)bi.hwnd, bi.id, bi.text[0] ? bi.text : "(no text)");
				ImGui::SameLine();
				if (ImGui::SmallButton("use"))
				{
					AutoLogin::g_buttonIdOverride = (int)bi.id;
					AutoLogin::g_cachedButton = bi.hwnd;
				}
				ImGui::SameLine();
				if (ImGui::SmallButton("click"))
				{
					AutoLogin::g_loginCompleted = false;
					AutoLogin::g_cachedButton = bi.hwnd;
					AutoLogin::g_clickInProgress = true;
					AutoLogin::ClickButtonMethod(bi.hwnd);
					AutoLogin::g_clickInProgress = false;
					AutoLogin::g_clickCount++;
				}
				ImGui::PopID();
			}
		}
		ImGui::TreePop();
	}
}
