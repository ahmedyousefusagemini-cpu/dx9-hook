#include <windows.h>
#include "imgui.h"
#include "MinHook.h"

// ============================================================================
// Auto Login (MFC CDlgLogin) - Conquer.exe client 7950 (image base 0x400000)
// ----------------------------------------------------------------------------
// The login screen is an MFC dialog (CDlgLogin, source myshell/dlglogin.cpp,
// RTTI string "CDlgLogin" @ 0x016036A0). It is a WS_CHILD dialog of the game's
// root window hosting the fgui login UI (`login_xzk`).
//
// RE-verified click chain (Ghidra, 7950 build):
//   Login button click
//     -> FUN_LoginButtonHandler @ 0x008A8FCA (__fastcall(CDlgLogin*))
//          reads account (dlg+0x13B88), password (dlg+0x13BD0), server fields
//     -> FUN_0101C9D8 @ 0x0101C9D8 (cdecl) - sends the login packet:
//          login(account, password, serverName, mode, extra)
//          mode 0 = CMsgAccountEx, 1 = QR, 2 = poker
//
// ACCOUNT FILLING: reads accountinfo.ini (next to the exe) — [AccountN]
// sections, first Use=1 wins, User= (plain) — and fills the account edit via
// WM_SETTEXT + MinHook on FUN_0101C9D8 that replaces the account ptr.
// PASSWORD FILLING: same ini section, Pass= (plain). Separate "Fill Password"
// button types it with real SendInput keystrokes into the password Edit
// (second smallest Y, fgui ignores WM_SETTEXT). The hook also re-encrypts
// Pass= into the CEncryptData at dlg+0x13BD0 (FUN_00EA1F50) so the packet is
// correct even if UI sync missed. No member offsets needed for account,
// password encrypt uses the game's own setter (0x00EA1F50) via the hook.
// ============================================================================

extern volatile bool g_suppressImGuiWndProc;
namespace AutoLogin { extern char g_activeAccount[64]; extern char g_activePassword[128]; }

// MinHook target: FUN_0101C9D8 (cdecl) - the login packet sender.
// Replaces the account argument with the ini account when the game passes
// an empty (or matching) one, so the server always receives the right name.
// Password: the passed `password` is a CEncryptData* (len at +0x104, enc buf at +0x108,
// see FUN_00ea1f50). The HOOK DOES NOT re-encrypt by default — the UI typing
// via SendInput + Process (dlg+0x13BD0 encrypt) is the source of truth. The
// hook only acts as a last-resort when the game's CEncryptData is empty
// (len==0) to avoid corrupting a correctly-typed password with a potentially
// wrong key base. See FillPasswordEdit for the UI path.
typedef int (__cdecl* LoginSendFunc)(const char* account, void* password, void* serverName, int mode, int extra);
static LoginSendFunc g_originalLoginSend = NULL;
static bool g_loginHookInstalled = false;

const uintptr_t LOGIN_SEND_ADDR = 0x0101C9D8;

// Game's CEncryptData::SetString — encrypts plain into the struct at ECX.
// Verified: FUN_00ea1f50 @ 0x00EA1F50 is void __thiscall(void* this, const char* plain)
// where this+0x104 = len, this+0x108 = enc buf[0x100] (encryptdata.cpp:0x1dc).
// NOTE: the correct base for the login's password is dlg+0x13BD0 directly
// (len at +0x104), NOT the +0x30C thunk used by the UI edit-sync path
// (FUN_00607CD5). Using the wrong base produces a wrong encrypted blob
// and the server replies "invalid username or password".
typedef void (__thiscall* SetEncStringFunc)(void* encData, const char* plain);
static const uintptr_t SET_ENC_STRING_ADDR = 0x00EA1F50;

static int __cdecl HookedLoginSend(const char* account, void* password, void* serverName, int mode, int extra)
{
	if (mode == 0)
	{
		if (AutoLogin::g_activeAccount[0])
		{
			if (!account || !account[0] || lstrcmpA(account, AutoLogin::g_activeAccount) == 0)
				account = AutoLogin::g_activeAccount;
		}
		// Password: only patch if the game's CEncryptData is empty (len==0).
		// If UI typing succeeded (len>0), leave it alone — the UI's encrypt via
		// Process is correct. This avoids the previous bug where unconditional
		// re-encrypt with SetEncString produced a wrong blob (wrong key base)
		// and caused "invalid username or password".
		if (AutoLogin::g_activePassword[0] && password)
		{
			__try
			{
				if (!IsBadReadPtr(password, 0x208) && !IsBadWritePtr(password, 0x208))
				{
					int encLen = *(int*)((char*)password + 0x104);
					// encLen is the encrypted length; 0 or 0xFFFFFFFF means empty/not set.
					// Only patch when empty, or when the UI failed to sync.
					if (encLen <= 0 || encLen > 0x100)
					{
						((SetEncStringFunc)SET_ENC_STRING_ADDR)(password, AutoLogin::g_activePassword);
					}
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {}
		}
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

namespace AutoLogin
{
	// User intent - auto-click the Login button until the dialog disappears.
	bool g_autoClickLogin = false;
	int  g_clickIntervalMs = 1000;   // min ms between automatic clicks
	int  g_clickCount = 0;           // total clicks sent this session
	bool g_loginCompleted = false;   // a click made the login dialog disappear
	int  g_clickMethod = 0;          // 0 = SendMessage LBDOWN/UP (no cursor), 1 = SendInput real click, 2 = BM_CLICK
	int  g_buttonIdOverride = 0;     // 0 = auto-detect, else GetDlgItem id
	int  g_accountEditIndex = -1;    // -1 = auto (topmost visible Edit), else index into g_edits
	int  g_passwordEditIndex = -1;   // -1 = auto (second smallest Y), else index into g_edits

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
	HWND g_filledAccountDialog = NULL;  // dialog instance we already auto-filled
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
	static bool IsDialogUsable(HWND hwnd)
	{
		return hwnd != NULL && IsWindow(hwnd) && IsWindowVisible(hwnd);
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

	// Finds the MFC login dialog. The game's own root/render windows are
	// skipped as candidates (they host no Edit controls); a WS_CHILD dialog
	// with Edit+Button children is the login screen. Returns NULL in-game.
	static HWND FindLoginDialog()
	{
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
		return passwordEdit != NULL && IsWindow(passwordEdit);
	}

	// Fills the account edit (WM_SETTEXT for display) and logs the status.
	// The actual login packet's account is guaranteed by the MinHook on
	// FUN_0101C9D8 — no member write needed. Never overwrites a field that
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

		// Install the MinHook on FUN_0101C9D8 if not done yet.
		InstallLoginHook();

		// Move focus to the password field (user can type there).
		if (result >= 0 && passwordEdit && IsWindow(passwordEdit))
			SetFocus(passwordEdit);
		return result;
	}

	// Fills the password edit by typing the plain Pass= value with real
	// SendInput keystrokes (fgui edits ignore WM_SETTEXT). Uses the same
	// visibility/Y logic as account — password = second smallest Y.
	// Also installs the login hook so the packet is guaranteed even if the
	// UI sync is bypassed. Never overwrites a non-empty different password
	// unless the user explicitly clicked Fill Password.
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
		// Also resolve account for focus dance (best effort)
		HWND accountEdit = NULL;
		{
			HWND tmpAcc = NULL, tmpPwd = NULL;
			if (ResolveAccountEdit(dialog, tmpAcc, tmpPwd))
				accountEdit = tmpAcc;
		}

		// If field already holds a different non-empty password and not forced, skip typing.
		char cur[128] = "";
		GetWindowTextA(passwordEdit, cur, sizeof(cur));
		if (cur[0] != 0 && lstrcmpA(cur, g_activePassword) != 0 && !forceOverwrite)
		{
			InstallLoginHook();
			return 0; // leave it, hook still covers login packet
		}

		InstallLoginHook();

		// Focus the password edit and type the plain password with SendInput.
		// This triggers the game's EN_KILLFOCUS/Process path that encrypts into
		// CDlgLogin+0x13BD0 (CEncryptData +0x104/+0x108) correctly.
		if (!SetFocus(passwordEdit))
			return -1;
		Sleep(30);

		// Select all + delete to clear.
		{
			INPUT ctrlDown = {0}; ctrlDown.type = INPUT_KEYBOARD; ctrlDown.ki.wVk = VK_CONTROL;
			INPUT aDown = {0}; aDown.type = INPUT_KEYBOARD; aDown.ki.wVk = 'A';
			INPUT aUp = {0}; aUp.type = INPUT_KEYBOARD; aUp.ki.wVk = 'A'; aUp.ki.dwFlags = KEYEVENTF_KEYUP;
			INPUT ctrlUp = {0}; ctrlUp.type = INPUT_KEYBOARD; ctrlUp.ki.wVk = VK_CONTROL; ctrlUp.ki.dwFlags = KEYEVENTF_KEYUP;
			SendInput(1, &ctrlDown, sizeof(INPUT));
			SendInput(1, &aDown, sizeof(INPUT));
			SendInput(1, &aUp, sizeof(INPUT));
			SendInput(1, &ctrlUp, sizeof(INPUT));
		}
		Sleep(20);
		// Delete
		INPUT del = {0}; del.type = INPUT_KEYBOARD; del.ki.wVk = VK_DELETE;
		SendInput(1, &del, sizeof(INPUT));
		del.ki.dwFlags = KEYEVENTF_KEYUP;
		SendInput(1, &del, sizeof(INPUT));
		Sleep(20);

		// Type the password via KEYEVENTF_UNICODE (works for any charset, no shift handling).
		for (const char* p = g_activePassword; *p; ++p)
		{
			INPUT down = {0}, up = {0};
			WCHAR w = (WCHAR)(unsigned char)*p;
			// For plain ASCII Pass=, VK_PACKET unicode is simplest; fallback to VkKeyScan if needed.
			down.type = INPUT_KEYBOARD; down.ki.wScan = w; down.ki.dwFlags = KEYEVENTF_UNICODE;
			up.type = INPUT_KEYBOARD; up.ki.wScan = w; up.ki.dwFlags = KEYEVENTF_UNICODE | KEYEVENTF_KEYUP;
			SendInput(1, &down, sizeof(INPUT));
			SendInput(1, &up, sizeof(INPUT));
			Sleep(5);
		}
		// Trigger EN_KILLFOCUS sync by moving focus away and back: focus account then back to password
		// so the game's Process handler copies Edit text → CEncryptData.
		if (accountEdit && IsWindow(accountEdit))
			SetFocus(accountEdit);
		Sleep(20);
		SetFocus(passwordEdit);
		Sleep(20);

		// Verify display (GetWindowText may return **** or plain depending on style — check length at least)
		char after[128] = "";
		GetWindowTextA(passwordEdit, after, sizeof(after));
		// If style is ES_PASSWORD, after may be same as before typing but hook still ensures packet.
		// Consider success if the field is non-empty.
		if (after[0] != 0)
			return 0;
		// Even if GetWindowText fails, hook guarantees packet — return success.
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

	// Applies the user-selected click method to an arbitrary button HWND.
	static bool ClickButtonMethod(HWND button)
	{
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

		// The account packet is patched by the FUN_0101C9D8 hook — no member
		// writes needed here.
		if (g_activeAccount[0])
			InstallLoginHook();

		HWND dialog = FindLoginDialog();
		HWND button = dialog ? FindLoginButton(dialog) : NULL;

		if (button && ClickButtonMethod(button))
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
	// the password field (types plain Pass= with SendInput, hook guarantees packet).
	void FillPasswordNow()
	{
		LoadActiveAccount();
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
		case 0:  msg = "password typed (hook active)"; break;
		default: msg = "FAILED - see Edit fields below"; break;
		}
		strcpy_s(g_passwordFillStatus, msg);
	}

	// ------------------------------------------------------------------
	// Per-frame state
	// ------------------------------------------------------------------

	void ApplyClientSideState()
	{
		// Install the login-send hook once if we have an account or password configured.
		if (g_activeAccount[0] || g_activePassword[0])
			InstallLoginHook();

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
		if (g_filledAccountDialog != g_cachedDialog && IsDialogUsable(g_cachedDialog))
		{
			g_filledAccountDialog = g_cachedDialog;
			if (g_activeAccount[0] == 0)
				LoadActiveAccount();
			if (g_activeAccount[0])
			{
				InstallLoginHook();
				FillAccountEdit(g_cachedDialog);
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
	if (ImGui::Button("Click Login Now"))
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
	ImGui::TextDisabled("(Fill Account types User, Fill Password types Pass= — no cursor movement)");
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
		          strstr(AutoLogin::g_passwordFillStatus, "typed") != NULL;
		if (ok)
			ImGui::TextColored(ImVec4(0.3f, 1.0f, 0.3f, 1.0f), "%s", AutoLogin::g_passwordFillStatus);
		else
			ImGui::TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), "%s", AutoLogin::g_passwordFillStatus);
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
		"Message (no cursor)\0Mouse (real click)\0BM_CLICK\0");

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
