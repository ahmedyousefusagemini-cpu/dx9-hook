#include <windows.h>
#include "imgui.h"

// ============================================================================
// Auto Login (MFC CDlgLogin) - Conquer.exe client 7950 (image base 0x400000)
// ----------------------------------------------------------------------------
// The login screen is an MFC dialog (CDlgLogin, source myshell/dlglogin.cpp,
// RTTI string "CDlgLogin" @ 0x016036A0). It is a WS_CHILD dialog of the game's
// root window hosting the fgui login UI (`login_xzk`): a real account/password
// Edit pair plus a real Login Button HWND (window text e.g. "EnterGame",
// displayed label e.g. "Log In").
//
// RE-verified click chain (Ghidra, 7950 build):
//   Login button click
//     -> FUN_LoginButtonHandler @ 0x008A8FCA (__fastcall(CDlgLogin*))
//          reads account (dlg+0x13B88), password (dlg+0x13BD0), server fields
//     -> FUN_0101C9D8 @ 0x0101C9D8
//          login(account, password, serverName, mode, extra) - sends the
//          CMsgAccountEx login packet (mode 0; 1 = QR code, 2 = poker)
//   Dispatched from the big UI event dispatcher (FUN_00a5b653 area) with
//   ECX = appObj + 0x39B948 (CDlgLogin is a member of the main app object,
//   returned by the accessor FUN_0041f880 -> DAT_01a546f4), gated on
//   FUN_00BFEE8B (IsWindow + IsWindowVisible of dlg+0x20 = the dialog HWND).
//
// CLICK MECHANISM (why not BM_CLICK): these are fgui-drawn controls, not
// standard MFC buttons - BM_CLICK does nothing (784 clicks observed, zero
// effect). SendInput (real mouse) works but moves the cursor and interacts
// badly with the ImGui overlay (the click fails when the overlay is visible
// because the ImGui WndProc handler processes the synthetic mouse messages
// before the fgui handler sees them).
//
// The default method therefore sends WM_LBUTTONDOWN + WM_LBUTTONUP directly
// to the button HWND via SendMessage — purely programmatic, no cursor
// movement, no OS hit-testing. The ImGui WndProc handler (which calls
// SetCapture()/AddMouseButtonEvent() on every LBDOWN and corrupts the fgui
// click when the overlay is open) is suppressed for the duration via the
// g_suppressImGuiWndProc flag, so the game's own WndProc sees the raw
// messages exactly like a real click.
// SendInput (real mouse) is kept as option 1, BM_CLICK as option 2.
//
// ACCOUNT TYPING ("Fill Account" button): reads accountinfo.ini ([AccountN]
// sections, first Use=1 wins, User=) and TYPES the name into the account edit
// (topmost VISIBLE Edit child) with real SendInput keystrokes — the fgui edit
// controls ignore WM_SETTEXT, but accept normal keyboard input like a human
// typing (Ctrl+A, Delete, then the name). Manual only; no auto-fill loop.
// ============================================================================

extern volatile bool g_suppressImGuiWndProc;

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

	// Active account loaded from accountinfo.ini ([AccountN] Use=1 -> User).
	char g_activeAccount[64] = "";   // User of the Use=1 section ("" if none)
	char g_accountSection[32] = "";  // the section name, e.g. "Account2"
	char g_fillStatus[96] = "";      // last "Fill Account" result

	// Runtime discovery (cached, re-validated per frame).
	HWND g_cachedDialog = NULL;
	HWND g_cachedButton = NULL;
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
	// Direct member set (bypasses the fgui edit-sync that was failing)
	// ------------------------------------------------------------------

	// App accessor: FUN_0041f880 -> DAT_01a546f4 (the main app object).
	// CDlgLogin = app + 0x39B948 (verified from the dispatcher at 0x00A5B90E).
	// Account setter: FUN_008acefa(this, account) -> dlg+0x13B88 = account.
	// All three addresses are guarded with byte checks.

	const uintptr_t APP_ACCESSOR_ADDR = 0x0041F880;
	const uintptr_t ACCOUNT_SETTER_ADDR = 0x008ACEFA;
	const size_t DLG_OFFSET = 0x39B948;

	// Verifies the app accessor hasn't been moved by a recompile.
	static bool IsAppAccessorValid()
	{
		if (IsBadReadPtr((const void*)APP_ACCESSOR_ADDR, 3))
			return false;
		const unsigned char* code = (const unsigned char*)APP_ACCESSOR_ADDR;
		// "83 3D ?? ?? ?? ?? 00" - the lazy accessor pattern
		return code[0] == 0x83 && code[1] == 0x3D;
	}

	// Verifies the account setter hasn't been moved by a recompile.
	static bool IsAccountSetterValid()
	{
		if (IsBadReadPtr((const void*)ACCOUNT_SETTER_ADDR, 3))
			return false;
		const unsigned char* code = (const unsigned char*)ACCOUNT_SETTER_ADDR;
		// "55 8B EC 83 7D 08 00" - PUSH EBP; MOV EBP,ESP; CMP [EBP+8],0
		return code[0] == 0x55 && code[1] == 0x8B && code[2] == 0xEC &&
			code[3] == 0x83 && code[4] == 0x7D && code[5] == 0x08 && code[6] == 0x00;
	}

	// Calls the game's own account setter (FUN_008acefa) to write the
	// account string directly into dlg+0x13B88 - the field the login
	// handler actually reads. This bypasses the fragile fgui edit-sync.
	static bool SetAccountMemberDirectly(const char* account)
	{
		if (!account || !account[0])
			return false;
		if (!IsAppAccessorValid() || !IsAccountSetterValid())
			return false;

		typedef int (__fastcall* AppAccessorFunc)();
		int app = ((AppAccessorFunc)APP_ACCESSOR_ADDR)();
		if (IsBadReadPtr((const void*)app, DLG_OFFSET + 0x100))
			return false;

		void* dlg = (void*)(app + DLG_OFFSET);
		// Verify the dialog's m_hWnd is valid (mirrors FUN_00BFEE8B).
		HWND hwnd = *(HWND*)((intptr_t)dlg + 0x20);
		if (!IsWindow(hwnd) || !IsWindowVisible(hwnd))
			return false;

		typedef void (__fastcall* AccountSetter)(void* dlg, void* /*unused edx*/, const char* acct);
		((AccountSetter)ACCOUNT_SETTER_ADDR)(dlg, NULL, account);
		return true;
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
	// stores its User value into g_activeAccount. Format:
	//   [Account1]  User=myusername  Use=1
	//   [Account2]  User=otheruser   Use=0
	static bool LoadActiveAccount()
	{
		g_activeAccount[0] = 0;
		g_accountSection[0] = 0;

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

		// Sends one real (SendInput) key event. vk-based events carry the virtual
	// key in wVk; text input uses KEYEVENTF_UNICODE with the char in wScan.
	static void SendKey(WORD vk, WORD scan, DWORD flags)
	{
		INPUT in = { 0 };
		in.type = INPUT_KEYBOARD;
		in.ki.wVk = vk;
		in.ki.wScan = scan;
		in.ki.dwFlags = flags;
		SendInput(1, &in, sizeof(INPUT));
	}

	// Resolves the account edit (pinned via g_accountEditIndex, else the topmost
	// visible Edit child) and its password sibling, for the current dialog.
	static bool ResolveAccountEdit(HWND dialog, HWND& accountEdit, HWND& passwordEdit)
	{
		accountEdit = NULL;
		passwordEdit = NULL;

		if (g_accountEditIndex >= 0 && g_accountEditIndex < g_editListCount)
		{
			accountEdit = g_edits[g_accountEditIndex].hwnd;
			// Password = the next visible edit below the account.
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

	// Attempt 1: WM_SETTEXT straight to the edit. Sets the edit's own text
	// buffer - works when the fgui edit draws its window text.
	static bool FillViaSetText(HWND edit)
	{
		SendMessage(edit, WM_SETTEXT, 0, (LPARAM)g_activeAccount);
		char t[128] = "";
		GetWindowTextA(edit, t, sizeof(t));
		return lstrcmpA(t, g_activeAccount) == 0;
	}

	// Attempt 2: activate the edit (SetFocus + suppressed synchronous click,
	// no cursor movement) then type via real SendInput keystrokes.
	static bool FillViaTyping(HWND edit)
	{
		SetFocus(edit);
		RECT rc;
		LPARAM pos = 0;
		if (GetClientRect(edit, &rc))
			pos = MAKELPARAM(rc.right / 2, rc.bottom / 2);
		g_suppressImGuiWndProc = true;
		SendMessage(edit, WM_LBUTTONDOWN, MK_LBUTTON, pos);
		SendMessage(edit, WM_LBUTTONUP, MK_LBUTTON, pos);
		g_suppressImGuiWndProc = false;
		Sleep(50);

		// Select all + delete any pre-filled text, then type the account.
		SendKey(VK_CONTROL, 0, 0);                 // Ctrl down
		SendKey('A', 0, 0);                        // A down (Ctrl+A = select all)
		SendKey('A', 0, KEYEVENTF_KEYUP);
		SendKey(VK_CONTROL, 0, KEYEVENTF_KEYUP);
		SendKey(VK_DELETE, 0, 0);                  // delete selection
		SendKey(VK_DELETE, 0, KEYEVENTF_KEYUP);

		for (const char* p = g_activeAccount; *p; p++)
		{
			SendKey(0, (WORD)(unsigned char)*p, KEYEVENTF_UNICODE);
			SendKey(0, (WORD)(unsigned char)*p, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP);
		}
		Sleep(30);

		char t[128] = "";
		GetWindowTextA(edit, t, sizeof(t));
		return lstrcmpA(t, g_activeAccount) == 0;
	}

	// Attempt 3: direct WM_CHAR messages to the edit (synchronous, suppressed).
	// Works when the edit's own WndProc inserts text on WM_CHAR.
	static bool FillViaChar(HWND edit)
	{
		g_suppressImGuiWndProc = true;
		for (const char* p = g_activeAccount; *p; p++)
			SendMessage(edit, WM_CHAR, (WPARAM)(unsigned char)*p, 1);
		g_suppressImGuiWndProc = false;

		char t[128] = "";
		GetWindowTextA(edit, t, sizeof(t));
		return lstrcmpA(t, g_activeAccount) == 0;
	}

	// Types the account name into the account edit without moving the cursor.
	// Tries WM_SETTEXT, then click+real-keys, then direct WM_CHAR - the first
	// one that verifies wins. On success, focus moves to the password field
	// (fires the EN_KILLFOCUS sync and leaves the cursor ready for the
	// password). Returns which method worked (0 = WM_SETTEXT, 1 = typing,
	// 2 = WM_CHAR, -1 = failed).
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
		if (FillViaSetText(accountEdit))
			result = 0;
		else if (FillViaTyping(accountEdit))
			result = 1;
		else if (FillViaChar(accountEdit))
			result = 2;

		// Regardless of the display fill, ALSO set the account member
		// directly via the game's own setter. The login handler reads the
		// member (dlg+0x13B88), not the edit - this is what actually matters.
		if (SetAccountMemberDirectly(g_activeAccount))
		{
			if (result < 0)
				result = 3;  // member set directly (display failed but OK)
		}

		if (result >= 0 && passwordEdit && IsWindow(passwordEdit))
			SetFocus(passwordEdit);
		return result;
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
		case 0:  msg = "account set (WM_SETTEXT)"; break;
		case 1:  msg = "account typed (click+keys)"; break;
		case 2:  msg = "account set (WM_CHAR)"; break;
		case 3:  msg = "member set directly (OK)"; break;
		default: msg = "FAILED - see Edit fields below"; break;
		}
		strcpy_s(g_fillStatus, msg);
	}

	// ------------------------------------------------------------------
	// Per-frame state
	// ------------------------------------------------------------------

	void ApplyClientSideState()
	{
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
	ImGui::TextDisabled("(programmatic press / types the account, no cursor movement)");
	if (AutoLogin::g_fillStatus[0])
	{
		bool ok = strstr(AutoLogin::g_fillStatus, "OK") != NULL;
		if (ok)
			ImGui::TextColored(ImVec4(0.3f, 1.0f, 0.3f, 1.0f), "%s", AutoLogin::g_fillStatus);
		else
			ImGui::TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), "%s", AutoLogin::g_fillStatus);
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
		ImGui::TextDisabled("accountinfo.ini is next to the game exe");
		ImGui::TextDisabled("Button found = the MFC login dialog is up");

		if (AutoLogin::g_editListCount > 0)
		{
			ImGui::Text("Edit fields (click 'use' to pick the account field):");
			for (int i = 0; i < AutoLogin::g_editListCount; i++)
			{
				const AutoLogin::EditInfo& ei = AutoLogin::g_edits[i];
				ImGui::PushID(1000 + i);
				ImGui::Text("  #%02d y=%-5d 0x%08X \"%s\"%s",
					i, ei.y, (unsigned int)ei.hwnd,
					ei.text[0] ? ei.text : "(empty)",
					i == AutoLogin::g_accountEditIndex ? "  <== ACCOUNT" : "");
				ImGui::SameLine();
				if (ImGui::SmallButton("use"))
				{
					AutoLogin::g_accountEditIndex = i;
				}
				ImGui::SameLine();
				if (ImGui::SmallButton("auto"))
				{
					AutoLogin::g_accountEditIndex = -1;
				}
				ImGui::PopID();
			}
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
