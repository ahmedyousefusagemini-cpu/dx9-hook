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
	ImGui::TextDisabled("(programmatic press, no cursor movement)");

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
		ImGui::TextDisabled("Button found = the MFC login dialog is up");

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
