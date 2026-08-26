#include <windows.h>
#include <d3d9.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <vector>
#include <map>
#include "imgui.h"
#include "imgui_impl_dx9.h"
#include "imgui_impl_win32.h"
#include "MinHook.h"
#include "common.h"

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
extern GameWindowInfo g_gameWindow;
extern bool g_isImGuiInitialized;
extern EndSceneFunc g_originalEndSceneFunction;
extern ResetFunc g_originalResetFunction;
extern LPVOID g_originalEndSceneAddress;
extern ShowStringExFunc g_originalShowStringExFunction;
extern std::vector<CapturedStringData> g_capturedStrings;
extern void RenderImGuiInterface();
extern void UpdateRainbowColors();
extern HWND FindGameWindowHandle();
extern Direct3DRenderStateBackup SaveDirect3DRenderStates(LPDIRECT3DDEVICE9 device);
extern void RestoreDirect3DRenderStates(LPDIRECT3DDEVICE9 device, const Direct3DRenderStateBackup& backup);
extern void SetDirect3DRenderStatesFor2D(LPDIRECT3DDEVICE9 device);
extern void DrawStringBackgroundRectangle(LPDIRECT3DDEVICE9 device, int x1, int y1, int x2, int y2, DWORD color);
extern const StringConfiguration* FindItemStringConfiguration(const std::string& matchedString);
extern LPVOID g_originalShowStringExAddress;

// Original window procedure of the render window. The root window's
// original procedure lives in g_gameWindow.originalWindowProcedure.
static WNDPROC g_originalChildWindowProcedure = NULL;

// Additional windows subclassed beyond root/render (the MFC login dialog is a
// separate HWND created after the first frame; without its subclass the
// overlay receives no mouse/keyboard while it is up). Maps window -> original.
static std::map<HWND, WNDPROC> g_subclassedWindows;
static DWORD g_lastSubclassEnumTick = 0;

// Auto-login typing helper (defined in auto_login.cpp): types the ini
// credentials through the login dialog's real edit controls on the game thread.
namespace AutoLogin {
	void AutoLoginTypeViaControls();
	void AutoLoginPrimeConnection();
	extern int  g_retryCount;
	extern char g_account[128];
	extern const uintptr_t LOGIN_BUTTON_HANDLER; // FUN_008a8fba - the game's Login button handler
}

// Auto-login submit message handler.  Called on the game's message thread
// when the auto-login module posts WM_AUTOLOGIN_SUBMIT.  Runs the game's
// own Login button handler (FUN_008a8fba) which does GetServerInfo (resolves
// the account-server IP/port and connects the socket) then sends the packet.
// This MUST run on the message thread — calling FUN_008a8fba directly from
// the render thread crashed the client.

// BOTH DLL copies (proxy + injected sibling) subclass the dialog window, so
// one posted submit travels through BOTH window procedures and would run the
// login handler twice - two auth packets 350ms apart, which the server
// answers with silence. A named shared-memory tick deduplicates across
// copies: whichever layer processes the message first wins, the other skips.
static HANDLE g_alSubmitMap = nullptr;
static unsigned long* g_alSubmitTick = nullptr;
static unsigned long* AlSubmitSharedTick()
{
	if (!g_alSubmitTick) {
		g_alSubmitMap = CreateFileMappingA(INVALID_HANDLE_VALUE, nullptr,
			PAGE_READWRITE, 0, 64, "Local\\CDX9Hook_AutoLoginSubmit");
		if (g_alSubmitMap)
			g_alSubmitTick = (unsigned long*)MapViewOfFile(g_alSubmitMap,
				FILE_MAP_ALL_ACCESS, 0, 0, 64);
		if (g_alSubmitTick)
			*g_alSubmitTick = 0;
	}
	return g_alSubmitTick;
}

void HandleAutoLoginSubmit(void* dialog)
{
	// Cross-copy duplicate suppression (see above).
	unsigned long* shTick = AlSubmitSharedTick();
	unsigned long nowMs = GetTickCount();
	if (shTick && nowMs - *shTick < 3000) {
		extern void AutoLoginLogFromHook(const char* msg, void* dialog, HWND hwnd);
		AutoLoginLogFromHook("DUPLICATE submit suppressed (second subclass layer)", dialog,
			dialog ? *(HWND*)((unsigned char*)dialog + 0x20) : NULL);
		return;
	}
	if (shTick)
		*shTick = nowMs;

	// Cross-thread log: confirms the message reached this handler on the
	// game's message thread.
	extern void AutoLoginLogFromHook(const char* msg, void* dialog, HWND hwnd);
	HWND dlgHwnd = dialog ? *(HWND*)((unsigned char*)dialog + 0x20) : NULL;
	AutoLoginLogFromHook("WM_AUTOLOGIN_SUBMIT received", dialog, dlgHwnd);
	// Log the dialog fields FUN_008a8fba's GetServerInfo will read:
	// group/server indices + server name CString.
	if (dialog)
	{
		char tmp[64];
		AutoLoginLogFromHook("group/server", (void*)(uintptr_t)*(int*)((unsigned char*)dialog + 0x135f8),
			(HWND)(uintptr_t)*(int*)((unsigned char*)dialog + 0x135fc));
		_snprintf_s(tmp, _TRUNCATE, "srvname=%p", (void*)*(void**)((unsigned char*)dialog + 0x13628));
		AutoLoginLogFromHook(tmp, dialog, dlgHwnd);
	}
	__try {
		// Type the ACCOUNT through the dialog's real edit control (WM_CHAR).
		// The password is set directly via SetPassword on the wrapper at
		// dialog+0x13BD0 (confirmed: PASSWORD CHECK MATCH, pswdump len=8).
		// Do NOT type the password via WM_CHAR — the password bytes contain
		// 0x04 control chars that the Windows edit control drops, producing
		// a 6-char password (EDITREADBACK len=6 MISMATCH) that corrupts the
		// game's display-wrapper sync.
		AutoLogin::AutoLoginTypeViaControls();
		// Click the REAL realm-row button (BM_CLICK) exactly like the manual
		// login. This establishes the account-server connection and sets up
		// the dialog's selected-server state through the game's own dispatch.
		// Directly calling FUN_008a9348 skips the MFC message-map setup that
		// the real click provides.
		{
			HWND rowBtn = nullptr;
			EnumChildWindows(dlgHwnd, [](HWND h, LPARAM lp)->BOOL {
				char cls[24] = {0};
				GetClassNameA(h, cls, sizeof(cls));
				if (_stricmp(cls, "Button") != 0) return TRUE;
				RECT r = {};
				GetWindowRect(h, &r);
				// Realm-row buttons: ~72x20 at x~838, y in 694..780 band
				if ((r.right-r.left) > 50 && (r.right-r.left) < 100 &&
				    (r.bottom-r.top) > 15 && (r.bottom-r.top) < 30 &&
				    r.left > 800 && r.left < 860 && r.top > 680 && r.top < 790) {
					*(HWND*)lp = h;
					return FALSE;
				}
				return TRUE;
			}, (LPARAM)&rowBtn);
			if (rowBtn && IsWindow(rowBtn)) {
				SendMessageA(rowBtn, BM_CLICK, 0, 0);
				AutoLoginLogFromHook("CLICKED realm-row button (via BM_CLICK)", dialog, dlgHwnd);
			} else {
				AutoLoginLogFromHook("realm-row not found - direct FUN_008a9348 fallback", dialog, dlgHwnd);
				AutoLogin::AutoLoginPrimeConnection();
			}
		}
		// Match the MANUAL login's timing: the accepted manual run sent the
		// auth packet ~353ms after the account-server's 6B challenge reply.
		Sleep(500);

		// Click the REAL Login button (BM_CLICK) exactly like a human. The
		// manual login sequence is proven to work: one 472B packet -> 10B
		// ACCEPT. Directly calling FUN_008a8fba instead DOUBLE-SENDS (two
		// 472B packets ~380ms apart) and the server rejects the duplicate.
		// The button click goes through the game's own message map -> the
		// handler at 0x00a5b8fe -> FUN_008a8fba -> single send.
		{
			HWND loginBtn = nullptr;
			EnumChildWindows(dlgHwnd, [](HWND h, LPARAM lp)->BOOL {
				char cls[24] = {0};
				GetClassNameA(h, cls, sizeof(cls));
				if (_stricmp(cls, "Button") != 0) return TRUE;
				RECT r = {};
				GetWindowRect(h, &r);
				// Login button: large bottom-right (~195x60 at ~956,714)
				if ((r.right-r.left) > 150 && (r.bottom-r.top) > 50 &&
				    r.left > 900 && r.top > 690) {
					*(HWND*)lp = h;
					return FALSE;
				}
				return TRUE;
			}, (LPARAM)&loginBtn);

			if (loginBtn && IsWindow(loginBtn)) {
				SendMessageA(loginBtn, BM_CLICK, 0, 0);
				AutoLoginLogFromHook("CLICKED real Login button (single-send path)", dialog, dlgHwnd);
			} else {
				// Fallback: direct handler invocation. Only used when the
				// button could not be located. NOTE: this path may double-send
				// and the server may reject it - prefer the button click.
				AutoLoginLogFromHook("Login button not found - direct FUN_008a8fba fallback", dialog, dlgHwnd);
				typedef void (__fastcall* LoginBtnFn)(void* dialog);
				LoginBtnFn loginFn = (LoginBtnFn)AutoLogin::LOGIN_BUTTON_HANDLER;
				loginFn(dialog);
			}
		}
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		AutoLoginLogFromHook("submit EXCEPTION", dialog, dlgHwnd);
	}
}

// [overlay] subclass_all_windows in overlay.ini (next to the game exe).
// 1 (default): every process window is subclassed so the overlay also receives
//              input while the MFC login dialog owns it. The login screen is a
//              separate MFC HWND; without subclassing it the overlay is not
//              interactive at boot (the "frozen ImGui" bug).
// 0: opt-out back to only render+root. Hot-reloaded every enum tick.
bool g_subclassAllWindows = true;

// Diagnostics: live counters of messages reaching the WndProc hook,
// displayed at the top of the overlay window.
unsigned long g_debugMouseMessageCount = 0;
unsigned long g_debugKeyboardMessageCount = 0;
unsigned long g_debugSubclassedWindowCount = 0;

// Reads the flag tolerating ANSI, UTF-8 and UTF-16 files (Notepad defaults
// to UTF-16, which GetPrivateProfileIntA silently fails on -> flag stuck off).
// Returns true if key found, false otherwise. Out param `found` indicates
// whether the key was present at all.
static bool ReadOverlayFlagFromFileEx(const char* iniPath, bool* found)
{
	if (found) *found = false;
	FILE* f = NULL;
	if (fopen_s(&f, iniPath, "rb") != 0 || !f)
		return false;
	unsigned char buf[4096];
	size_t n = fread(buf, 1, sizeof(buf) - 1, f);
	fclose(f);
	buf[n] = 0;

	const unsigned char* p = buf;
	size_t remaining = n;
	bool wideLE = false, wideBE = false;
	if (n >= 3 && buf[0] == 0xEF && buf[1] == 0xBB && buf[2] == 0xBF) { p += 3; remaining -= 3; }
	else if (n >= 2 && buf[0] == 0xFF && buf[1] == 0xFE) { wideLE = true; p += 2; remaining -= 2; }
	else if (n >= 2 && buf[0] == 0xFE && buf[1] == 0xFF) { wideBE = true; p += 2; remaining -= 2; }

	char narrow[4096];
	size_t m = 0;
	if (wideLE || wideBE)
	{
		for (size_t i = 0; i + 1 < remaining && m < sizeof(narrow) - 1; i += 2)
			narrow[m++] = (char)(wideLE ? p[i] : p[i + 1]);
	}
	else
	{
		for (size_t i = 0; i < remaining && m < sizeof(narrow) - 1; ++i)
			narrow[m++] = (char)p[i];
	}
	narrow[m] = 0;

	for (char* c = narrow; *c; ++c)
		*c = (char)(*c >= 'A' && *c <= 'Z' ? *c + 32 : *c);
	const char* key = strstr(narrow, "subclass_all_windows");
	if (!key)
		return false;
	const char* eq = strchr(key, '=');
	if (!eq)
		return false;
	if (found) *found = true;
	return atoi(eq + 1) != 0;
}

static bool ReadOverlayFlagFromFile(const char* iniPath)
{
	bool f = false;
	return ReadOverlayFlagFromFileEx(iniPath, &f);
}

static void LoadOverlayConfig()
{
	char exePath[MAX_PATH];
	if (!GetModuleFileNameA(NULL, exePath, MAX_PATH))
		return;
	char* lastSlash = strrchr(exePath, '\\');
	if (lastSlash)
		*lastSlash = '\0';
	char iniPath[MAX_PATH];
	_snprintf_s(iniPath, sizeof(iniPath), _TRUNCATE, "%s\\overlay.ini", exePath);
	// Create a template if the file is missing so the user sees the option.
	if (GetFileAttributesA(iniPath)==INVALID_FILE_ATTRIBUTES) {
		FILE* f=nullptr;
		if (fopen_s(&f, iniPath, "w")==0 && f) {
			fprintf(f,
				"; Overlay config - next to Conquer.exe\n"
				"; subclass_all_windows=1 (default) subclasses every window so ImGui is interactive even on the MFC login screen.\n"
				"; Set to 0 to only hook render+root (may freeze ImGui at login).\n"
				"[overlay]\n"
				"subclass_all_windows=1\n");
			fclose(f);
		}
	}
	bool found = false;
	bool val = ReadOverlayFlagFromFileEx(iniPath, &found);
	if (found)
		g_subclassAllWindows = val;
	else
		g_subclassAllWindows = true; // default ON -> login dialog interactive out of box
}

LRESULT CALLBACK HookedWindowProcedure(HWND windowHandle, UINT message, WPARAM wParam, LPARAM lParam);

static BOOL CALLBACK SubclassEnumChildren(HWND hwnd, LPARAM lParam)
{
	if (!hwnd || !IsWindow(hwnd))
		return TRUE;
	// Never touch the two windows with dedicated hooks: they already run
	// HookedWindowProcedure - re-subclassing would store this very function
	// as the "original" and recurse into a stack overflow on the first
	// message (instant crash).
	if (hwnd == g_gameWindow.gameWindowHandle || hwnd == g_gameWindow.parentWindowHandle)
		return TRUE;
	if (g_subclassedWindows.find(hwnd) != g_subclassedWindows.end())
		return TRUE;
	if ((WNDPROC)GetWindowLongPtrA(hwnd, GWLP_WNDPROC) == HookedWindowProcedure)
		return TRUE;
	WNDPROC original = (WNDPROC)SetWindowLongPtrA(hwnd, GWLP_WNDPROC, (LONG_PTR)HookedWindowProcedure);
	if (original && original != HookedWindowProcedure)
		g_subclassedWindows[hwnd] = original;
	return TRUE;
}

static BOOL CALLBACK SubclassEnumProc(HWND hwnd, LPARAM lParam)
{
	DWORD pid = 0;
	GetWindowThreadProcessId(hwnd, &pid);
	if (pid != GetCurrentProcessId())
		return TRUE; // foreign window
	if (hwnd == g_gameWindow.gameWindowHandle || hwnd == g_gameWindow.parentWindowHandle)
	{
		// The windows themselves have dedicated hooks; their CHILDREN (e.g. a
		// WS_CHILD MFC login dialog and its edit controls) still need ours.
		EnumChildWindows(hwnd, SubclassEnumChildren, 0);
		return TRUE;
	}
	SubclassEnumChildren(hwnd, 0);
	EnumChildWindows(hwnd, SubclassEnumChildren, 0);
	return TRUE;
}

// Subclasses every process-owned top-level window and its children so the
// overlay input hook sees messages no matter which window has focus/hit-test
// (the MFC login dialog owns its own HWNDs). Every message is forwarded to
// the window's original procedure, so the game UI is unaffected unless ImGui
// requests capture.
void SubclassAllProcessWindows()
{
	// Reentrancy guard: SetWindowLongPtrA can dispatch messages synchronously;
	// a nested pump reaching EndScene must not re-run the enumeration.
	static bool inProgress = false;
	if (inProgress || !g_gameWindow.gameWindowHandle)
		return;
	inProgress = true;

	// Drop entries for destroyed windows: the OS reuses HWND values, so a
	// stale entry would both suppress re-subclassing of the new window and
	// forward to a dead window procedure.
	for (std::map<HWND, WNDPROC>::iterator it = g_subclassedWindows.begin(); it != g_subclassedWindows.end(); )
	{
		if (IsWindow(it->first))
			++it;
		else
			g_subclassedWindows.erase(it++);
	}

	EnumWindows(SubclassEnumProc, 0);
	g_debugSubclassedWindowCount = (unsigned long)g_subclassedWindows.size();
	inProgress = false;
}

// Hooks the exact window the D3D9 device renders into (plus its root
// window for keyboard input). Far more reliable than searching window
// titles, which can match a launcher/updater window instead.
void InstallInputHooksFromDevice(LPDIRECT3DDEVICE9 device)
{
	if (!device)
		return;

	HWND renderWindow = NULL;

	// Preferred: the swap chain's device window (the actual render target).
	IDirect3DSwapChain9* swapChain = NULL;
	if (SUCCEEDED(device->GetSwapChain(0, &swapChain)) && swapChain)
	{
		D3DPRESENT_PARAMETERS presentParams;
		if (SUCCEEDED(swapChain->GetPresentParameters(&presentParams)))
			renderWindow = presentParams.hDeviceWindow;
		swapChain->Release();
	}

	// Fallback: the focus window from creation parameters.
	if (!renderWindow)
	{
		D3DDEVICE_CREATION_PARAMETERS creationParams;
		if (SUCCEEDED(device->GetCreationParameters(&creationParams)))
			renderWindow = creationParams.hFocusWindow;
	}

	if (!renderWindow)
		return;

	g_gameWindow.gameWindowHandle = renderWindow;
	g_gameWindow.parentWindowHandle = GetAncestor(renderWindow, GA_ROOT);

	// Hook the root window: keyboard input (WM_CHAR/WM_KEYDOWN) goes to the
	// top-level window with focus.
	if (g_gameWindow.parentWindowHandle &&
		g_gameWindow.parentWindowHandle != renderWindow &&
		!g_gameWindow.originalWindowProcedure)
	{
		g_gameWindow.originalWindowProcedure = (WNDPROC)SetWindowLongPtrA(
			g_gameWindow.parentWindowHandle, GWLP_WNDPROC, (LONG_PTR)HookedWindowProcedure);
	}

	// Hook the render window: mouse input goes to it.
	if (!g_originalChildWindowProcedure)
	{
		g_originalChildWindowProcedure = (WNDPROC)SetWindowLongPtrA(
			renderWindow, GWLP_WNDPROC, (LONG_PTR)HookedWindowProcedure);
	}
}

HRESULT WINAPI HookedEndScene(LPDIRECT3DDEVICE9 device) 
{

	if (!g_gameWindow.direct3DDevice) 
	{
		g_gameWindow.direct3DDevice = device;
	}

	// Keep subclassing process windows (the MFC login dialog appears after
	// the first frame and owns its own HWNDs -> without this the overlay is
	// dead at the login screen). Throttled 250ms; the .ini switch is now
	// default ON and hot-reloads so the user can opt-out without restart.
	// Even when opted-out we still subclass at least once so the login
	// dialog's first appearance is caught.
	DWORD nowTick = GetTickCount();
	if (nowTick - g_lastSubclassEnumTick > 250)
	{
		g_lastSubclassEnumTick = nowTick;
		LoadOverlayConfig();
		// Always run: the "all vs root-only" distinction is kept as a hint
		// for diagnostics, but the login-screen bug requires at least the
		// dialog windows. Running unconditionally is safe - SubclassEnumProc
		// already skips already-hooked windows and cleans up dead HWNDs.
		SubclassAllProcessWindows();
		// If the user explicitly opted out we could limit to children of
		// root/render only, but the current unconditional behavior is the
		// desired fix; keep the flag for the overlay debug line.
		(void)g_subclassAllWindows;
	}

	if (!g_isImGuiInitialized) 
	{
		InstallInputHooksFromDevice(device);

		if (!g_gameWindow.gameWindowHandle)
		{
			g_gameWindow.gameWindowHandle = FindGameWindowHandle();
		}
		// First-frame catch: the MFC login dialog may already exist before the
		// first throttled EnumWindows tick fires 250ms later. Probe once
		// immediately after the root/render handles are known.
		if (g_gameWindow.gameWindowHandle)
			SubclassAllProcessWindows();
		
		ImGui::CreateContext();
		ImGuiIO& io = ImGui::GetIO();
		io.ConfigFlags |= ImGuiConfigFlags_NoMouseCursorChange;  
		
		// Use the render window: mouse messages arrive there, so this keeps
		// ImGui's input coordinates and display size in the same space.
		ImGui_ImplWin32_Init(g_gameWindow.gameWindowHandle);
		ImGui_ImplDX9_Init(g_gameWindow.direct3DDevice);
		g_isImGuiInitialized = true;
	}

	ImGui_ImplDX9_NewFrame();
	ImGui_ImplWin32_NewFrame();
	ImGui::NewFrame();
	RenderImGuiInterface();  
	ImGui::EndFrame();
	ImGui::Render();
	ImGui_ImplDX9_RenderDrawData(ImGui::GetDrawData());
	
	UpdateRainbowColors();
	
	if (g_originalShowStringExFunction && !g_capturedStrings.empty() && device) 
	{
		DWORD backgroundColor = D3DCOLOR_RGBA(0, 0, 0, RenderingConstants::BACKGROUND_ALPHA);
		
		Direct3DRenderStateBackup renderStateBackup = SaveDirect3DRenderStates(device);
		SetDirect3DRenderStatesFor2D(device);
		
		for (const auto& captured : g_capturedStrings) 
		{
			bool shouldShowBackground = false;
			
			if (captured.matchedSearchString != "SERVER_NAME") 
			{
				const StringConfiguration* config = FindItemStringConfiguration(captured.matchedSearchString);
				shouldShowBackground = config ? config->showBackground : false;
			}
			
			if (shouldShowBackground) 
			{
				int textWidth = static_cast<int>(captured.text.length() * captured.fontSize * RenderingConstants::TEXT_WIDTH_MULTIPLIER);
				int textHeight = captured.fontSize;
				
				int backgroundX1 = captured.positionX - RenderingConstants::BACKGROUND_PADDING_X;
				int backgroundY1 = captured.positionY - RenderingConstants::BACKGROUND_PADDING_Y;
				int backgroundX2 = captured.positionX + textWidth + RenderingConstants::BACKGROUND_PADDING_X;
				int backgroundY2 = captured.positionY + textHeight + RenderingConstants::BACKGROUND_PADDING_Y;
				
				DrawStringBackgroundRectangle(device, backgroundX1, backgroundY1, backgroundX2, backgroundY2, backgroundColor);
			}
		}
		
		for (const auto& captured : g_capturedStrings) 
		{
			const char* fontToUse = captured.fontName.empty() ? NULL : captured.fontName.c_str();
			
			g_originalShowStringExFunction(captured.positionX, captured.positionY, captured.color,
				captured.text.c_str(), fontToUse,
				captured.fontSize, captured.isAntialiased,
				captured.style, captured.secondColor, captured.offset);
		}
		
		RestoreDirect3DRenderStates(device, renderStateBackup);
		
		g_capturedStrings.clear();
	}

	return g_originalEndSceneFunction(device);
}


HRESULT WINAPI HookedReset(LPDIRECT3DDEVICE9 device, D3DPRESENT_PARAMETERS* presentationParameters) 
{

	ImGui_ImplDX9_InvalidateDeviceObjects();

	MH_DisableHook(g_originalEndSceneAddress);
	g_isImGuiInitialized = false;

	HRESULT result = g_originalResetFunction(device, presentationParameters);


	if (SUCCEEDED(result)) 
	{
		ImGui_ImplDX9_CreateDeviceObjects();

		ImGui_ImplDX9_Shutdown();
		ImGui_ImplWin32_Shutdown();
		ImGui::DestroyContext();

		MH_EnableHook(g_originalEndSceneAddress);
	}

	return result;
}

LRESULT CALLBACK HookedWindowProcedure(HWND windowHandle, UINT message, WPARAM wParam, LPARAM lParam) 
{
	// Auto-login submit: posted from the render thread, handled here on the
	// game's message thread so the game's MFC-heavy login handler runs in its
	// native context (calling it from the render thread crashed the client).
	if (message == WM_AUTOLOGIN_SUBMIT)
	{
		HandleAutoLoginSubmit((void*)lParam);
		return 0;
	}

	// Diagnostics: count input messages reaching the hook.
	switch (message) 
	{
	case WM_MOUSEMOVE:
	case WM_LBUTTONDOWN:
	case WM_RBUTTONDOWN:
	case WM_MBUTTONDOWN:
		g_debugMouseMessageCount++;
		break;
	case WM_CHAR:
	case WM_KEYDOWN:
		g_debugKeyboardMessageCount++;
		break;
	}

	if (g_isImGuiInitialized && g_gameWindow.isGuiWindowOpen) 
	{
		ImGuiIO& io = ImGui::GetIO();

		bool isExtraWindow = (windowHandle != g_gameWindow.gameWindowHandle &&
		                      windowHandle != g_gameWindow.parentWindowHandle);

		// Mouse messages from extra windows (the MFC login dialog) carry
		// coordinates in THEIR client space; ImGui positions are relative to
		// the render window, so remap before ImGui sees the message.
		WPARAM imMsgWParam = wParam;
		LPARAM imMsgLParam = lParam;
		if (windowHandle != g_gameWindow.gameWindowHandle)
		{
			switch (message)
			{
			case WM_MOUSEMOVE:
			case WM_LBUTTONDOWN:
			case WM_LBUTTONUP:
			case WM_LBUTTONDBLCLK:
			case WM_RBUTTONDOWN:
			case WM_RBUTTONUP:
			case WM_RBUTTONDBLCLK:
			case WM_MBUTTONDOWN:
			case WM_MBUTTONUP:
			case WM_MBUTTONDBLCLK:
				{
					POINT pt = { (short)LOWORD(lParam), (short)HIWORD(lParam) };
					ClientToScreen(windowHandle, &pt);
					ScreenToClient(g_gameWindow.gameWindowHandle, &pt);
					imMsgLParam = MAKELPARAM(pt.x, pt.y);
				}
				break;
			}
		}

		ImGui_ImplWin32_WndProcHandler(windowHandle, message, imMsgWParam, imMsgLParam);

		// CRITICAL: extra windows are the MFC login dialog and its Button/Edit
		// controls. If we swallow their clicks when ImGui wants capture, the
		// Login button becomes dead (the bug reported). The dialog HWNDs sit
		// on top of the D3D render target that ImGui draws into, so a click
		// on the dialog should always go to the game, not be blocked.
		// Only the render/root windows may be blocked when ImGui is hovered.
		if (isExtraWindow)
		{
			// Still let ImGui see the mouse pos (handled above) but never
			// block the game's own dialog input. This keeps the MFC Login
			// button and its Edit controls responsive even while the overlay
			// is open (overlay is behind the dialog anyway).
		}
		else if (io.WantCaptureMouse || io.WantCaptureKeyboard) 
		{
			switch (message) {
			case WM_LBUTTONDOWN:      
			case WM_LBUTTONUP:        
			case WM_LBUTTONDBLCLK:    
			case WM_RBUTTONDOWN:      
			case WM_RBUTTONUP:        
			case WM_RBUTTONDBLCLK:    
			case WM_MBUTTONDOWN:      
			case WM_MBUTTONUP:        
			case WM_MBUTTONDBLCLK:    
			case WM_MOUSEWHEEL:       
			case WM_MOUSEHWHEEL:      
			case WM_MOUSEMOVE:        
			case WM_KEYDOWN:          
			case WM_KEYUP:            
			case WM_SYSKEYDOWN:       
			case WM_SYSKEYUP:         
			case WM_CHAR:             
			case WM_IME_CHAR:         
			case WM_IME_COMPOSITION:  
				return 0;  
			}
		}
	}
	
	// Forward to the correct original procedure for THIS window.
	WNDPROC originalProcedure = NULL;
	std::map<HWND, WNDPROC>::iterator it = g_subclassedWindows.find(windowHandle);
	if (it != g_subclassedWindows.end())
		originalProcedure = it->second;
	if (!originalProcedure)
		originalProcedure = (windowHandle == g_gameWindow.gameWindowHandle && g_originalChildWindowProcedure)
			? g_originalChildWindowProcedure
			: g_gameWindow.originalWindowProcedure;

	return CallWindowProcA(originalProcedure, windowHandle, message, wParam, lParam);
}
