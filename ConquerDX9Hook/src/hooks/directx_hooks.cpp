#include <windows.h>
#include <d3d9.h>
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

// [overlay] subclass_all_windows in overlay.ini (next to the game exe).
// 0 (default): only the render + root windows are hooked - the known-good
//              behavior for the running game.
// 1: every process window is subclassed so the overlay also receives input
//    while the MFC login dialog owns it. Interferes with some game input,
//    hence opt-in.
static bool g_subclassAllWindows = false;

// Diagnostics: live counters of messages reaching the WndProc hook,
// displayed at the top of the overlay window.
unsigned long g_debugMouseMessageCount = 0;
unsigned long g_debugKeyboardMessageCount = 0;
unsigned long g_debugSubclassedWindowCount = 0;

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
	g_subclassAllWindows = GetPrivateProfileIntA("overlay", "subclass_all_windows", 0, iniPath) != 0;
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

	// Opt-in: keep subclassing process windows (the MFC login dialog appears
	// after the first frame). Throttled: the enum is cheap but not free.
	static bool overlayConfigLoaded = false;
	if (!overlayConfigLoaded)
	{
		overlayConfigLoaded = true;
		LoadOverlayConfig();
	}
	DWORD nowTick = GetTickCount();
	if (g_subclassAllWindows && nowTick - g_lastSubclassEnumTick > 250)
	{
		g_lastSubclassEnumTick = nowTick;
		SubclassAllProcessWindows();
	}

	if (!g_isImGuiInitialized) 
	{
		InstallInputHooksFromDevice(device);

		if (!g_gameWindow.gameWindowHandle)
		{
			g_gameWindow.gameWindowHandle = FindGameWindowHandle();
		}
		
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

		if (io.WantCaptureMouse || io.WantCaptureKeyboard) 
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
