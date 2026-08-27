#include <windows.h>
#include <cstdio>
#include <cstdarg>
#include "hooks/common.h"
#include "hooks/config.h"
#include "hooks/anticheat.h"
#include "MinHook.h"

#pragma comment(lib, "d3d9.lib")
#pragma comment(lib, "libMinHook.x86.lib")

static void HookLog(const char* fmt, ...)
{
	char exePath[MAX_PATH]={0};
	if (!GetModuleFileNameA(NULL, exePath, MAX_PATH)) return;
	char* s=strrchr(exePath,'\\'); if(s) *(s+1)=0;
	char logPath[MAX_PATH]; _snprintf_s(logPath,_TRUNCATE,"%shook_init.log",exePath);
	FILE* f=nullptr; if(fopen_s(&f,logPath,"a")!=0||!f) return;
	va_list ap; va_start(ap,fmt); vfprintf(f,fmt,ap); va_end(ap);
	fprintf(f,"\n"); fclose(f);
}

static void LogLoadedModules()
{
	char buf[4096]; buf[0]=0;
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
	if (snap == INVALID_HANDLE_VALUE) { HookLog("ModuleSnap failed"); return; }
	MODULEENTRY32 me; me.dwSize = sizeof(me);
	if (Module32First(snap, &me)) {
		do {
			if (strlen(buf) + strlen(me.szModule) + 2 < sizeof(buf)) {
				strcat_s(buf, me.szModule); strcat_s(buf, " ");
			}
		} while (Module32Next(snap, &me));
	}
	CloseHandle(snap);
	HookLog("Loaded modules: %s", buf);
}

// Runs LogLoadedModules() safely OUTSIDE DllMain (CreateToolhelp32Snapshot in
// DllMain can deadlock under the loader lock). Called once from the hook thread.
void ModuleLogThread()
{
	Sleep(2000); // give the game's own imports time to resolve
	LogLoadedModules();
}

extern GameWindowInfo g_gameWindow;
extern EndSceneFunc g_originalEndSceneFunction;
extern ResetFunc g_originalResetFunction;
extern LPVOID g_originalEndSceneAddress;
extern LPVOID g_originalResetAddress;
extern void InstallDrawIndexedPrimitiveHook();
extern uintptr_t FindMemoryPattern(uintptr_t startAddress, size_t searchLength, const std::vector<int>& pattern);
extern HRESULT WINAPI HookedEndScene(LPDIRECT3DDEVICE9 device);
extern HRESULT WINAPI HookedReset(LPDIRECT3DDEVICE9 device, D3DPRESENT_PARAMETERS* presentationParameters);


void HookInitializationThread() 
{
	// Restore the settings saved by the last session's "Save Config" button.
	// Runs before any frame is rendered, so the overlay comes up configured.
	LoadConfig();

	HMODULE direct3D9ModuleHandle = nullptr;

	while (!(direct3D9ModuleHandle = GetModuleHandleA("d3d9.dll"))) 
	{
		Sleep(100); 
	}

	uintptr_t direct3D9ModuleBaseAddress = reinterpret_cast<uintptr_t>(direct3D9ModuleHandle);

	std::vector<int> vmtPattern = { 0xC7, 0x06, -1, -1, -1, -1, 0x89, 0x86, -1, -1, -1, -1, 0x89, 0x86 };
	
	size_t moduleSize = 0x100000;


	if (direct3D9ModuleHandle) 
	{
		PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)direct3D9ModuleHandle;
		if (dosHeader && dosHeader->e_magic == IMAGE_DOS_SIGNATURE) 
		{
			PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((uintptr_t)direct3D9ModuleHandle + dosHeader->e_lfanew);
			if (ntHeaders && ntHeaders->Signature == IMAGE_NT_SIGNATURE) 
			{
				moduleSize = ntHeaders->OptionalHeader.SizeOfImage;
			}
		}
	}
	
	uintptr_t vmtBaseAddress = FindMemoryPattern(direct3D9ModuleBaseAddress, moduleSize, vmtPattern);
	uintptr_t* virtualMethodTable = nullptr;

	if (!vmtBaseAddress)
	{
		HookLog("VMT pattern not found in d3d9.dll (base %p size 0x%zx) - trying dummy device fallback", (void*)direct3D9ModuleBaseAddress, moduleSize);
		// Fallback: create a dummy D3D9 device to extract the VMT directly.
		// This works even when the byte pattern changes across Windows builds.
		typedef IDirect3D9* (WINAPI* D3DCreate9Fn)(UINT);
		HMODULE hD3D = GetModuleHandleA("d3d9.dll");
		if (hD3D) {
			D3DCreate9Fn pCreate = (D3DCreate9Fn)GetProcAddress(hD3D, "Direct3DCreate9");
			if (pCreate) {
				IDirect3D9* d3d = pCreate(D3D_SDK_VERSION);
				if (d3d) {
					// Need a window for CreateDevice - use a hidden static.
					WNDCLASSA wc={0}; wc.lpfnWndProc=DefWindowProcA; wc.hInstance=GetModuleHandleA(NULL); wc.lpszClassName="__dx9hook_dummy__";
					RegisterClassA(&wc);
					HWND dummyWnd = CreateWindowA("__dx9hook_dummy__", "", WS_OVERLAPPEDWINDOW, 0,0, 64,64, NULL,NULL, wc.hInstance, NULL);
					if (dummyWnd) {
						D3DPRESENT_PARAMETERS pp={0};
						pp.Windowed=TRUE; pp.SwapEffect=D3DSWAPEFFECT_DISCARD; pp.hDeviceWindow=dummyWnd; pp.BackBufferFormat=D3DFMT_UNKNOWN;
						IDirect3DDevice9* dev=nullptr;
						HRESULT hr = d3d->CreateDevice(D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, dummyWnd, D3DCREATE_SOFTWARE_VERTEXPROCESSING, &pp, &dev);
						if (SUCCEEDED(hr) && dev) {
							virtualMethodTable = *(uintptr_t**)dev;
							HookLog("Fallback dummy device VMT %p", virtualMethodTable);
							dev->Release();
						} else {
							HookLog("Fallback CreateDevice failed hr=0x%08x", hr);
						}
						DestroyWindow(dummyWnd);
					}
					UnregisterClassA("__dx9hook_dummy__", wc.hInstance);
					d3d->Release();
				}
			}
		}
		if (!virtualMethodTable) {
			HookLog("Fallback also failed - no hooks installed");
			return;
		}
	} else {
		virtualMethodTable = *reinterpret_cast<uintptr_t**>(vmtBaseAddress + 2);
		HookLog("VMT pattern found at %p VMT %p", (void*)vmtBaseAddress, virtualMethodTable);
	}
	EndSceneFunc originalEndSceneFunc = reinterpret_cast<EndSceneFunc>(virtualMethodTable[42]);
	ResetFunc originalResetFunc = reinterpret_cast<ResetFunc>(virtualMethodTable[16]);


	g_originalEndSceneAddress = (LPVOID)originalEndSceneFunc;
	g_originalResetAddress = (LPVOID)originalResetFunc;


	MH_STATUS sh = MH_Initialize();
	if (sh!=MH_OK && sh!=MH_ERROR_ALREADY_INITIALIZED) HookLog("MH_Initialize failed %d", sh);
	sh = MH_CreateHook(g_originalEndSceneAddress, (LPVOID)HookedEndScene, (LPVOID*)&g_originalEndSceneFunction);
	HookLog("CreateHook EndScene %p -> %d", g_originalEndSceneAddress, sh);
	sh = MH_CreateHook(g_originalResetAddress, (LPVOID)HookedReset, (LPVOID*)&g_originalResetFunction);
	HookLog("CreateHook Reset %p -> %d", g_originalResetAddress, sh);
	
	// Input hooks are installed from HookedEndScene once the D3D device is
	// known (InstallInputHooksFromDevice), so no window title search needed.
	sh = MH_EnableHook(g_originalEndSceneAddress);
	HookLog("EnableHook EndScene %d", sh);
	sh = MH_EnableHook(g_originalResetAddress);
	HookLog("EnableHook Reset %d", sh);
	
	while (!g_gameWindow.direct3DDevice) 
	{
		Sleep(100);
	}
	InstallDrawIndexedPrimitiveHook();

	while (true) 
	{
		Sleep(16);

		if (GetAsyncKeyState(VK_INSERT) & 1) 
		{
			g_gameWindow.isGuiWindowOpen = !g_gameWindow.isGuiWindowOpen;
			Sleep(200); 
		}
	}
}


BOOL APIENTRY DllMain(HMODULE moduleHandle, DWORD reason, LPVOID reserved) 
{
	switch (reason) 
	{
	case DLL_PROCESS_ATTACH:
	
		DisableThreadLibraryCalls(moduleHandle);

		// Neutralize the game's anti-debug / anti-CE (IsDebuggerPresent +
		// SoftICE probes in the login dialog init, and TqNDProtect/ndac/
		// Assist delay-load watchdogs) before the game's own init runs.
		// Memory-only.
		if (InstallAntiCheatBypass())
			HookLog("AntiCheat bypass: applied (debugger/SoftICE/TQNDP/ndac/Assist blocked)");
		else
			HookLog("AntiCheat bypass: FAILED");

		CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)HookInitializationThread, NULL, 0, NULL);
		CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ModuleLogThread, NULL, 0, NULL);
		break;
		
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
