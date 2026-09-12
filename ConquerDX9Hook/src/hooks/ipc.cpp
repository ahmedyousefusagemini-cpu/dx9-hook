// ============================================================================
// IPC command channel for the AccountManager control plane
// ----------------------------------------------------------------------------
// The manager (AccountManager.exe) launches the client and needs to drive the
// proxied DLL's feature state LIVE - toggles applied while the game runs, not
// only via coinfo.ini at load. Every manager command comes through here.
//
// Transport: the DLL creates a hidden message-only window (title
// "ConquerDX9HookIPC") in its init thread. The manager broadcasts WM_COPYDATA
// payloads of one or more newline-separated "key=value" lines, where key
// matches the coinfo.ini LoadConfig key names (see ApplyIpcCommand). The
// WM_COPYDATA handler enqueues lines; HookedEndScene drains the queue each
// frame so every state mutation happens on the same thread run on.
// ============================================================================

#include <windows.h>
#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <string>
#include <vector>
#include "common.h"
#include "ipc.h"

// ---------------------------------------------------------------------------
// Command queue (filled by the IPC thread, drained by HookedEndScene)
// ---------------------------------------------------------------------------
struct IpcCommand
{
    std::string key;
    std::string value;
};

static std::vector<IpcCommand> g_ipcQueue;
static CRITICAL_SECTION g_ipcCs;
static bool g_ipcCsReady = false;

static void LogIpc(const char* fmt, ...)
{
	char exePath[MAX_PATH] = {0};
	if (!GetModuleFileNameA(NULL, exePath, MAX_PATH)) return;
	char* s = strrchr(exePath, '\\'); if (s) *(s+1) = 0;
	char logPath[MAX_PATH];
	_snprintf_s(logPath, _TRUNCATE, "%sipc.log", exePath);
	FILE* f = nullptr;
	if (fopen_s(&f, logPath, "a") != 0 || !f) return;
	va_list ap; va_start(ap, fmt); vfprintf(f, fmt, ap); va_end(ap);
	fprintf(f, "\n"); fclose(f);
}

// ---------------------------------------------------------------------------
// Feature state (extern from the feature modules, same declarations as
// config.cpp - the one source of truth for these globals)
// ---------------------------------------------------------------------------
namespace AutoHunt
{
	struct Waypoint { int x; int y; };
	extern bool g_notifyServer;
	extern bool g_spoofVipLevel;
	extern int  g_vipLevel;
	extern bool g_waypointsEnabled;
	extern std::vector<Waypoint> g_waypoints;
	extern int  g_arrivalThreshold;
	extern int  g_clearedSeconds;
	extern int  g_travelTimeoutSeconds;
	extern bool g_autoHuntOnLogin;
	extern void ApplyClientSideState();
	extern void Start();
	extern void Stop();
	extern int  g_currentWaypoint;
	extern bool GetPlayerPos(int& x, int& y);
	extern bool IsHunting();
	extern bool IsInCombat();
}

namespace Speed
{
	extern bool g_speedEnabled;
	extern int  g_speedPercent;
	extern bool g_fastLootTick;
	extern int  g_fastLootIntervalMs;
	extern bool g_autoMoveSpeedEnabled;
	extern int  g_autoMovePercent;
	extern bool g_attackSpeedEnabled;
	extern int  g_attackSpeedPercent;
	extern int  g_attackIntervalMs;
	extern void SetSpeedEnabled(bool);
	extern void SetAutoMoveSpeedEnabled(bool);
	extern void SetAttackSpeedEnabled(bool);
}

namespace XpSkill
{
	extern bool g_allowXpSkills;
	extern bool g_autoXpSkill;
	extern bool g_autoXpOnlyWhileHunting;
	extern bool g_forceXpSkillId;
	extern int  g_forcedXpSkillId;
	extern void ApplyXpSkillState();
}

namespace Buffs
{
	extern bool g_buffsEnabled;
}

namespace GearSwap
{
	extern bool g_autoSwap;
	extern int  g_iconStatusIdA;
	extern int  g_iconStatusIdB;
}

namespace AutoLogin
{
	extern bool g_autoClickLogin;
	extern bool g_autoFillAccount;
	extern bool g_autoFillPassword;
	extern int  g_clickIntervalMs;
	extern int  g_clickRetryMs;
	extern int  g_clickMethod;
	extern int  g_buttonIdOverride;
	extern int  g_accountEditIndex;
	extern int  g_passwordEditIndex;
	extern bool g_autoRelogin;
}

extern bool g_isWireframeEnabled;

// ---------------------------------------------------------------------------
// Queue drain - runs on the game thread (called from HookedEndScene)
// ---------------------------------------------------------------------------
void DrainIpcQueue()
{
    if (!g_ipcCsReady)
        return;

    std::vector<IpcCommand> local;
    EnterCriticalSection(&g_ipcCs);
    local.swap(g_ipcQueue);
    LeaveCriticalSection(&g_ipcCs);

    for (size_t i = 0; i < local.size(); i++)
    {
        const std::string& key = local[i].key;
        const std::string& val = local[i].value;
        int num = atoi(val.c_str());

        LogIpc("APPLY key='%s' val='%s'", key.c_str(), val.c_str());

        // --- Auto Hunt settings ---
        if (key == "AutoHuntOnLogin")           AutoHunt::g_autoHuntOnLogin = num != 0;
        else if (key == "NotifyServer")         AutoHunt::g_notifyServer = num != 0;
        else if (key == "SpoofVipLevel")        AutoHunt::g_spoofVipLevel = num != 0;
        else if (key == "VipLevel")
        {
            AutoHunt::g_vipLevel = num;
            if (AutoHunt::g_vipLevel < 0) AutoHunt::g_vipLevel = 0;
            if (AutoHunt::g_vipLevel > 6) AutoHunt::g_vipLevel = 6;
        }
        else if (key == "WaypointsEnabled")     AutoHunt::g_waypointsEnabled = num != 0;
        else if (key == "ArrivalThreshold")     AutoHunt::g_arrivalThreshold = num;
        else if (key == "ClearedSeconds")       AutoHunt::g_clearedSeconds = num;
        else if (key == "TravelTimeoutSeconds") AutoHunt::g_travelTimeoutSeconds = num;
        else if (key == "Waypoints")
        {
            AutoHunt::g_waypoints.clear();
            char buf[1024];
            strncpy_s(buf, val.c_str(), _TRUNCATE);
            char* ctx = NULL;
            for (char* tok = strtok_s(buf, ";", &ctx); tok; tok = strtok_s(NULL, ";", &ctx))
            {
                int x = 0, y = 0;
                if (sscanf_s(tok, " %d , %d", &x, &y) == 2)
                {
                    AutoHunt::Waypoint wp = { x, y };
                    AutoHunt::g_waypoints.push_back(wp);
                }
            }
        }
        // --- Auto Hunt run control (commands, not settings) ---
        else if (key == "AutoHuntStart")        AutoHunt::Start();
        else if (key == "AutoHuntStop")         AutoHunt::Stop();
        // --- Speed ---
        else if (key == "SpeedEnabled")          Speed::SetSpeedEnabled(num != 0);
        else if (key == "SpeedPercent")          Speed::g_speedPercent = num;
        else if (key == "FastLootTick")          Speed::g_fastLootTick = num != 0;
        else if (key == "FastLootIntervalMs")   Speed::g_fastLootIntervalMs = num;
        else if (key == "AutoMoveSpeedEnabled")  Speed::SetAutoMoveSpeedEnabled(num != 0);
        else if (key == "AutoMovePercent")       Speed::g_autoMovePercent = num;
        else if (key == "AttackSpeedEnabled")    Speed::SetAttackSpeedEnabled(num != 0);
        else if (key == "AttackSpeedPercent")    Speed::g_attackSpeedPercent = num;
        else if (key == "AttackIntervalMs")      Speed::g_attackIntervalMs = num;
        // --- XP Skills ---
        else if (key == "AllowXpSkills")        { XpSkill::g_allowXpSkills = num != 0; XpSkill::ApplyXpSkillState(); }
        else if (key == "AutoXpSkill")          XpSkill::g_autoXpSkill = num != 0;
        else if (key == "AutoXpOnlyWhileHunting") XpSkill::g_autoXpOnlyWhileHunting = num != 0;
        else if (key == "ForceXpSkillId")       XpSkill::g_forceXpSkillId = num != 0;
        else if (key == "ForcedXpSkillId")       XpSkill::g_forcedXpSkillId = num;
        // --- Buffs ---
        else if (key == "BuffsEnabled")          Buffs::g_buffsEnabled = num != 0;
        // --- Gear Swap ---
        else if (key == "AutoSwap")              GearSwap::g_autoSwap = num != 0;
        else if (key == "IconStatusIdA")         GearSwap::g_iconStatusIdA = num;
        else if (key == "IconStatusIdB")         GearSwap::g_iconStatusIdB = num;
        // --- Auto Login ---
        else if (key == "AutoClick")             AutoLogin::g_autoClickLogin = num != 0;
        else if (key == "AutoFillAccount")       AutoLogin::g_autoFillAccount = num != 0;
        else if (key == "AutoFillPassword")      AutoLogin::g_autoFillPassword = num != 0;
        else if (key == "AutoRelogin")           AutoLogin::g_autoRelogin = num != 0;
        else if (key == "ClickIntervalMs")       AutoLogin::g_clickIntervalMs = num;
        else if (key == "ClickRetryMs")          AutoLogin::g_clickRetryMs = num;
        else if (key == "ClickMethod")           AutoLogin::g_clickMethod = num;
        else if (key == "ButtonIdOverride")      AutoLogin::g_buttonIdOverride = num;
        else if (key == "AccountEditIndex")      AutoLogin::g_accountEditIndex = num;
        else if (key == "PasswordEditIndex")     AutoLogin::g_passwordEditIndex = num;
        // --- General ---
        else if (key == "Wireframe")             g_isWireframeEnabled = num != 0;
        else LogIpc("UNKNOWN key='%s'", key.c_str());
    }

    // The hunt flags are asserted per frame by ApplyClientSideState; the
    // cap tables / byte patches are re-applied here so a command takes
    // effect on this frame.
    AutoHunt::ApplyClientSideState();
}

// ---------------------------------------------------------------------------
// Hunt/character status heartbeat (for the manager's hunting indicator)
// ---------------------------------------------------------------------------
// Window text (|HUNT_TEXT_PREFIX prefix) is polled by the manager via
// GetWindowTextA on the IPC window. One writer, one reader: the DLL
// overwrites the title exactly once per EndScene; the manager reads it on
// its existing TIMER_STATUS tick.
static const char kHuntTextPrefix[] = "|HUNT_";

void IpcPublishHuntHeartbeat()
{
    if (!g_ipcWnd || !IsWindow(g_ipcWnd))
        return;

    int px = -1, py = -1;
    AutoHunt::GetPlayerPos(px, py);

    int wpIdx = AutoHunt::g_currentWaypoint;
    int wpCount = (int)AutoHunt::g_waypoints.size();

    // These queries hit the same global flag + client/manager bytes the brain
    // itself does, so the displayed state mirrors the in-game hunter.
    int hunting     = AutoHunt::IsHunting()        ? 1 : 0; // hunt flag set + byte
    int inCombat    = AutoHunt::IsInCombat()       ? 1 : 0; // mgr+0x04 != 0
    int monsterNear = hunting && AutoHunt::g_waypointsEnabled ? 0 : 0; // filled by caller when available
    (void)monsterNear;

    // AutoHunt::IsHunting already implies g_clientSideHunting + valid
    // client/manager bytes, so use it as the displayed "character is hunting".
    // g_clientSideHunting is the requested hunting intent (Start/Stop),

    char title[160];
    _snprintf_s(title, sizeof(title), _TRUNCATE,
        "|HUNT_H%d_WP%d/%d_POS%d,%d", hunting, wpIdx, wpCount, px, py);
    SetWindowTextA(g_ipcWnd, title);
}

// ---------------------------------------------------------------------------
// IPC thread: owns the message-only window and pumps its messages
// ----------------------------------------------------------------------------
// WM_COPYDATA is a cross-thread SendMessage: the receiving thread must pump
// messages or the sender blocks forever. The init thread's Sleep(16) loop
// never pumps, so the window lives on this dedicated thread instead. The
// manager finds it with FindWindowEx(HWND_MESSAGE, ...) - message-only
// windows are invisible to EnumWindows and never receive broadcasts.
// ---------------------------------------------------------------------------
static const char* kIpcClassName = "ConquerDX9HookIPCWnd";
static const char* kIpcWinName   = "ConquerDX9HookIPC";
static HWND g_ipcWnd = NULL;

static LRESULT CALLBACK IpcWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (msg == WM_COPYDATA)
    {
        COPYDATASTRUCT* cds = (COPYDATASTRUCT*)lParam;
        if (!cds || cds->dwData != 0x434F4E51) // 'CONQ' signature
            return FALSE;
        const char* data = (const char*)cds->lpData;
        int len = (int)cds->cbData;
        if (!data || len <= 0 || len > 65536)
            return FALSE;

        // Payload = one or more newline-separated key=value lines.
        std::string payload(data, len);
        size_t start = 0;
        int queued = 0;
        while (start < payload.size())
        {
            size_t end = payload.find('\n', start);
            std::string line = payload.substr(start,
                (end == std::string::npos ? payload.size() : end) - start);
            start = (end == std::string::npos) ? payload.size() : end + 1;
            if (!line.empty() && line[line.size() - 1] == '\r')
                line.erase(line.size() - 1);
            if (line.empty())
                continue;
            size_t eq = line.find('=');
            if (eq == std::string::npos)
                continue;
            EnterCriticalSection(&g_ipcCs);
            g_ipcQueue.push_back({ line.substr(0, eq), line.substr(eq + 1) });
            LeaveCriticalSection(&g_ipcCs);
            queued++;
        }
        LogIpc("RECV %d line(s), %d byte(s)", queued, len);
        return TRUE;
    }
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

static DWORD WINAPI IpcThread(LPVOID)
{
    // Message-only windows are children of the pseudo-parent HWND_MESSAGE,
    // NOT EnumWindows-visible top-level windows; only a pumping thread +
    // FindWindowEx(HWND_MESSAGE, ...) pairing works as a cross-process
    // channel.
    WNDCLASSEXA wc;
    memset(&wc, 0, sizeof(wc));
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = IpcWndProc;
    wc.hInstance     = GetModuleHandleA(NULL);
    wc.lpszClassName = kIpcClassName;
    if (!RegisterClassExA(&wc))
    {
        LogIpc("RegisterClass failed (err %lu)", GetLastError());
        return 1;
    }

    g_ipcWnd = CreateWindowExA(0, kIpcClassName, kIpcWinName, 0,
        0, 0, 0, 0, HWND_MESSAGE, NULL, wc.hInstance, NULL);
    if (!g_ipcWnd)
    {
        LogIpc("CreateWindow failed (err %lu)", GetLastError());
        return 1;
    }
    LogIpc("IPC window ready hwnd=%p tid=%lu", g_ipcWnd, GetCurrentThreadId());

    // Pump until WM_QUIT (posted by UninstallIpcWindow).
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0) > 0)
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    LogIpc("IPC thread exiting");
    return 0;
}

static HANDLE g_ipcThread = NULL;
static DWORD  g_ipcTid = 0;

bool InstallIpcWindow()
{
    if (g_ipcWnd)
        return true;

    InitializeCriticalSection(&g_ipcCs);
    g_ipcCsReady = true;

    g_ipcThread = CreateThread(NULL, 0, IpcThread, NULL, 0, &g_ipcTid);
    if (!g_ipcThread)
    {
        LogIpc("CreateThread failed (err %lu)", GetLastError());
        return false;
    }

    // Wait until the window exists so the manager sees it immediately after
    // InstallIpcWindow returns (it may still retry for late loads).
    for (int i = 0; i < 100 && !g_ipcWnd; i++)
        Sleep(10);
    return g_ipcWnd != NULL;
}

void UninstallIpcWindow()
{
    // WM_QUIT must go to the thread's own queue (PostMessage(hwnd, WM_QUIT)
    // is not supported). The pump loop exits, and the thread's windows are
    // destroyed automatically when the thread exits - DestroyWindow from
    // another thread is not allowed anyway.
    if (g_ipcTid)
        PostThreadMessage(g_ipcTid, WM_QUIT, 0, 0);
    if (g_ipcThread)
    {
        WaitForSingleObject(g_ipcThread, 2000);
        CloseHandle(g_ipcThread);
        g_ipcThread = NULL;
    }
    g_ipcWnd = NULL;
    g_ipcTid = 0;
    if (g_ipcCsReady)
    {
        DeleteCriticalSection(&g_ipcCs);
        g_ipcCsReady = false;
    }
}
