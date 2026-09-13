// ============================================================================
// AccountManager.exe - portable Win32 launcher / control plane for Conquer.exe
// ----------------------------------------------------------------------------
// Single config file: accounts.txt next to this exe. Holds [Global] (ClientPath,
// LastSelected) and one [Account:<name>] section per account, each with its own
// complete settings set: login automation (top-level keys) + every bot feature
// setting the ImGui overlay exposes (Feature.<Key> rows - checkboxes, ints and
// the waypoint list). No registry, no other files owned by the manager.
//
// Launch flow: auto-save selected account -> validate client path -> write
// transient accountinfo.ini / coinfo.ini into the client dir (regenerated every
// launch; the hook DLL reads those two files from the game dir at load; key
// names/sections match the hook's config.cpp LoadConfig exactly) ->
// CreateProcess("\"<ClientPath>\" blacknull") with the client dir as CWD.
// The launched process handle is kept so the Status column shows live
// "Running (pid N)" and the Kill button can stop it.
// ============================================================================

// Deliberately ANSI translation unit: every call below uses the A-suffix APIs
// (accounts.txt, client paths, window text are ANSI). The project builds with
// CharacterSet=Unicode, so kill the Unicode macros BEFORE windows.h - this
// makes the generic ListView_*/TabCtrl_*/SNDMSG macros resolve to their ANSI
// forms and stay consistent with the explicit *A calls.
#ifdef UNICODE
#undef UNICODE
#endif
#ifdef _UNICODE
#undef _UNICODE
#endif

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shlwapi.h>
#include <cstring>
#include <cstdio>
#include <cstdarg>
#include <string>
#include <vector>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "comdlg32.lib")

// ---------------------------------------------------------------------------
// Control IDs
// ---------------------------------------------------------------------------
#define IDC_LIST           1001
#define IDC_BTN_ADD        1002
#define IDC_BTN_SAVE       1003
#define IDC_BTN_DELETE     1004
#define IDC_BTN_LAUNCH     1005
#define IDC_BTN_PATH       1006
#define IDC_EDIT_ACCOUNT   1007
#define IDC_EDIT_PASSWORD  1008
#define IDC_COMBO_METHOD   1010
#define IDC_CHK_FILL_ACCT  1011
#define IDC_CHK_FILL_PASS  1012
#define IDC_CHK_AUTOCLICK  1013
#define IDC_CHK_RELOGIN    1014
// Login-tab int edits (top-level keys in accounts.txt).
#define IDC_ED_CLICKINT    1015
#define IDC_ED_CLICKRETRY  1016
#define IDC_ED_BTNOR       1017
#define IDC_ED_ACCTIDX     1018
#define IDC_ED_PASSIDX     1019
#define IDC_TABS           1020
#define IDC_BTN_KILL       1021
#define IDC_BTN_PUSH       1022
#define IDC_BTN_HUNT_ON    1023
#define IDC_BTN_HUNT_OFF   1024
#define IDC_LBL_HUNTSTATE  1025
#define IDC_STATIC_STATUS  1900
#define TIMER_STATUS       1     // live client status poll
#define TIMER_AUTOSAVE     2     // debounced per-account settings save
// Feature controls: table row i -> checkbox 1100+i, edit 1300+i, label 2100+i.
#define IDC_FEAT_CHK_FIRST  1100
#define IDC_FEAT_EDIT_FIRST 1300
#define IDC_FEAT_LBL_FIRST  2100
#define IDC_LBL_FIRST       2000  // static labels 2000..2004 (edits/combo/login)
#define IDC_LBL_LOGININT    2050  // login int labels 2050..2054

// ---------------------------------------------------------------------------
// Per-account feature settings table (the ImGui control surface)
// ----------------------------------------------------------------------------
// One row per Feature.<Key> line in accounts.txt. coinSection/coinKey = where
// the value lands in the transient coinfo.ini written to the client dir - key
// names/sections must match the hook's config.cpp LoadConfig/SaveConfig.
// Tabs: 0=Login (login table rows live there too), 1=Auto Hunt, 2=Speed,
// 3=XP / Buffs / Gear. Defaults mirror config.cpp LoadConfig (a missing key
// behaves exactly like a fresh hook install), except the original seven
// checkbox features which default 0 per the accounts.txt spec.
enum FeatKind { K_CHECK, K_INT, K_TEXT };

struct FeatDef
{
    const char* key;         // Feature.<Key> in accounts.txt
    const char* label;       // GUI text
    FeatKind    kind;
    const char* coinSection; // coinfo.ini section ("" = manager-only/special)
    const char* coinKey;     // coinfo.ini key
    const char* def;         // default value string
    int         tab;
};

static const FeatDef gFeats[] =
{
    // --- Auto Hunt (tab 1) ---
    { "AutoHuntOnLogin",     "Auto Hunt On Login",  K_CHECK, "AutoHunt", "AutoHuntOnLogin",     "0",  1 },
    { "NotifyServer",        "Notify Server",       K_CHECK, "AutoHunt", "NotifyServer",        "0",  1 },
    { "SpoofVipLevel",       "Spoof Vip Level",     K_CHECK, "AutoHunt", "SpoofVipLevel",       "0",  1 },
    { "WaypointsEnabled",    "Waypoints Enabled",   K_CHECK, "AutoHunt", "WaypointsEnabled",    "0",  1 },
    { "VipLevel",            "Vip Level (0-6)",     K_INT,   "AutoHunt", "VipLevel",            "6",  1 },
    { "ArrivalThreshold",    "Arrival Threshold",   K_INT,   "AutoHunt", "ArrivalThreshold",    "4",  1 },
    { "ClearedSeconds",      "Cleared Seconds",     K_INT,   "AutoHunt", "ClearedSeconds",      "5",  1 },
    { "TravelTimeoutSeconds","Travel Timeout (s)",  K_INT,   "AutoHunt", "TravelTimeoutSeconds","30", 1 },
    { "Waypoints",           "Waypoints (x,y;x,y)",K_TEXT,  "",         "",                    "",   1 },
    // --- Speed (tab 2) ---
    { "SpeedEnabled",        "Speed Enabled",       K_CHECK, "Speed",    "SpeedEnabled",        "0",  2 },
    { "FastLootTick",        "Fast Loot Tick",      K_CHECK, "Speed",    "FastLootTick",        "0",  2 },
    { "AutoMoveSpeedEnabled","Auto Move Enabled",   K_CHECK, "Speed",    "AutoMoveSpeedEnabled","0",  2 },
    { "AttackSpeedEnabled",  "Attack Speed Enabled", K_CHECK, "Speed",    "AttackSpeedEnabled",  "0",  2 },
    { "SpeedPercent",        "Speed Percent",        K_INT,   "Speed",    "SpeedPercent",        "200",2 },
    { "FastLootIntervalMs",  "Fast Loot Interval",  K_INT,   "Speed",    "FastLootIntervalMs",  "50", 2 },
    { "AutoMovePercent",     "Auto Move Percent",    K_INT,   "Speed",    "AutoMovePercent",     "500",2 },
    { "AttackSpeedPercent",  "Attack Speed Percent", K_INT,   "Speed",    "AttackSpeedPercent",  "500",2 },
    { "AttackIntervalMs",    "Attack Interval (ms)",K_INT,   "Speed",    "AttackIntervalMs",    "650",2 },
    // --- XP / Buffs / GearSwap / General (tab 3) ---
    { "AllowXpSkills",       "Allow XP Skills",     K_CHECK, "XpSkill",  "AllowXpSkills",       "0",  3 },
    { "AutoXpSkill",         "Auto XP Skill",       K_CHECK, "XpSkill",  "AutoXpSkill",         "0",  3 },
    { "AutoXpOnlyWhileHunting","Auto XP Only Hunt", K_CHECK, "XpSkill",  "AutoXpOnlyWhileHunting","1",3 },
    { "ForceXpSkillId",      "Force XP Skill Id",   K_CHECK, "XpSkill",  "ForceXpSkillId",      "1",  3 },
    { "ForcedXpSkillId",     "Forced Skill Id",     K_INT,   "XpSkill",  "ForcedXpSkillId",     "6011",3 },
    { "BuffsEnabled",        "Buffs Enabled",       K_CHECK, "Buffs",    "BuffsEnabled",        "0",  3 },
    { "GearSwap",            "Gear Swap",           K_CHECK, "GearSwap", "AutoSwap",            "0",  3 },
    { "IconStatusIdA",       "Swap Icon Id A",      K_INT,   "GearSwap", "IconStatusIdA",       "10", 3 },
    { "IconStatusIdB",       "Swap Icon Id B",      K_INT,   "GearSwap", "IconStatusIdB",       "5",  3 },
    { "Wireframe",           "Wireframe",           K_CHECK, "General",  "Wireframe",           "0",  3 },
};
static const int kFeatCount = sizeof(gFeats) / sizeof(gFeats[0]);
static const char* kTabNames[4] = { "Login", "Auto Hunt", "Speed", "XP / Buffs / Gear" };

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------
static const int kMaxAccounts = 64;

struct Settings
{
    bool autoFillAccount;
    bool autoFillPassword;
    bool autoClick;
    bool autoRelogin;
    int  clickMethod;
    int  clickIntervalMs;
    int  clickRetryMs;
    int  buttonIdOverride;
    int  accountEditIndex;
    int  passwordEditIndex;
};

struct Account
{
    char name[64];
    char pass[128];
    Settings s;
    // ALL Feature.<Key> rows (suffix key -> raw value string), known and
    // unknown. Unknown keys round-trip untouched; known ones feed the GUI and
    // the transient coinfo.ini export.
    std::vector<std::pair<std::string, std::string>> feats;
    // Live client tracking (in-memory only, never persisted).
    DWORD   pid;      // last launched client pid (0 = never launched)
    HANDLE  hProc;    // open handle while that client is running (NULL = dead)
};

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------
static char g_exeDir[MAX_PATH] = { 0 };
static char g_cfgPath[MAX_PATH] = { 0 };

static void BuildPaths()
{
    if (g_cfgPath[0])
        return;
    GetModuleFileNameA(NULL, g_exeDir, MAX_PATH);
    char* slash = strrchr(g_exeDir, '\\');
    if (slash)
        *slash = '\0';
    _snprintf_s(g_cfgPath, MAX_PATH, _TRUNCATE, "%s\\accounts.txt", g_exeDir);
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------
static void SetStatus(HWND hMain, const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    char text[512];
    _vsnprintf_s(text, sizeof(text), _TRUNCATE, fmt, ap);
    va_end(ap);
    HWND st = GetDlgItem(hMain, IDC_STATIC_STATUS);
    if (st)
        SetWindowTextA(st, text);
}

static bool FileExists(const char* path)
{
    return PathFileExistsA(path) == TRUE;
}

static void WriteIntKey(const char* section, const char* key, int v, const char* file)
{
    char buf[32];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%d", v);
    WritePrivateProfileStringA(section, key, buf, file);
}

static std::string ReadGlobal(const char* key, const char* def)
{
    char buf[MAX_PATH] = { 0 };
    GetPrivateProfileStringA("Global", key, def, buf, sizeof(buf), g_cfgPath);
    std::string s(buf);
    if (s.size() >= 2 && s.front() == '\"' && s.back() == '\"')
        s = s.substr(1, s.size() - 2);
    return s;
}

static void Defaults(Settings& s)
{
    s.autoFillAccount   = true;
    s.autoFillPassword  = true;
    s.autoClick         = false;
    s.autoRelogin       = true;
    s.clickMethod       = 0;
    s.clickIntervalMs   = 1000;
    s.clickRetryMs      = 10000;
    s.buttonIdOverride  = 0;
    s.accountEditIndex  = -1;
    s.passwordEditIndex = -1;
}

static void ClearAccount(Account& a)
{
    memset(a.name, 0, sizeof(a.name));
    memset(a.pass, 0, sizeof(a.pass));
    Defaults(a.s);
    a.feats.clear();
    a.pid = 0;
    a.hProc = NULL;
}

// Feature.<Key> accessors over the feats vector.
static bool IsKnownFeatKey(const char* suffix)
{
    for (int i = 0; i < kFeatCount; i++)
        if (_stricmp(suffix, gFeats[i].key) == 0)
            return true;
    return false;
}

static std::string GetFeat(const Account& a, const char* suffix, const char* def)
{
    for (size_t i = 0; i < a.feats.size(); i++)
        if (_stricmp(a.feats[i].first.c_str(), suffix) == 0)
            return a.feats[i].second;
    return std::string(def);
}

static void SetFeat(Account& a, const char* suffix, const char* val)
{
    for (size_t i = 0; i < a.feats.size(); i++)
        if (_stricmp(a.feats[i].first.c_str(), suffix) == 0)
        {
            a.feats[i].second = val;
            return;
        }
    a.feats.push_back({ std::string(suffix), std::string(val) });
}

// ---------------------------------------------------------------------------
// Config: accounts.txt
// ---------------------------------------------------------------------------
static std::vector<Account> g_accounts;
static char g_clientPath[MAX_PATH] = { 0 };
static char g_lastSelected[64] = { 0 };
static int  g_selAccount = -1;     // ListView index == vector index
static bool g_loading = false;     // suppress LVN_ITEMCHANGED while refreshing

static void LoadAll()
{
    g_accounts.clear();
    g_selAccount = -1;

    std::string cp = ReadGlobal("ClientPath", "");
    strncpy_s(g_clientPath, cp.c_str(), _TRUNCATE);
    GetPrivateProfileStringA("Global", "LastSelected", "", g_lastSelected,
        sizeof(g_lastSelected), g_cfgPath);

    // Enumerate sections; "Account:<name>" suffix IS the login username.
    char names[32768];
    DWORD n = GetPrivateProfileSectionNamesA(names, sizeof(names), g_cfgPath);
    if (n == 0 || n >= sizeof(names) - 2)
        return;

    for (char* s = names; *s; s += strlen(s) + 1)
    {
        if (_strnicmp(s, "Account:", 8) != 0)
            continue;
        const char* nm = s + 8;
        if (!*nm || g_accounts.size() >= (size_t)kMaxAccounts)
            continue;

        char sec[96];
        _snprintf_s(sec, sizeof(sec), _TRUNCATE, "Account:%s", nm);

        Account a;
        ClearAccount(a);
        strcpy_s(a.name, nm);
        GetPrivateProfileStringA(sec, "Pass", "", a.pass, sizeof(a.pass), g_cfgPath);

        a.s.autoFillAccount   = GetPrivateProfileIntA(sec, "AutoFillAccount", 1, g_cfgPath) != 0;
        a.s.autoFillPassword  = GetPrivateProfileIntA(sec, "AutoFillPassword", 1, g_cfgPath) != 0;
        a.s.autoClick         = GetPrivateProfileIntA(sec, "AutoClick", 0, g_cfgPath) != 0;
        a.s.autoRelogin       = GetPrivateProfileIntA(sec, "AutoRelogin", 1, g_cfgPath) != 0;
        a.s.clickMethod       = GetPrivateProfileIntA(sec, "ClickMethod", 0, g_cfgPath);
        a.s.clickIntervalMs   = GetPrivateProfileIntA(sec, "ClickIntervalMs", 1000, g_cfgPath);
        a.s.clickRetryMs      = GetPrivateProfileIntA(sec, "ClickRetryMs", 10000, g_cfgPath);
        a.s.buttonIdOverride  = GetPrivateProfileIntA(sec, "ButtonIdOverride", 0, g_cfgPath);
        a.s.accountEditIndex  = GetPrivateProfileIntA(sec, "AccountEditIndex", -1, g_cfgPath);
        a.s.passwordEditIndex = GetPrivateProfileIntA(sec, "PasswordEditIndex", -1, g_cfgPath);

        // Every Feature.<Key> row (known and unknown) - stored raw by suffix.
        char secbuf[8192];
        DWORD got = GetPrivateProfileSectionA(sec, secbuf, sizeof(secbuf), g_cfgPath);
        if (got > 0 && got < sizeof(secbuf) - 2)
        {
            for (char* p = secbuf; *p; p += strlen(p) + 1)
            {
                char* eq = strchr(p, '=');
                if (!eq)
                    continue;
                *eq = 0;
                std::string k(p);
                std::string v(eq + 1);
                *eq = '=';
                if (_strnicmp(k.c_str(), "Feature.", 8) != 0)
                    continue;
                a.feats.push_back({ k.substr(8), v });
            }
        }
        g_accounts.push_back(a);
    }
}

// Persist one account into its "Account:<name>" section (per-key writes).
static void WriteAccountIni(const Account& a)
{
    char sec[96];
    _snprintf_s(sec, sizeof(sec), _TRUNCATE, "Account:%s", a.name);

    WritePrivateProfileStringA(sec, "Pass", a.pass, g_cfgPath);
    WritePrivateProfileStringA(sec, "AutoFillAccount", a.s.autoFillAccount ? "1" : "0", g_cfgPath);
    WritePrivateProfileStringA(sec, "AutoFillPassword", a.s.autoFillPassword ? "1" : "0", g_cfgPath);
    WritePrivateProfileStringA(sec, "AutoClick", a.s.autoClick ? "1" : "0", g_cfgPath);
    WritePrivateProfileStringA(sec, "AutoRelogin", a.s.autoRelogin ? "1" : "0", g_cfgPath);
    WriteIntKey(sec, "ClickMethod", a.s.clickMethod, g_cfgPath);
    WriteIntKey(sec, "ClickIntervalMs", a.s.clickIntervalMs, g_cfgPath);
    WriteIntKey(sec, "ClickRetryMs", a.s.clickRetryMs, g_cfgPath);
    WriteIntKey(sec, "ButtonIdOverride", a.s.buttonIdOverride, g_cfgPath);
    WriteIntKey(sec, "AccountEditIndex", a.s.accountEditIndex, g_cfgPath);
    WriteIntKey(sec, "PasswordEditIndex", a.s.passwordEditIndex, g_cfgPath);
    for (size_t i = 0; i < a.feats.size(); i++)
    {
        char key[96];
        _snprintf_s(key, sizeof(key), _TRUNCATE, "Feature.%s", a.feats[i].first.c_str());
        WritePrivateProfileStringA(sec, key, a.feats[i].second.c_str(), g_cfgPath);
    }
}

static bool FindAccountByName(const char* name, int* idxOut = NULL)
{
    for (size_t i = 0; i < g_accounts.size(); i++)
        if (_stricmp(g_accounts[i].name, name) == 0)
        {
            if (idxOut)
                *idxOut = (int)i;
            return true;
        }
    return false;
}

// ---------------------------------------------------------------------------
// GUI <-> account transfers
// ---------------------------------------------------------------------------
// Builds an account from the GUI. pid/hProc (live client tracking) are copied
// from `old` when provided.
static Account AccountFromGui(HWND hMain, const char* name, const Account* old = NULL)
{
    Account a;
    ClearAccount(a);
    strcpy_s(a.name, name);
    GetDlgItemTextA(hMain, IDC_EDIT_PASSWORD, a.pass, sizeof(a.pass));
    a.s.autoFillAccount   = (IsDlgButtonChecked(hMain, IDC_CHK_FILL_ACCT) == BST_CHECKED);
    a.s.autoFillPassword  = (IsDlgButtonChecked(hMain, IDC_CHK_FILL_PASS) == BST_CHECKED);
    a.s.autoClick         = (IsDlgButtonChecked(hMain, IDC_CHK_AUTOCLICK) == BST_CHECKED);
    a.s.autoRelogin       = (IsDlgButtonChecked(hMain, IDC_CHK_RELOGIN) == BST_CHECKED);
    LRESULT cm = SendMessage(GetDlgItem(hMain, IDC_COMBO_METHOD), CB_GETCURSEL, 0, 0);
    a.s.clickMethod = (cm >= 0 && cm <= 3) ? (int)cm : 0;
    a.s.clickIntervalMs   = GetDlgItemInt(hMain, IDC_ED_CLICKINT, NULL, FALSE);
    a.s.clickRetryMs      = GetDlgItemInt(hMain, IDC_ED_CLICKRETRY, NULL, FALSE);
    a.s.buttonIdOverride  = GetDlgItemInt(hMain, IDC_ED_BTNOR, NULL, FALSE);
    a.s.accountEditIndex  = GetDlgItemInt(hMain, IDC_ED_ACCTIDX, NULL, TRUE);
    a.s.passwordEditIndex = GetDlgItemInt(hMain, IDC_ED_PASSIDX, NULL, TRUE);
    if (old)
    {
        a.pid = old->pid;
        a.hProc = old->hProc;
    }

    // Feature table controls -> Feature.<Key> rows (all of them, every save).
    for (int i = 0; i < kFeatCount; i++)
    {
        char val[512] = { 0 };
        if (gFeats[i].kind == K_CHECK)
            _snprintf_s(val, sizeof(val), _TRUNCATE, "%d",
                IsDlgButtonChecked(hMain, IDC_FEAT_CHK_FIRST + i) == BST_CHECKED ? 1 : 0);
        else
            GetDlgItemTextA(hMain, IDC_FEAT_EDIT_FIRST + i, val, sizeof(val));
        SetFeat(a, gFeats[i].key, val);
    }

    // Unknown Feature.* rows round-trip untouched.
    if (old)
        for (size_t i = 0; i < old->feats.size(); i++)
            if (!IsKnownFeatKey(old->feats[i].first.c_str()))
                SetFeat(a, old->feats[i].first.c_str(), old->feats[i].second.c_str());
    return a;
}

static void GuiShowAccount(HWND hMain, int idx)
{
    if (idx < 0 || idx >= (int)g_accounts.size())
        return;
    const Account& a = g_accounts[idx];
    g_loading = true;
    SetDlgItemTextA(hMain, IDC_EDIT_ACCOUNT, a.name);
    SetDlgItemTextA(hMain, IDC_EDIT_PASSWORD, a.pass);
    CheckDlgButton(hMain, IDC_CHK_FILL_ACCT, a.s.autoFillAccount ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(hMain, IDC_CHK_FILL_PASS, a.s.autoFillPassword ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(hMain, IDC_CHK_AUTOCLICK, a.s.autoClick ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(hMain, IDC_CHK_RELOGIN, a.s.autoRelogin ? BST_CHECKED : BST_UNCHECKED);
    int cm = a.s.clickMethod;
    if (cm < 0 || cm > 3) cm = 0; // combo index == ClickMethod value (0-3)
    SendMessage(GetDlgItem(hMain, IDC_COMBO_METHOD), CB_SETCURSEL, (WPARAM)cm, 0);
    SetDlgItemInt(hMain, IDC_ED_CLICKINT, (UINT)a.s.clickIntervalMs, FALSE);
    SetDlgItemInt(hMain, IDC_ED_CLICKRETRY, (UINT)a.s.clickRetryMs, FALSE);
    SetDlgItemInt(hMain, IDC_ED_BTNOR, (UINT)a.s.buttonIdOverride, FALSE);
    SetDlgItemInt(hMain, IDC_ED_ACCTIDX, (UINT)a.s.accountEditIndex, TRUE);
    SetDlgItemInt(hMain, IDC_ED_PASSIDX, (UINT)a.s.passwordEditIndex, TRUE);
    for (int i = 0; i < kFeatCount; i++)
    {
        std::string v = GetFeat(a, gFeats[i].key, gFeats[i].def);
        if (gFeats[i].kind == K_CHECK)
            CheckDlgButton(hMain, IDC_FEAT_CHK_FIRST + i,
                atoi(v.c_str()) != 0 ? BST_CHECKED : BST_UNCHECKED);
        else
            SetDlgItemTextA(hMain, IDC_FEAT_EDIT_FIRST + i, v.c_str());
    }
    // Name is read-only while a row is selected.
    SendMessage(GetDlgItem(hMain, IDC_EDIT_ACCOUNT), EM_SETREADONLY, TRUE, 0);
    g_loading = false;
}

static void GuiClearFields(HWND hMain)
{
    g_loading = true;
    SetDlgItemTextA(hMain, IDC_EDIT_ACCOUNT, "");
    SetDlgItemTextA(hMain, IDC_EDIT_PASSWORD, "");
    CheckDlgButton(hMain, IDC_CHK_FILL_ACCT, BST_CHECKED);
    CheckDlgButton(hMain, IDC_CHK_FILL_PASS, BST_CHECKED);
    CheckDlgButton(hMain, IDC_CHK_AUTOCLICK, BST_UNCHECKED);
    CheckDlgButton(hMain, IDC_CHK_RELOGIN, BST_CHECKED);
    SendMessage(GetDlgItem(hMain, IDC_COMBO_METHOD), CB_SETCURSEL, 0, 0);
    SetDlgItemInt(hMain, IDC_ED_CLICKINT, 1000, FALSE);
    SetDlgItemInt(hMain, IDC_ED_CLICKRETRY, 10000, FALSE);
    SetDlgItemInt(hMain, IDC_ED_BTNOR, 0, FALSE);
    SetDlgItemInt(hMain, IDC_ED_ACCTIDX, (UINT)-1, TRUE);
    SetDlgItemInt(hMain, IDC_ED_PASSIDX, (UINT)-1, TRUE);
    for (int i = 0; i < kFeatCount; i++)
    {
        if (gFeats[i].kind == K_CHECK)
            CheckDlgButton(hMain, IDC_FEAT_CHK_FIRST + i,
                atoi(gFeats[i].def) != 0 ? BST_CHECKED : BST_UNCHECKED);
        else
            SetDlgItemTextA(hMain, IDC_FEAT_EDIT_FIRST + i, gFeats[i].def);
    }
    // Name is editable when no row is selected (add mode).
    SendMessage(GetDlgItem(hMain, IDC_EDIT_ACCOUNT), EM_SETREADONLY, FALSE, 0);
    g_loading = false;
}

// ---------------------------------------------------------------------------
// Live client status
// ---------------------------------------------------------------------------
static const char* StatusText(const Account& a, char* buf, size_t bufsz)
{
    if (a.hProc)
    {
        if (WaitForSingleObject(a.hProc, 0) == WAIT_TIMEOUT)
        {
            _snprintf_s(buf, bufsz, _TRUNCATE, "Running (pid %lu)", a.pid);
            return buf;
        }
        // Signaled - the client exited; caller closes the handle.
        return "Last used";
    }
    return a.pid ? "Last used" : "";
}

// Reap dead handles and refresh only the Status column (no list rebuild, so
// the selection is untouched).
static void UpdateStatusColumn(HWND hMain)
{
    HWND lv = GetDlgItem(hMain, IDC_LIST);
    for (size_t i = 0; i < g_accounts.size(); i++)
    {
        if (g_accounts[i].hProc
            && WaitForSingleObject(g_accounts[i].hProc, 0) != WAIT_TIMEOUT)
        {
            CloseHandle(g_accounts[i].hProc);
            g_accounts[i].hProc = NULL;
        }
        char buf[64];
        ListView_SetItemText(lv, (int)i, 1, (LPSTR)StatusText(g_accounts[i], buf, sizeof(buf)));
    }
}

static void KillSelectedClient(HWND hMain)
{
    if (g_selAccount < 0 || g_selAccount >= (int)g_accounts.size())
    {
        SetStatus(hMain, "No account selected");
        return;
    }
    Account& a = g_accounts[g_selAccount];
    if (!a.hProc || WaitForSingleObject(a.hProc, 0) != WAIT_TIMEOUT)
    {
        SetStatus(hMain, "No running client for %s", a.name);
        return;
    }
    if (TerminateProcess(a.hProc, 0))
    {
        WaitForSingleObject(a.hProc, 3000);
        SetStatus(hMain, "Killed client (pid %lu) for %s", a.pid, a.name);
    }
    else
        SetStatus(hMain, "Kill failed (error %lu)", GetLastError());
    UpdateStatusColumn(hMain);
}

// ---------------------------------------------------------------------------
// Auto hunt: live hunting status + Start/Stop commands over IPC
// ---------------------------------------------------------------------------
static HWND FindIpcWindow();
static bool SendIpcLines(HWND hMain, const std::string& payload);

static void PollHuntStatus(HWND hMain)
{
    HWND hwnd = FindIpcWindow();
    if (!hwnd)
        return;
    char title[160] = {0};
    if (GetWindowTextA(hwnd, title, sizeof(title)) <= 0)
        return;
    // Title is |HUNT_H<N>_WP<N>/<M>_POS<X>,<Y> when the DLL heartbeat ran.
    const char* p = strstr(title, "|HUNT_");
    if (!p)
        return;

    int H = (p[6] == 'H') ? atoi(p + 7) : 0;
    int WP = 0, WC = 0, PX = -1, PY = -1;
    const char *wp = strstr(title, "_WP"), *pos = strstr(title, "_POS");
    if (wp) sscanf_s(wp, "_WP%d/%d", &WP, &WC);
    if (pos) sscanf_s(pos, "_POS%d,%d", &PX, &PY);

    wchar_t w[256];
    _snwprintf_s(w, _TRUNCATE, L"Character: %S  |  Waypoint %d/%d  |  Pos %d,%d",
        H ? "HUNTING" : "idle", WP, WC, PX, PY);
    SetWindowTextW(GetDlgItem(hMain, IDC_LBL_HUNTSTATE), w);
}

static bool SendHuntCommand(HWND hMain, const char* key)
{
    if (g_selAccount < 0 || g_selAccount >= (int)g_accounts.size())
    {
        SetStatus(hMain, "Select an account first");
        return false;
    }
    Account& a = g_accounts[g_selAccount];
    if (!a.hProc || WaitForSingleObject(a.hProc, 0) != WAIT_TIMEOUT)
    {
        SetStatus(hMain, "No running client for %s", a.name);
        return false;
    }
    char line[64];
    _snprintf_s(line, sizeof(line), _TRUNCATE, "%s=1\n", key);
    if (SendIpcLines(hMain, line))
    {
        SetStatus(hMain, "%s sent to %s", key, a.name);
        return true;
    }
    SetStatus(hMain, "No IPC window - is the client running?");
    return false;
}

// ---------------------------------------------------------------------------
// Auto-save: every settings edit is committed to the SELECTED account's own
// [Account:<name>] section, debounced so typing in an edit doesn't hammer
// WritePrivateProfileString per keystroke.
// ---------------------------------------------------------------------------
static void ScheduleAutosave(HWND hMain)
{
    SetTimer(hMain, TIMER_AUTOSAVE, 500, NULL);
}

static void FlushAutosave(HWND hMain)
{
    KillTimer(hMain, TIMER_AUTOSAVE);
    if (g_selAccount < 0 || g_selAccount >= (int)g_accounts.size())
        return;
    Account& live = g_accounts[g_selAccount];
    Account a = AccountFromGui(hMain, live.name, &live);
    g_accounts[g_selAccount] = a;
    WriteAccountIni(a);
}

// ---------------------------------------------------------------------------
// IPC: push settings/commands into the RUNNING client's proxied DLL
// ----------------------------------------------------------------------------
// The DLL creates a message-only window titled "ConquerDX9HookIPC". We send
// WM_COPYDATA (signature 'CONQ') with newline-separated key=value lines using
// exactly the coinfo.ini LoadConfig key names - the DLL's DrainIpcQueue
// applies them through the same paths as the ImGui toggles.
//
// The DLL window may not exist yet right after CreateProcess (the proxy DLL
// needs a moment to load), so SendIpcToAccount retries briefly.

static const UINT_PTR kIpcSignature = 0x434F4E51; // 'CONQ'
static const char* kIpcWinName = "ConquerDX9HookIPC";

// Message-only windows are NOT visible to EnumWindows and never receive
// HWND_BROADCAST - the only cross-process lookup is FindWindowEx under the
// HWND_MESSAGE pseudo-parent. The window title identifies the DLL instance;
// NULL hwndParent finds any process's window (single-client machine).
static HWND FindIpcWindow()
{
    return FindWindowExA(HWND_MESSAGE, NULL, NULL, kIpcWinName);
}

static bool SendIpcLines(HWND hMain, const std::string& payload)
{
    if (payload.empty())
        return true;

    HWND target = NULL;
    DWORD deadline = GetTickCount() + 5000;
    for (;;)
    {
        target = FindIpcWindow();
        if (target)
            break;
        if (GetTickCount() >= deadline)
            return false;
        Sleep(100);
    }

    COPYDATASTRUCT cds;
    cds.dwData = kIpcSignature;
    cds.cbData = (DWORD)payload.size();
    cds.lpData = (void*)payload.c_str();
    LRESULT ok = SendMessageA(target, WM_COPYDATA, (WPARAM)hMain, (LPARAM)&cds);
    return ok != 0;
}

// Build the full key=value line set for an account (login settings + all
// Feature.* rows) - the same keys the transient coinfo.ini export writes.
static std::string BuildIpcPayload(const Account& a)
{
    std::string out;
    char line[256];

    _snprintf_s(line, sizeof(line), _TRUNCATE, "AutoClick=%d\n", a.s.autoClick ? 1 : 0);
    out += line;
    _snprintf_s(line, sizeof(line), _TRUNCATE, "AutoFillAccount=%d\n", a.s.autoFillAccount ? 1 : 0);
    out += line;
    _snprintf_s(line, sizeof(line), _TRUNCATE, "AutoFillPassword=%d\n", a.s.autoFillPassword ? 1 : 0);
    out += line;
    _snprintf_s(line, sizeof(line), _TRUNCATE, "AutoRelogin=%d\n", a.s.autoRelogin ? 1 : 0);
    out += line;
    _snprintf_s(line, sizeof(line), _TRUNCATE, "ClickIntervalMs=%d\n", a.s.clickIntervalMs);
    out += line;
    _snprintf_s(line, sizeof(line), _TRUNCATE, "ClickRetryMs=%d\n", a.s.clickRetryMs);
    out += line;
    _snprintf_s(line, sizeof(line), _TRUNCATE, "ClickMethod=%d\n", a.s.clickMethod);
    out += line;
    _snprintf_s(line, sizeof(line), _TRUNCATE, "ButtonIdOverride=%d\n", a.s.buttonIdOverride);
    out += line;
    _snprintf_s(line, sizeof(line), _TRUNCATE, "AccountEditIndex=%d\n", a.s.accountEditIndex);
    out += line;
    _snprintf_s(line, sizeof(line), _TRUNCATE, "PasswordEditIndex=%d\n", a.s.passwordEditIndex);
    out += line;

    for (int i = 0; i < kFeatCount; i++)
    {
        if (gFeats[i].kind == K_TEXT)
            continue;
        std::string v = GetFeat(a, gFeats[i].key, gFeats[i].def);
        if (gFeats[i].kind == K_CHECK)
            _snprintf_s(line, sizeof(line), _TRUNCATE, "%s=%d\n",
                gFeats[i].coinKey, atoi(v.c_str()) != 0 ? 1 : 0);
        else
            _snprintf_s(line, sizeof(line), _TRUNCATE, "%s=%s\n",
                gFeats[i].coinKey, v.c_str());
        out += line;
    }

    // Waypoints row (K_TEXT) - the DLL parses "x,y;x,y".
    std::string wps = GetFeat(a, "Waypoints", "");
    if (!wps.empty())
    {
        out += "Waypoints=" + wps + "\n";
    }
    return out;
}

// Status-bar helper: the coinfo key name a changed control maps to.
static const char* IpcKeyFor(int controlId)
{
    if (controlId >= IDC_FEAT_CHK_FIRST && controlId < IDC_FEAT_CHK_FIRST + kFeatCount)
        return gFeats[controlId - IDC_FEAT_CHK_FIRST].coinKey;
    if (controlId >= IDC_FEAT_EDIT_FIRST && controlId < IDC_FEAT_EDIT_FIRST + kFeatCount)
        return gFeats[controlId - IDC_FEAT_EDIT_FIRST].coinKey;
    switch (controlId)
    {
    case IDC_CHK_FILL_ACCT:  return "AutoFillAccount";
    case IDC_CHK_FILL_PASS:  return "AutoFillPassword";
    case IDC_CHK_AUTOCLICK:   return "AutoClick";
    case IDC_CHK_RELOGIN:    return "AutoRelogin";
    case IDC_COMBO_METHOD:   return "ClickMethod";
    case IDC_ED_CLICKINT:    return "ClickIntervalMs";
    case IDC_ED_CLICKRETRY:  return "ClickRetryMs";
    case IDC_ED_BTNOR:       return "ButtonIdOverride";
    case IDC_ED_ACCTIDX:     return "AccountEditIndex";
    case IDC_ED_PASSIDX:     return "PasswordEditIndex";
    }
    return "setting";
}

static void PushAccountToClient(HWND hMain, const char* who)
{
    if (g_selAccount < 0 || g_selAccount >= (int)g_accounts.size())
    {
        SetStatus(hMain, "No account selected - nothing to push");
        return;
    }
    const Account& a = g_accounts[g_selAccount];
    if (!a.hProc || WaitForSingleObject(a.hProc, 0) != WAIT_TIMEOUT)
    {
        SetStatus(hMain, "No running client for %s", a.name);
        return;
    }
    if (SendIpcLines(hMain, BuildIpcPayload(a)))
        SetStatus(hMain, "Pushed %s settings to running client (%s)", a.name, who);
    else
        SetStatus(hMain, "Push failed: no IPC window in client of %s", a.name);
}

// ---------------------------------------------------------------------------
// ListView
// ---------------------------------------------------------------------------
static void RefreshList(HWND hMain)
{
    HWND lv = GetDlgItem(hMain, IDC_LIST);
    g_loading = true;
    ListView_DeleteAllItems(lv);
    for (size_t i = 0; i < g_accounts.size(); i++)
    {
        LVITEMA it;
        memset(&it, 0, sizeof(it));
        it.mask = LVIF_TEXT;
        it.iItem = (int)i;
        it.pszText = (LPSTR)g_accounts[i].name;
        int row = ListView_InsertItem(lv, &it);
        if (row >= 0)
        {
            char buf[64];
            ListView_SetItemText(lv, row, 1,
                (LPSTR)StatusText(g_accounts[i], buf, sizeof(buf)));
        }
    }
    if (g_selAccount >= (int)g_accounts.size())
        g_selAccount = -1;
    // On first fill, restore the last session's selection.
    if (g_selAccount < 0 && g_lastSelected[0])
    {
        int idx = -1;
        if (FindAccountByName(g_lastSelected, &idx))
            g_selAccount = idx;
    }
    if (g_selAccount >= 0)
    {
        ListView_SetItemState(lv, g_selAccount,
            LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_EnsureVisible(lv, g_selAccount, FALSE);
    }
    g_loading = false;
}

// ---------------------------------------------------------------------------
// Client path prompt
// ---------------------------------------------------------------------------
static bool PromptForClientPath(HWND hMain)
{
    char file[MAX_PATH] = { 0 };
    strncpy_s(file, g_clientPath, _TRUNCATE);

    OPENFILENAMEA ofn;
    memset(&ofn, 0, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hMain;
    ofn.lpstrFilter = "Conquer.exe\0Conquer.exe\0";
    ofn.lpstrFile = file;
    ofn.nMaxFile = MAX_PATH;
    // Suggested browsing start point (only used if it exists on this machine).
    ofn.lpstrInitialDir = FileExists("H:\\client\\Env_DX9") ? "H:\\client\\Env_DX9" : NULL;
    ofn.lpstrTitle = "Select Conquer.exe";
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY;
    if (!GetOpenFileNameA(&ofn))
        return false;
    strncpy_s(g_clientPath, file, _TRUNCATE);
    WritePrivateProfileStringA("Global", "ClientPath", g_clientPath, g_cfgPath);
    return true;
}

static void EnsureClientPath(HWND hMain)
{
    std::string cp = ReadGlobal("ClientPath", "");
    if (cp.empty() || !FileExists(cp.c_str()))
        PromptForClientPath(hMain);
}

// ---------------------------------------------------------------------------
// Transient export (client dir; regenerated on every launch)
// ---------------------------------------------------------------------------
static void ExportAccountInfoIni(const Account& a, const char* clientDir)
{
    char path[MAX_PATH];
    _snprintf_s(path, MAX_PATH, _TRUNCATE, "%s\\accountinfo.ini", clientDir);

    // Clear stale [AccountN] N>1 sections and any other section still marked
    // Use=1 - only our single [Account1] may be active.
    char names[4096];
    DWORD n = GetPrivateProfileSectionNamesA(names, sizeof(names), path);
    if (n > 0 && n < sizeof(names) - 2)
    {
        for (char* s = names; *s; s += strlen(s) + 1)
        {
            if (_stricmp(s, "Account1") == 0)
                continue;
            int idx = -1;
            if (sscanf_s(s, "Account%d", &idx) == 1 && idx > 1)
            {
                WritePrivateProfileStringA(s, NULL, NULL, path); // drop section
                continue;
            }
            char use[8] = { 0 };
            GetPrivateProfileStringA(s, "Use", "0", use, sizeof(use), path);
            if (_stricmp(use, "1") == 0)
                WritePrivateProfileStringA(s, "Use", "0", path);
        }
    }

    WritePrivateProfileStringA("Account1", "User", a.name, path);
    WritePrivateProfileStringA("Account1", "Pass", a.pass, path);
    WritePrivateProfileStringA("Account1", "Use", "1", path);
}

// Waypoints: "x,y;x,y;..." in accounts.txt -> WaypointCount/Waypoint0..N in
// coinfo.ini (the format the hook's LoadConfig parses).
static void ExportWaypoints(const Account& a, const char* path)
{
    std::string v = GetFeat(a, "Waypoints", "");
    int count = 0;
    if (!v.empty())
    {
        char buf[2048];
        strncpy_s(buf, v.c_str(), _TRUNCATE);
        char* ctx = NULL;
        for (char* tok = strtok_s(buf, ";", &ctx); tok; tok = strtok_s(NULL, ";", &ctx))
        {
            int x = 0, y = 0;
            if (sscanf_s(tok, " %d , %d", &x, &y) == 2)
            {
                char key[16], val[32];
                _snprintf_s(key, sizeof(key), _TRUNCATE, "Waypoint%d", count);
                _snprintf_s(val, sizeof(val), _TRUNCATE, "%d,%d", x, y);
                WritePrivateProfileStringA("AutoHunt", key, val, path);
                count++;
            }
        }
    }
    WriteIntKey("AutoHunt", "WaypointCount", count, path);
}

static void ExportCoinfoIni(const Account& a, const char* clientDir)
{
    char path[MAX_PATH];
    _snprintf_s(path, MAX_PATH, _TRUNCATE, "%s\\coinfo.ini", clientDir);

    // [AutoLogin] - key names must match the hook's config.cpp LoadConfig.
    WritePrivateProfileStringA("AutoLogin", "AutoClick", a.s.autoClick ? "1" : "0", path);
    WritePrivateProfileStringA("AutoLogin", "AutoFillAccount", a.s.autoFillAccount ? "1" : "0", path);
    WritePrivateProfileStringA("AutoLogin", "AutoFillPassword", a.s.autoFillPassword ? "1" : "0", path);
    WritePrivateProfileStringA("AutoLogin", "AutoRelogin", a.s.autoRelogin ? "1" : "0", path);
    WriteIntKey("AutoLogin", "ClickIntervalMs", a.s.clickIntervalMs, path);
    WriteIntKey("AutoLogin", "ClickRetryMs", a.s.clickRetryMs, path);
    WriteIntKey("AutoLogin", "ClickMethod", a.s.clickMethod, path);
    WriteIntKey("AutoLogin", "ButtonIdOverride", a.s.buttonIdOverride, path);
    WriteIntKey("AutoLogin", "AccountEditIndex", a.s.accountEditIndex, path);
    WriteIntKey("AutoLogin", "PasswordEditIndex", a.s.passwordEditIndex, path);

    // Feature.* -> their coinfo.ini sections/keys (the Waypoints row expands
    // to WaypointCount/WaypointN below).
    for (int i = 0; i < kFeatCount; i++)
    {
        if (gFeats[i].kind == K_TEXT)
            continue;
        std::string v = GetFeat(a, gFeats[i].key, gFeats[i].def);
        if (gFeats[i].kind == K_CHECK)
            WritePrivateProfileStringA(gFeats[i].coinSection, gFeats[i].coinKey,
                atoi(v.c_str()) != 0 ? "1" : "0", path);
        else
            WritePrivateProfileStringA(gFeats[i].coinSection, gFeats[i].coinKey,
                v.c_str(), path);
    }
    ExportWaypoints(a, path);

    // Unknown Feature.* keys round-trip under [AutoHunt] with the suffix name.
    for (size_t i = 0; i < a.feats.size(); i++)
        if (!IsKnownFeatKey(a.feats[i].first.c_str()))
            WritePrivateProfileStringA("AutoHunt", a.feats[i].first.c_str(),
                a.feats[i].second.c_str(), path);
}

// ---------------------------------------------------------------------------
// Launch
// ---------------------------------------------------------------------------
static void LaunchSelectedClient(HWND hMain)
{
    if (g_selAccount < 0 || g_selAccount >= (int)g_accounts.size())
    {
        MessageBoxA(hMain, "Select an account", "Account Manager", MB_OK | MB_ICONINFORMATION);
        return;
    }

    // 0. Guard against double-launching a still-running client.
    {
        Account& cur = g_accounts[g_selAccount];
        if (cur.hProc && WaitForSingleObject(cur.hProc, 0) == WAIT_TIMEOUT)
        {
            char msg[256];
            _snprintf_s(msg, sizeof(msg), _TRUNCATE,
                "Client for \"%s\" is already running (pid %lu).\nLaunch another one?",
                cur.name, cur.pid);
            if (MessageBoxA(hMain, msg, "Account Manager",
                    MB_YESNO | MB_ICONQUESTION) != IDYES)
            {
                SetStatus(hMain, "Launch cancelled: client already running (pid %lu)", cur.pid);
                return;
            }
            CloseHandle(cur.hProc);
            cur.hProc = NULL;
        }
    }

    // 1. Auto-save the selected account's current GUI state first.
    Account a = AccountFromGui(hMain, g_accounts[g_selAccount].name, &g_accounts[g_selAccount]);
    g_accounts[g_selAccount] = a;
    WriteAccountIni(a);
    WritePrivateProfileStringA("Global", "LastSelected", a.name, g_cfgPath);
    strncpy_s(g_lastSelected, a.name, _TRUNCATE);

    // 2. Validate the client path (re-prompt when missing/invalid).
    std::string cp = ReadGlobal("ClientPath", "");
    if (cp.empty() || !FileExists(cp.c_str()))
    {
        SetStatus(hMain, "Client path missing - select Conquer.exe");
        if (!PromptForClientPath(hMain))
        {
            SetStatus(hMain, "Launch cancelled: no client path");
            return;
        }
        cp = ReadGlobal("ClientPath", "");
        if (cp.empty() || !FileExists(cp.c_str()))
        {
            SetStatus(hMain, "Launch cancelled: client path still invalid");
            return;
        }
    }
    strncpy_s(g_clientPath, cp.c_str(), _TRUNCATE);

    // 3. clientDir = directory of ClientPath.
    char clientDir[MAX_PATH];
    strcpy_s(clientDir, g_clientPath);
    char* slash = strrchr(clientDir, '\\');
    if (slash)
        *slash = '\0';

    // 4. Transient export into the client dir.
    ExportAccountInfoIni(a, clientDir);
    ExportCoinfoIni(a, clientDir);

    // 5. CreateProcess: "C:\...\Conquer.exe" blacknull
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));
    char cmdline[MAX_PATH + 32];
    _snprintf_s(cmdline, sizeof(cmdline), _TRUNCATE, "\"%s\" blacknull", g_clientPath);

    if (!CreateProcessA(g_clientPath, cmdline, NULL, NULL, FALSE,
            0, NULL, clientDir, &si, &pi))
    {
        DWORD gle = GetLastError();
        LPSTR sysMsg = NULL;
        FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS, NULL, gle, 0, (LPSTR)&sysMsg, 0, NULL);
        char msg[600];
        _snprintf_s(msg, sizeof(msg), _TRUNCATE,
            "CreateProcess failed (error %lu):\n%s\n\nCommand line:\n%s",
            gle, sysMsg ? sysMsg : "(no message)", cmdline);
        if (sysMsg)
            LocalFree(sysMsg);
        MessageBoxA(hMain, msg, "Account Manager", MB_OK | MB_ICONERROR);
        SetStatus(hMain, "Launch failed (error %lu)", gle);
        return;
    }

    CloseHandle(pi.hThread);

    // Keep the process handle so the Status column can track it live.
    g_accounts[g_selAccount].pid = pi.dwProcessId;
    g_accounts[g_selAccount].hProc = pi.hProcess;
    a.pid = pi.dwProcessId;
    a.hProc = pi.hProcess;

    UpdateStatusColumn(hMain);

    // Push the live settings into the DLL via IPC right after launch. The
    // proxy DLL needs a moment to create its window; retry for up to ~8s in
    // a worker thread so a slow startup never freezes the manager UI.
    struct PushCtx { int idx; };
    PushCtx* ctx = new PushCtx{ g_selAccount };
    CreateThread(NULL, 0, [](LPVOID p) -> DWORD
    {
        PushCtx* c = (PushCtx*)p;
        int idx = c->idx;
        delete c;
        Sleep(1500); // give the DLL time to create its IPC window
        if (idx < 0 || idx >= (int)g_accounts.size())
            return 0;
        SendIpcLines(NULL, BuildIpcPayload(g_accounts[idx]));
        return 0;
    }, ctx, 0, NULL);

    SetStatus(hMain, "Launched pid %lu with account %s", pi.dwProcessId, a.name);
}

// ---------------------------------------------------------------------------
// Layout
// ---------------------------------------------------------------------------
static const int MARGIN = 10;

// Position the controls of every tab inside the tab control's display rect
// (hidden tabs are moved too - harmless, keeps WM_SIZE simple).
static void Layout(HWND hMain)
{
    RECT rc;
    GetClientRect(hMain, &rc);
    int w = rc.right;
    int h = rc.bottom;
    int y = MARGIN;

    int listH = 190;
    MoveWindow(GetDlgItem(hMain, IDC_LIST), MARGIN, y, w - MARGIN * 2, listH, TRUE);
    y += listH + 10;

    // Left column: account / password edits.
    int labelW = 110;
    int editW = w / 2 - labelW - MARGIN * 2;
    MoveWindow(GetDlgItem(hMain, IDC_LBL_FIRST + 0), MARGIN, y + 3, labelW - 6, 18, TRUE);
    MoveWindow(GetDlgItem(hMain, IDC_EDIT_ACCOUNT), MARGIN + labelW, y, editW, 22, TRUE);
    MoveWindow(GetDlgItem(hMain, IDC_LBL_FIRST + 1), MARGIN, y + 31, labelW - 6, 18, TRUE);
    MoveWindow(GetDlgItem(hMain, IDC_EDIT_PASSWORD), MARGIN + labelW, y + 28, editW, 22, TRUE);

    // Right column: buttons.
    int bx = w - 180 - MARGIN, bw = 180;
    MoveWindow(GetDlgItem(hMain, IDC_BTN_ADD), bx, y, bw, 26, TRUE);
    MoveWindow(GetDlgItem(hMain, IDC_BTN_SAVE), bx, y + 30, bw, 26, TRUE);
    MoveWindow(GetDlgItem(hMain, IDC_BTN_DELETE), bx, y + 60, bw, 26, TRUE);
    MoveWindow(GetDlgItem(hMain, IDC_BTN_LAUNCH), bx, y + 90, bw, 30, TRUE);
    MoveWindow(GetDlgItem(hMain, IDC_BTN_KILL), bx, y + 124, bw, 26, TRUE);
    MoveWindow(GetDlgItem(hMain, IDC_BTN_PUSH), bx, y + 154, bw, 26, TRUE);
    MoveWindow(GetDlgItem(hMain, IDC_BTN_PATH), bx, y + 184, bw, 26, TRUE);
    y += 220;

    // Tab control fills the rest above the status bar.
    HWND tab = GetDlgItem(hMain, IDC_TABS);
    MoveWindow(tab, MARGIN, y, w - MARGIN * 2, h - y - 32, TRUE);

    // Tab display area (in main-window client coords).
    RECT dr;
    GetClientRect(tab, &dr);
    SendMessage(tab, TCM_ADJUSTRECT, FALSE, (LPARAM)&dr);
    POINT p0 = { dr.left, dr.top };
    ClientToScreen(tab, &p0);
    ScreenToClient(hMain, &p0);
    int tx = p0.x + 4, ty = p0.y + 4;
    int tw = (dr.right - dr.left) - 8;
    int rowH = 22;

    // --- Tab 0: Login ---
    int lx = tx, ly = ty;
    MoveWindow(GetDlgItem(hMain, IDC_CHK_FILL_ACCT), lx, ly, 130, 20, TRUE);
    MoveWindow(GetDlgItem(hMain, IDC_CHK_FILL_PASS), lx + 140, ly, 140, 20, TRUE);
    MoveWindow(GetDlgItem(hMain, IDC_CHK_AUTOCLICK), lx, ly + rowH, 130, 20, TRUE);
    MoveWindow(GetDlgItem(hMain, IDC_CHK_RELOGIN), lx + 140, ly + rowH, 140, 20, TRUE);
    ly += rowH * 2 + 6;
    MoveWindow(GetDlgItem(hMain, IDC_LBL_FIRST + 3), lx, ly + 3, 100, 18, TRUE);
    MoveWindow(GetDlgItem(hMain, IDC_COMBO_METHOD), lx + 105, ly, 170, 200, TRUE);
    ly += 30;
    struct LoginInt { int ed; int lbl; const char* text; };
    const LoginInt lints[5] =
    {
        { IDC_ED_CLICKINT,   IDC_LBL_LOGININT + 0, "Click Interval (ms)" },
        { IDC_ED_CLICKRETRY, IDC_LBL_LOGININT + 1, "Click Retry (ms)" },
        { IDC_ED_BTNOR,      IDC_LBL_LOGININT + 2, "Button Id Override" },
        { IDC_ED_ACCTIDX,    IDC_LBL_LOGININT + 3, "Account Edit Index" },
        { IDC_ED_PASSIDX,    IDC_LBL_LOGININT + 4, "Password Edit Index" },
    };
    for (int i = 0; i < 5; i++)
    {
        int col = i % 2, row = i / 2;
        int cx = lx + col * (tw / 2), cy = ly + row * 28;
        MoveWindow(GetDlgItem(hMain, lints[i].lbl), cx, cy + 3, 130, 18, TRUE);
        MoveWindow(GetDlgItem(hMain, lints[i].ed), cx + 135, cy, 70, 22, TRUE);
    }

    // --- Feature tabs (1..3): checkboxes flow 3-per-row, then int pairs
    // 2-per-row, then the waypoints text row (table order guarantees
    // checks -> ints -> text within each tab). ---
    for (int t = 1; t < 4; t++)
    {
        int fx = tx, fy = ty;

        // Auto Hunt tab: hunt status + Start/Stop occupy the first two rows
        // before the feature checkboxes, so the offsets below shift down.
        if (t == 1)
        {
            MoveWindow(GetDlgItem(hMain, IDC_LBL_HUNTSTATE), fx, fy, tw - 8, 18, TRUE);
            MoveWindow(GetDlgItem(hMain, IDC_BTN_HUNT_ON), fx, fy + 20, 110, 24, TRUE);
            MoveWindow(GetDlgItem(hMain, IDC_BTN_HUNT_OFF), fx + 116, fy + 20, 110, 24, TRUE);
            fy += 48;
        }
        int chkCols = 3, nInt = 0;
        for (int i = 0; i < kFeatCount; i++)
            if (gFeats[i].tab == t && gFeats[i].kind == K_INT) nInt++;
        int placed = 0;
        for (int i = 0; i < kFeatCount; i++)
        {
            if (gFeats[i].tab != t || gFeats[i].kind != K_CHECK)
                continue;
            int col = placed % chkCols, row = placed / chkCols;
            MoveWindow(GetDlgItem(hMain, IDC_FEAT_CHK_FIRST + i),
                fx + col * (tw / chkCols), fy + row * rowH,
                (tw / chkCols) - 4, 20, TRUE);
            placed++;
        }
        fy += ((placed + chkCols - 1) / chkCols) * rowH + 6;
        // Int fields: label + edit, 2 per row.
        placed = 0;
        for (int i = 0; i < kFeatCount; i++)
        {
            if (gFeats[i].tab != t || gFeats[i].kind != K_INT)
                continue;
            int col = placed % 2, row = placed / 2;
            int cx = fx + col * (tw / 2), cy = fy + row * 28;
            MoveWindow(GetDlgItem(hMain, IDC_FEAT_LBL_FIRST + i), cx, cy + 3, 135, 18, TRUE);
            MoveWindow(GetDlgItem(hMain, IDC_FEAT_EDIT_FIRST + i), cx + 140, cy, 70, 22, TRUE);
            placed++;
        }
        if (nInt)
            fy += ((nInt + 1) / 2) * 28 + 6;
        // Text row (waypoints): label + wide edit.
        for (int i = 0; i < kFeatCount; i++)
        {
            if (gFeats[i].tab != t || gFeats[i].kind != K_TEXT)
                continue;
            MoveWindow(GetDlgItem(hMain, IDC_FEAT_LBL_FIRST + i), fx, fy + 3, 135, 18, TRUE);
            MoveWindow(GetDlgItem(hMain, IDC_FEAT_EDIT_FIRST + i), fx + 140, fy, tw - 145, 22, TRUE);
        }
    }

    // Status bar.
    MoveWindow(GetDlgItem(hMain, IDC_STATIC_STATUS), MARGIN, h - 26, w - MARGIN * 2, 20, TRUE);
}

// Show/hide per-tab controls for the currently selected tab.
static void ApplyTabVisibility(HWND hMain)
{
    HWND tab = GetDlgItem(hMain, IDC_TABS);
    int cur = (int)SendMessage(tab, TCM_GETCURSEL, 0, 0);
    ShowWindow(GetDlgItem(hMain, IDC_LBL_HUNTSTATE), cur == 1 ? SW_SHOW : SW_HIDE);
    ShowWindow(GetDlgItem(hMain, IDC_BTN_HUNT_ON), cur == 1 ? SW_SHOW : SW_HIDE);
    ShowWindow(GetDlgItem(hMain, IDC_BTN_HUNT_OFF), cur == 1 ? SW_SHOW : SW_HIDE);
    for (int i = 0; i < kFeatCount; i++)
    {
        BOOL vis = (gFeats[i].tab == cur) ? SW_SHOW : SW_HIDE;
        if (gFeats[i].kind == K_CHECK)
            ShowWindow(GetDlgItem(hMain, IDC_FEAT_CHK_FIRST + i), vis);
        else
        {
            ShowWindow(GetDlgItem(hMain, IDC_FEAT_EDIT_FIRST + i), vis);
            ShowWindow(GetDlgItem(hMain, IDC_FEAT_LBL_FIRST + i), vis);
        }
    }
    // Login-tab controls (table rows 0-4 chks, combo, login ints).
    BOOL vis = (cur == 0) ? SW_SHOW : SW_HIDE;
    for (int id = IDC_CHK_FILL_ACCT; id <= IDC_CHK_RELOGIN; id++)
        ShowWindow(GetDlgItem(hMain, id), vis);
    ShowWindow(GetDlgItem(hMain, IDC_COMBO_METHOD), vis);
    ShowWindow(GetDlgItem(hMain, IDC_LBL_FIRST + 3), vis);
    for (int i = 0; i < 5; i++)
    {
        ShowWindow(GetDlgItem(hMain, IDC_LBL_LOGININT + i), vis);
        ShowWindow(GetDlgItem(hMain, IDC_ED_CLICKINT + i), vis);
    }
}

// ---------------------------------------------------------------------------
// WndProc
// ---------------------------------------------------------------------------
static LRESULT CALLBACK WndProc(HWND hMain, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
    case WM_CREATE:
    {
        CREATESTRUCTA* cs = (CREATESTRUCTA*)lParam;
        HINSTANCE hInst = cs->hInstance;
        HFONT hf = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

        // ListView.
        HWND lv = CreateWindowExA(0, WC_LISTVIEWA, "",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
            0, 0, 100, 100, hMain, (HMENU)(INT_PTR)IDC_LIST, hInst, NULL);
        ListView_SetExtendedListViewStyle(lv, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
        LVCOLUMNA col;
        memset(&col, 0, sizeof(col));
        col.mask = LVCF_WIDTH | LVCF_TEXT;
        col.cx = 200;
        col.pszText = (LPSTR)"Account";
        ListView_InsertColumn(lv, 0, &col);
        memset(&col, 0, sizeof(col));
        col.mask = LVCF_WIDTH | LVCF_TEXT;
        col.cx = 150;
        col.pszText = (LPSTR)"Status";
        ListView_InsertColumn(lv, 1, &col);

        // Edits + labels.
        struct EditDef { int id; const char* label; DWORD style; };
        const EditDef edits[2] =
        {
            { IDC_EDIT_ACCOUNT,  "Account:",  0 },
            { IDC_EDIT_PASSWORD, "Password:", ES_PASSWORD },
        };
        for (int i = 0; i < 2; i++)
        {
            HWND hS = CreateWindowExA(0, "STATIC", edits[i].label,
                WS_CHILD | WS_VISIBLE, 0, 0, 100, 18, hMain,
                (HMENU)(INT_PTR)(IDC_LBL_FIRST + i), hInst, NULL);
            HWND hE = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL | edits[i].style,
                0, 0, 100, 22, hMain, (HMENU)(INT_PTR)edits[i].id, hInst, NULL);
            SendMessage(hS, WM_SETFONT, (WPARAM)hf, TRUE);
            SendMessage(hE, WM_SETFONT, (WPARAM)hf, TRUE);
        }

        // Buttons.
        struct BtnDef { int id; const char* label; };
        const BtnDef btns[7] =
        {
            { IDC_BTN_ADD,    "Add" },
            { IDC_BTN_SAVE,   "Save" },
            { IDC_BTN_DELETE, "Delete" },
            { IDC_BTN_LAUNCH, "Launch Client" },
            { IDC_BTN_KILL,   "Kill Client" },
            { IDC_BTN_PUSH,   "Push to Client" },
            { IDC_BTN_PATH,   "Change Client Path" },
        };
        for (int i = 0; i < 7; i++)
        {
            HWND hB = CreateWindowExA(0, "BUTTON", btns[i].label,
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                0, 0, 100, 26, hMain, (HMENU)(INT_PTR)btns[i].id, hInst, NULL);
            SendMessage(hB, WM_SETFONT, (WPARAM)hf, TRUE);
        }

        // Tab control.
        HWND tab = CreateWindowExA(0, WC_TABCONTROLA, "",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | TCS_FIXEDWIDTH,
            0, 0, 100, 100, hMain, (HMENU)(INT_PTR)IDC_TABS, hInst, NULL);
        SendMessage(tab, WM_SETFONT, (WPARAM)hf, TRUE);
        for (int i = 0; i < 4; i++)
        {
            TCITEMA tci;
            memset(&tci, 0, sizeof(tci));
            tci.mask = TCIF_TEXT;
            tci.pszText = (LPSTR)kTabNames[i];
            SendMessage(tab, TCM_INSERTITEM, (WPARAM)i, (LPARAM)&tci);
        }

        // Login-tab controls: 4 checkboxes, combo + label, 5 int pairs.
        struct ChkDef { int id; const char* label; };
        const ChkDef chks[4] =
        {
            { IDC_CHK_FILL_ACCT, "Auto Fill Account" },
            { IDC_CHK_FILL_PASS, "Auto Fill Password" },
            { IDC_CHK_AUTOCLICK, "Auto Click Login" },
            { IDC_CHK_RELOGIN,   "Auto Relogin" },
        };
        for (int i = 0; i < 4; i++)
        {
            HWND hC = CreateWindowExA(0, "BUTTON", chks[i].label,
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
                0, 0, 130, 20, hMain, (HMENU)(INT_PTR)chks[i].id, hInst, NULL);
            SendMessage(hC, WM_SETFONT, (WPARAM)hf, TRUE);
        }
        HWND hS3 = CreateWindowExA(0, "STATIC", "Click method:",
            WS_CHILD | WS_VISIBLE, 0, 0, 100, 18, hMain,
            (HMENU)(INT_PTR)(IDC_LBL_FIRST + 3), hInst, NULL);
        SendMessage(hS3, WM_SETFONT, (WPARAM)hf, TRUE);
        HWND hCombo = CreateWindowExA(0, "COMBOBOX", "",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST,
            0, 0, 160, 200, hMain, (HMENU)(INT_PTR)IDC_COMBO_METHOD, hInst, NULL);
        const char* methods[4] =
        {
            "0 - Message (no cursor)",
            "1 - SendInput",
            "2 - BM_CLICK (dead)",
            "3 - Direct handler",
        };
        for (int i = 0; i < 4; i++)
            SendMessage(hCombo, CB_ADDSTRING, 0, (LPARAM)methods[i]);
        SendMessage(hCombo, CB_SETCURSEL, 0, 0);
        SendMessage(hCombo, WM_SETFONT, (WPARAM)hf, TRUE);
        struct LoginIntDef { const char* label; };
        const LoginIntDef lints[5] =
        {
            { "Click Interval (ms)" },
            { "Click Retry (ms)" },
            { "Button Id Override" },
            { "Account Edit Index" },
            { "Password Edit Index" },
        };
        for (int i = 0; i < 5; i++)
        {
            HWND hL = CreateWindowExA(0, "STATIC", lints[i].label,
                WS_CHILD | WS_VISIBLE, 0, 0, 130, 18, hMain,
                (HMENU)(INT_PTR)(IDC_LBL_LOGININT + i), hInst, NULL);
            HWND hE = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL | ES_NUMBER,
                0, 0, 70, 22, hMain, (HMENU)(INT_PTR)(IDC_ED_CLICKINT + i), hInst, NULL);
            SendMessage(hL, WM_SETFONT, (WPARAM)hf, TRUE);
            SendMessage(hE, WM_SETFONT, (WPARAM)hf, TRUE);
        }

        // Feature controls from the table (created hidden; the tab logic
        // shows the active tab's rows).
        for (int i = 0; i < kFeatCount; i++)
        {
            if (gFeats[i].kind == K_CHECK)
            {
                HWND hC = CreateWindowExA(0, "BUTTON", gFeats[i].label,
                    WS_CHILD | WS_TABSTOP | BS_AUTOCHECKBOX,
                    0, 0, 130, 20, hMain,
                    (HMENU)(INT_PTR)(IDC_FEAT_CHK_FIRST + i), hInst, NULL);
                SendMessage(hC, WM_SETFONT, (WPARAM)hf, TRUE);
            }
            else
            {
                HWND hL = CreateWindowExA(0, "STATIC", gFeats[i].label,
                    WS_CHILD, 0, 0, 135, 18, hMain,
                    (HMENU)(INT_PTR)(IDC_FEAT_LBL_FIRST + i), hInst, NULL);
                HWND hE = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
                    WS_CHILD | WS_TABSTOP | ES_AUTOHSCROLL,
                    0, 0, 70, 22, hMain,
                    (HMENU)(INT_PTR)(IDC_FEAT_EDIT_FIRST + i), hInst, NULL);
                SendMessage(hL, WM_SETFONT, (WPARAM)hf, TRUE);
                SendMessage(hE, WM_SETFONT, (WPARAM)hf, TRUE);
            }
        }

        // Auto Hunt: Start/Stop + live hunting indicator (character is
        // hunting or idle). Text is driven by the DLL's title heartbeat.
        HWND hHSt = CreateWindowExA(0, "STATIC", "Character: idle  |  Waypoint -/-  |  Pos -,-",
            WS_CHILD, 0, 0, 100, 18, hMain, (HMENU)(INT_PTR)IDC_LBL_HUNTSTATE, hInst, NULL);
        SendMessage(hHSt, WM_SETFONT, (WPARAM)hf, TRUE);
        HWND hOn = CreateWindowExA(0, "BUTTON", "Start Hunting",
            WS_CHILD | WS_TABSTOP | BS_PUSHBUTTON,
            0, 0, 110, 24, hMain, (HMENU)(INT_PTR)IDC_BTN_HUNT_ON, hInst, NULL);
        SendMessage(hOn, WM_SETFONT, (WPARAM)hf, TRUE);
        HWND hOff = CreateWindowExA(0, "BUTTON", "Stop Hunting",
            WS_CHILD | WS_TABSTOP | BS_PUSHBUTTON,
            0, 0, 110, 24, hMain, (HMENU)(INT_PTR)IDC_BTN_HUNT_OFF, hInst, NULL);
        SendMessage(hOff, WM_SETFONT, (WPARAM)hf, TRUE);

        // Status bar.
        HWND hSt = CreateWindowExA(0, "STATIC", "",
            WS_CHILD | WS_VISIBLE | SS_LEFTNOWORDWRAP,
            0, 0, 100, 20, hMain, (HMENU)(INT_PTR)IDC_STATIC_STATUS, hInst, NULL);
        SendMessage(hSt, WM_SETFONT, (WPARAM)hf, TRUE);

        // Data.
        BuildPaths();
        LoadAll();
        RefreshList(hMain);
        if (g_selAccount >= 0)
            GuiShowAccount(hMain, g_selAccount);
        else
            GuiClearFields(hMain); // add-mode defaults
        EnsureClientPath(hMain);
        ApplyTabVisibility(hMain);
        SetTimer(hMain, 1, 2000, NULL); // live client status poll
        SetStatus(hMain, "%d account(s) loaded", (int)g_accounts.size());
        return 0;
    }

    case WM_SIZE:
        if (wParam != SIZE_MINIMIZED)
            Layout(hMain);
        return 0;

    case WM_TIMER:
        if (wParam == TIMER_STATUS)
        {
            UpdateStatusColumn(hMain);
            PollHuntStatus(hMain);
        }
        else if (wParam == TIMER_AUTOSAVE)
            FlushAutosave(hMain);
        return 0;

    case WM_GETMINMAXINFO:
    {
        MINMAXINFO* mmi = (MINMAXINFO*)lParam;
        mmi->ptMinTrackSize.x = 660;
        mmi->ptMinTrackSize.y = 640;
        return 0;
    }

    case WM_NOTIFY:
    {
        NMHDR* nm = (NMHDR*)lParam;
        if (nm->idFrom == IDC_LIST && nm->code == LVN_ITEMCHANGED)
        {
            NMLISTVIEW* nlv = (NMLISTVIEW*)lParam;
            if (g_loading || !(nlv->uChanged & LVIF_STATE))
                return 0;
            if ((nlv->uNewState & LVIS_SELECTED) && nlv->iItem >= 0)
            {
                g_selAccount = nlv->iItem;
                GuiShowAccount(hMain, nlv->iItem);
                WritePrivateProfileStringA("Global", "LastSelected",
                    g_accounts[nlv->iItem].name, g_cfgPath);
                strncpy_s(g_lastSelected, g_accounts[nlv->iItem].name, _TRUNCATE);
                SetStatus(hMain, "Selected account: %s", g_accounts[nlv->iItem].name);
            }
            else if (!(nlv->uNewState & LVIS_SELECTED)
                && (nlv->uOldState & LVIS_SELECTED))
            {
                FlushAutosave(hMain);
                // Deselected (clicked empty space) - name becomes editable.
                g_selAccount = -1;
                GuiClearFields(hMain);
                SetStatus(hMain, "No account selected (name editable - type one and press Add)");
            }
        }
        else if (nm->idFrom == IDC_TABS && nm->code == TCN_SELCHANGE)
        {
            ApplyTabVisibility(hMain);
            return 0;
        }
        return 0;
    }

    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case IDC_BTN_ADD:
        {
            char name[64] = { 0 };
            GetDlgItemTextA(hMain, IDC_EDIT_ACCOUNT, name, sizeof(name));
            if (!name[0])
            {
                MessageBoxA(hMain, "Enter an account name first", "Account Manager",
                    MB_OK | MB_ICONINFORMATION);
                SetStatus(hMain, "Add cancelled: empty name");
                return 0;
            }
            if (FindAccountByName(name))
            {
                char msg[256];
                _snprintf_s(msg, sizeof(msg), _TRUNCATE, "Account \"%s\" already exists", name);
                MessageBoxA(hMain, msg, "Account Manager", MB_OK | MB_ICONWARNING);
                SetStatus(hMain, "Add cancelled: %s already exists", name);
                return 0;
            }
            if ((int)g_accounts.size() >= kMaxAccounts)
            {
                MessageBoxA(hMain, "Account limit reached (64)", "Account Manager",
                    MB_OK | MB_ICONWARNING);
                return 0;
            }
            // New section with defaults + current GUI values.
            Account a = AccountFromGui(hMain, name);
            WriteAccountIni(a);
            g_accounts.push_back(a);
            g_selAccount = (int)g_accounts.size() - 1;
            RefreshList(hMain);
            GuiShowAccount(hMain, g_selAccount);
            SetStatus(hMain, "Added account: %s", name);
            return 0;
        }

        case IDC_BTN_SAVE:
        {
            if (g_selAccount < 0 || g_selAccount >= (int)g_accounts.size())
            {
                SetStatus(hMain, "No account selected - nothing to save");
                return 0;
            }
            Account a = AccountFromGui(hMain, g_accounts[g_selAccount].name, &g_accounts[g_selAccount]);
            g_accounts[g_selAccount] = a;
            WriteAccountIni(a);
            RefreshList(hMain);
            GuiShowAccount(hMain, g_selAccount);
            SetStatus(hMain, "Saved account: %s", a.name);
            return 0;
        }

        case IDC_BTN_DELETE:
        {
            if (g_selAccount < 0 || g_selAccount >= (int)g_accounts.size())
            {
                SetStatus(hMain, "No account selected - nothing to delete");
                return 0;
            }
            char name[64];
            strcpy_s(name, g_accounts[g_selAccount].name);
            char msg[256];
            _snprintf_s(msg, sizeof(msg), _TRUNCATE, "Delete account \"%s\"?", name);
            if (MessageBoxA(hMain, msg, "Account Manager",
                    MB_OKCANCEL | MB_ICONQUESTION) != IDOK)
            {
                SetStatus(hMain, "Delete cancelled");
                return 0;
            }
            // Wipe every key (incl. Feature.*), then drop the section.
            char sec[96];
            _snprintf_s(sec, sizeof(sec), _TRUNCATE, "Account:%s", name);
            char secbuf[8192];
            DWORD got = GetPrivateProfileSectionA(sec, secbuf, sizeof(secbuf), g_cfgPath);
            if (got > 0 && got < sizeof(secbuf) - 2)
            {
                for (char* p = secbuf; *p; p += strlen(p) + 1)
                {
                    char* eq = strchr(p, '=');
                    if (!eq)
                        continue;
                    *eq = 0;
                    WritePrivateProfileStringA(sec, p, NULL, g_cfgPath);
                    *eq = '=';
                }
            }
            WritePrivateProfileStringA(sec, NULL, NULL, g_cfgPath);
            // Release the client handle (a running client keeps running).
            if (g_accounts[g_selAccount].hProc)
                CloseHandle(g_accounts[g_selAccount].hProc);
            KillTimer(hMain, TIMER_AUTOSAVE);
            g_accounts.erase(g_accounts.begin() + g_selAccount);
            g_selAccount = -1;
            RefreshList(hMain);
            GuiClearFields(hMain);
            SetStatus(hMain, "Deleted account: %s", name);
            return 0;
        }

        case IDC_BTN_PATH:
            if (PromptForClientPath(hMain))
                SetStatus(hMain, "Client path: %s", g_clientPath);
            else
                SetStatus(hMain, "Path change cancelled");
            return 0;

        case IDC_BTN_LAUNCH:
            LaunchSelectedClient(hMain);
            return 0;

        case IDC_BTN_KILL:
            KillSelectedClient(hMain);
            return 0;

        case IDC_BTN_PUSH:
            // Save first so accounts.txt matches what we push, then send.
            if (g_selAccount >= 0 && g_selAccount < (int)g_accounts.size())
            {
                Account a = AccountFromGui(hMain, g_accounts[g_selAccount].name, &g_accounts[g_selAccount]);
                g_accounts[g_selAccount] = a;
                WriteAccountIni(a);
            }
            PushAccountToClient(hMain, "manual");
            return 0;

        case IDC_BTN_HUNT_ON:
            SendHuntCommand(hMain, "AutoHuntStart");
            return 0;

        case IDC_BTN_HUNT_OFF:
            SendHuntCommand(hMain, "AutoHuntStop");
            return 0;
        }

        // Live push + auto-save: any per-account control change updates the
        // selected account's own section in accounts.txt (debounced) and, if
        // its client is running, pushes the change into the DLL over IPC.
        if (HIWORD(wParam) == BN_CLICKED || HIWORD(wParam) == CBN_SELCHANGE
            || HIWORD(wParam) == EN_CHANGE)
        {
            if (g_loading)
                return 0;
            int id = LOWORD(wParam);
            // Per-account controls: login + all Feature.<Key> rows + the
            // account/password edits.
            bool isSetting =
                (id == IDC_EDIT_ACCOUNT && false) // name is identity, never a setting
                || (id == IDC_EDIT_PASSWORD)
                || (id >= IDC_CHK_FILL_ACCT && id <= IDC_ED_PASSIDX)
                || (id >= IDC_FEAT_CHK_FIRST && id < IDC_FEAT_CHK_FIRST + kFeatCount)
                || (id >= IDC_FEAT_EDIT_FIRST && id < IDC_FEAT_EDIT_FIRST + kFeatCount);
            if (isSetting && g_selAccount >= 0 && g_selAccount < (int)g_accounts.size())
            {
                Account a = AccountFromGui(hMain, g_accounts[g_selAccount].name, &g_accounts[g_selAccount]);
                g_accounts[g_selAccount] = a;
                ScheduleAutosave(hMain);

                Account& live = g_accounts[g_selAccount];
                if (live.hProc && WaitForSingleObject(live.hProc, 0) == WAIT_TIMEOUT)
                {
                    if (SendIpcLines(hMain, BuildIpcPayload(a)))
                        SetStatus(hMain, "%s -> applied to running client", IpcKeyFor(id));
                    else
                        SetStatus(hMain, "%s -> no IPC window (client starting?)", IpcKeyFor(id));
                }
            }
        }
        break;

    case WM_DESTROY:
        FlushAutosave(hMain);
        KillTimer(hMain, TIMER_AUTOSAVE);
        KillTimer(hMain, TIMER_STATUS);
        for (size_t i = 0; i < g_accounts.size(); i++)
            if (g_accounts[i].hProc)
                CloseHandle(g_accounts[i].hProc);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hMain, msg, wParam, lParam);
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------
int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, PWSTR, int nCmdShow)
{
    BuildPaths();

    INITCOMMONCONTROLSEX icc;
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_LISTVIEW_CLASSES | ICC_TAB_CLASSES;
    InitCommonControlsEx(&icc);

    WNDCLASSEXA wc;
    memset(&wc, 0, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = "AccountMgrWnd";
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    if (!RegisterClassExA(&wc))
        return 1;

    HWND hMain = CreateWindowExA(0, wc.lpszClassName, "Account Manager",
        WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 760, 760,
        NULL, NULL, hInst, NULL);
    if (!hMain)
        return 1;

    ShowWindow(hMain, nCmdShow);
    UpdateWindow(hMain);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return (int)msg.wParam;
}
