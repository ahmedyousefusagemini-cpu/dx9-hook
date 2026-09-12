// ============================================================================
// AccountManager.exe - portable Win32 launcher / control plane for Conquer.exe
// ----------------------------------------------------------------------------
// Single config file: accounts.txt next to this exe. Holds [Global] (ClientPath,
// LastSelected) and one [Account:<name>] section per account, each with its own
// complete settings set (login automation + per-feature toggles). No registry,
// no other files owned by the manager.
//
// Launch flow: auto-save selected account -> validate client path -> write
// transient accountinfo.ini / coinfo.ini into the client dir (regenerated every
// launch; the hook DLL reads those two files from the game dir at load) ->
// CreateProcess("\"<ClientPath>\" blacknull") with the client dir as CWD.
// ============================================================================

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
#define IDC_EDIT_TOKEN     1009
#define IDC_COMBO_METHOD   1010
#define IDC_CHK_FILL_ACCT  1011
#define IDC_CHK_FILL_PASS  1012
#define IDC_CHK_AUTOCLICK  1013
#define IDC_CHK_RELOGIN    1014
// Per-account bot feature checkboxes (extensible): add one entry in kFeatures
// below; the Feature.<Key> line round-trips in accounts.txt automatically.
#define IDC_CHK_FEAT_FIRST 1100   // feature i -> IDC_CHK_FEAT_FIRST + i
#define IDC_LBL_FIRST      2000   // static labels 2000..2003
#define IDC_STATIC_STATUS  1900

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

// One checkbox-backed feature. coinSection/coinKey = where it lands inside the
// transient coinfo.ini written to the client dir (must match the hook DLL's
// config.cpp LoadConfig key names).
struct FeatureInfo
{
    const char* iniKey;       // Feature.<Key> in accounts.txt
    const char* label;        // checkbox text
    const char* coinSection;  // coinfo.ini section
    const char* coinKey;      // coinfo.ini key
    bool        def;          // default when the key is missing
};

static const FeatureInfo kFeatures[] =
{
    { "AutoHuntOnLogin", "Auto Hunt On Login", "AutoHunt", "AutoHuntOnLogin", false },
    { "NotifyServer",    "Notify Server",      "AutoHunt", "NotifyServer",    false },
    { "SpoofVipLevel",   "Spoof Vip Level",    "AutoHunt", "SpoofVipLevel",   false },
    { "SpeedEnabled",    "Speed Enabled",      "Speed",    "SpeedEnabled",    false },
    { "AllowXpSkills",   "Allow XP Skills",    "XpSkill",  "AllowXpSkills",    false },
    { "BuffsEnabled",    "Buffs Enabled",       "Buffs",    "BuffsEnabled",    false },
    { "GearSwap",        "Gear Swap",          "GearSwap", "AutoSwap",        false },
};
static const int kFeatureCount = sizeof(kFeatures) / sizeof(kFeatures[0]);

struct Account
{
    char name[64];
    char pass[128];
    char token[64];
    Settings s;
    bool feature[kFeatureCount];
    std::vector<std::pair<std::string, std::string>> extraKeys; // unknown Feature.*
    bool hasStatus;   // launched at least once this session -> "Last used"
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
    memset(a.token, 0, sizeof(a.token));
    Defaults(a.s);
    for (int i = 0; i < kFeatureCount; i++)
        a.feature[i] = false;
    a.extraKeys.clear();
    a.hasStatus = false;
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
        GetPrivateProfileStringA(sec, "Token", "", a.token, sizeof(a.token), g_cfgPath);

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

        for (int i = 0; i < kFeatureCount; i++)
            a.feature[i] = GetPrivateProfileIntA(sec, kFeatures[i].iniKey,
                kFeatures[i].def ? 1 : 0, g_cfgPath) != 0;

        // Round-trip unknown Feature.* keys untouched.
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
                bool known = false;
                for (int i = 0; i < kFeatureCount; i++)
                    if (_stricmp(k.c_str() + 8, kFeatures[i].iniKey) == 0)
                    {
                        known = true;
                        break;
                    }
                if (!known)
                    a.extraKeys.push_back({ k, v });
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
    WritePrivateProfileStringA(sec, "Token", a.token, g_cfgPath);
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
    for (int i = 0; i < kFeatureCount; i++)
    {
        char key[80];
        _snprintf_s(key, sizeof(key), _TRUNCATE, "Feature.%s", kFeatures[i].iniKey);
        WritePrivateProfileStringA(sec, key, a.feature[i] ? "1" : "0", g_cfgPath);
    }
    for (size_t i = 0; i < a.extraKeys.size(); i++)
        WritePrivateProfileStringA(sec, a.extraKeys[i].first.c_str(),
            a.extraKeys[i].second.c_str(), g_cfgPath);
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
static Account AccountFromGui(HWND hMain, const char* name)
{
    Account a;
    ClearAccount(a);
    strcpy_s(a.name, name);
    GetDlgItemTextA(hMain, IDC_EDIT_PASSWORD, a.pass, sizeof(a.pass));
    GetDlgItemTextA(hMain, IDC_EDIT_TOKEN, a.token, sizeof(a.token));
    a.s.autoFillAccount   = (IsDlgButtonChecked(hMain, IDC_CHK_FILL_ACCT) == BST_CHECKED);
    a.s.autoFillPassword  = (IsDlgButtonChecked(hMain, IDC_CHK_FILL_PASS) == BST_CHECKED);
    a.s.autoClick         = (IsDlgButtonChecked(hMain, IDC_CHK_AUTOCLICK) == BST_CHECKED);
    a.s.autoRelogin       = (IsDlgButtonChecked(hMain, IDC_CHK_RELOGIN) == BST_CHECKED);
    LRESULT cm = SendMessageA(GetDlgItem(hMain, IDC_COMBO_METHOD), CB_GETCURSEL, 0, 0);
    a.s.clickMethod = (cm >= 0 && cm <= 3) ? (int)cm : 0;
    for (int i = 0; i < kFeatureCount; i++)
        a.feature[i] = (IsDlgButtonChecked(hMain, IDC_CHK_FEAT_FIRST + i) == BST_CHECKED);
    a.hasStatus = false;
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
    SetDlgItemTextA(hMain, IDC_EDIT_TOKEN, a.token);
    CheckDlgButton(hMain, IDC_CHK_FILL_ACCT, a.s.autoFillAccount ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(hMain, IDC_CHK_FILL_PASS, a.s.autoFillPassword ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(hMain, IDC_CHK_AUTOCLICK, a.s.autoClick ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(hMain, IDC_CHK_RELOGIN, a.s.autoRelogin ? BST_CHECKED : BST_UNCHECKED);
    int cm = a.s.clickMethod;
    if (cm < 0 || cm > 3) cm = 0; // combo index == ClickMethod value (0-3)
    SendMessageA(GetDlgItem(hMain, IDC_COMBO_METHOD), CB_SETCURSEL, (WPARAM)cm, 0);
    for (int i = 0; i < kFeatureCount; i++)
        CheckDlgButton(hMain, IDC_CHK_FEAT_FIRST + i, a.feature[i] ? BST_CHECKED : BST_UNCHECKED);
    // Name is read-only while a row is selected.
    SendMessageA(GetDlgItem(hMain, IDC_EDIT_ACCOUNT), EM_SETREADONLY, TRUE, 0);
    g_loading = false;
}

static void GuiClearFields(HWND hMain)
{
    g_loading = true;
    SetDlgItemTextA(hMain, IDC_EDIT_ACCOUNT, "");
    SetDlgItemTextA(hMain, IDC_EDIT_PASSWORD, "");
    SetDlgItemTextA(hMain, IDC_EDIT_TOKEN, "");
    CheckDlgButton(hMain, IDC_CHK_FILL_ACCT, BST_CHECKED);
    CheckDlgButton(hMain, IDC_CHK_FILL_PASS, BST_CHECKED);
    CheckDlgButton(hMain, IDC_CHK_AUTOCLICK, BST_UNCHECKED);
    CheckDlgButton(hMain, IDC_CHK_RELOGIN, BST_CHECKED);
    SendMessageA(GetDlgItem(hMain, IDC_COMBO_METHOD), CB_SETCURSEL, 0, 0);
    for (int i = 0; i < kFeatureCount; i++)
        CheckDlgButton(hMain, IDC_CHK_FEAT_FIRST + i, kFeatures[i].def ? BST_CHECKED : BST_UNCHECKED);
    // Name is editable when no row is selected (add mode).
    SendMessageA(GetDlgItem(hMain, IDC_EDIT_ACCOUNT), EM_SETREADONLY, FALSE, 0);
    g_loading = false;
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
            ListView_SetItemText(lv, row, 1,
                (LPSTR)(g_accounts[i].hasStatus ? "Last used" : ""));
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
    WritePrivateProfileStringA("Account1", "Token", a.token, path);
    WritePrivateProfileStringA("Account1", "Use", "1", path);
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

    // Feature.* -> [AutoHunt]/[Speed]/[XpSkill]/[Buffs]/[GearSwap].
    for (int i = 0; i < kFeatureCount; i++)
        WritePrivateProfileStringA(kFeatures[i].coinSection, kFeatures[i].coinKey,
            a.feature[i] ? "1" : "0", path);

    // Unknown Feature.* keys round-trip under [AutoHunt] with the suffix name.
    for (size_t i = 0; i < a.extraKeys.size(); i++)
    {
        const char* dot = strchr(a.extraKeys[i].first.c_str(), '.');
        if (dot)
            WritePrivateProfileStringA("AutoHunt", dot + 1,
                a.extraKeys[i].second.c_str(), path);
    }
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

    // 1. Auto-save the selected account's current GUI state first.
    Account a = AccountFromGui(hMain, g_accounts[g_selAccount].name);
    a.extraKeys = g_accounts[g_selAccount].extraKeys;
    a.hasStatus = g_accounts[g_selAccount].hasStatus;
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

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    g_accounts[g_selAccount].hasStatus = true;
    RefreshList(hMain);
    SetStatus(hMain, "Launched pid %lu with account %s", pi.dwProcessId, a.name);
}

// ---------------------------------------------------------------------------
// Layout
// ---------------------------------------------------------------------------
static const int MARGIN = 10;

static void Layout(HWND hMain)
{
    RECT rc;
    GetClientRect(hMain, &rc);
    int w = rc.right;
    int h = rc.bottom;
    int y = MARGIN;

    int listH = (int)(h * 0.38);
    MoveWindow(GetDlgItem(hMain, IDC_LIST), MARGIN, y, w - MARGIN * 2, listH, TRUE);
    y += listH + 12;

    // Left column: account / password / token edits.
    int labelW = 110;
    int editW = w / 2 - labelW - MARGIN * 2;
    MoveWindow(GetDlgItem(hMain, IDC_LBL_FIRST + 0), MARGIN, y + 3, labelW - 6, 18, TRUE);
    MoveWindow(GetDlgItem(hMain, IDC_EDIT_ACCOUNT), MARGIN + labelW, y, editW, 22, TRUE);
    MoveWindow(GetDlgItem(hMain, IDC_LBL_FIRST + 1), MARGIN, y + 31, labelW - 6, 18, TRUE);
    MoveWindow(GetDlgItem(hMain, IDC_EDIT_PASSWORD), MARGIN + labelW, y + 28, editW, 22, TRUE);
    MoveWindow(GetDlgItem(hMain, IDC_LBL_FIRST + 2), MARGIN, y + 59, labelW - 6, 18, TRUE);
    MoveWindow(GetDlgItem(hMain, IDC_EDIT_TOKEN), MARGIN + labelW, y + 56, editW, 22, TRUE);

    // Right column: buttons.
    int bx = w - 170 - MARGIN, bw = 170;
    MoveWindow(GetDlgItem(hMain, IDC_BTN_ADD), bx, y, bw, 26, TRUE);
    MoveWindow(GetDlgItem(hMain, IDC_BTN_SAVE), bx, y + 30, bw, 26, TRUE);
    MoveWindow(GetDlgItem(hMain, IDC_BTN_DELETE), bx, y + 60, bw, 26, TRUE);
    MoveWindow(GetDlgItem(hMain, IDC_BTN_LAUNCH), bx, y + 90, bw, 30, TRUE);
    MoveWindow(GetDlgItem(hMain, IDC_BTN_PATH), bx, y + 126, bw, 26, TRUE);

    // Auto-login settings.
    int gy = y + 90;
    MoveWindow(GetDlgItem(hMain, IDC_CHK_FILL_ACCT), MARGIN, gy, 130, 20, TRUE);
    MoveWindow(GetDlgItem(hMain, IDC_CHK_FILL_PASS), MARGIN + 135, gy, 140, 20, TRUE);
    MoveWindow(GetDlgItem(hMain, IDC_CHK_AUTOCLICK), MARGIN, gy + 24, 130, 20, TRUE);
    MoveWindow(GetDlgItem(hMain, IDC_CHK_RELOGIN), MARGIN + 135, gy + 24, 140, 20, TRUE);
    MoveWindow(GetDlgItem(hMain, IDC_LBL_FIRST + 3), MARGIN, gy + 50, labelW, 18, TRUE);
    MoveWindow(GetDlgItem(hMain, IDC_COMBO_METHOD), MARGIN + labelW, gy + 48, 160, 200, TRUE);

    // Feature checkbox grid.
    int fy = gy + 78;
    MoveWindow(GetDlgItem(hMain, IDC_LBL_FIRST + 4), MARGIN, fy, 200, 18, TRUE);
    fy += 22;
    int perRow = 3;
    int cellW = (w - MARGIN * 2) / perRow;
    for (int i = 0; i < kFeatureCount; i++)
        MoveWindow(GetDlgItem(hMain, IDC_CHK_FEAT_FIRST + i),
            MARGIN + (i % perRow) * cellW, fy + (i / perRow) * 24,
            cellW - 4, 20, TRUE);

    // Status bar.
    MoveWindow(GetDlgItem(hMain, IDC_STATIC_STATUS), MARGIN, h - 26, w - MARGIN * 2, 20, TRUE);
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
        col.cx = 120;
        col.pszText = (LPSTR)"Status";
        ListView_InsertColumn(lv, 1, &col);

        // Edits + labels.
        struct EditDef { int id; const char* label; DWORD style; };
        const EditDef edits[3] =
        {
            { IDC_EDIT_ACCOUNT,  "Account:",  0 },
            { IDC_EDIT_PASSWORD, "Password:", ES_PASSWORD },
            { IDC_EDIT_TOKEN,    "Token:",    0 },
        };
        for (int i = 0; i < 3; i++)
        {
            HWND hS = CreateWindowExA(0, "STATIC", edits[i].label,
                WS_CHILD | WS_VISIBLE, 0, 0, 100, 18, hMain,
                (HMENU)(INT_PTR)(IDC_LBL_FIRST + i), hInst, NULL);
            HWND hE = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL | edits[i].style,
                0, 0, 100, 22, hMain, (HMENU)(INT_PTR)edits[i].id, hInst, NULL);
            SendMessageA(hS, WM_SETFONT, (WPARAM)hf, TRUE);
            SendMessageA(hE, WM_SETFONT, (WPARAM)hf, TRUE);
        }

        // Buttons.
        struct BtnDef { int id; const char* label; };
        const BtnDef btns[5] =
        {
            { IDC_BTN_ADD,    "Add" },
            { IDC_BTN_SAVE,   "Save" },
            { IDC_BTN_DELETE, "Delete" },
            { IDC_BTN_LAUNCH, "Launch Client" },
            { IDC_BTN_PATH,   "Change Client Path" },
        };
        for (int i = 0; i < 5; i++)
        {
            HWND hB = CreateWindowExA(0, "BUTTON", btns[i].label,
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                0, 0, 100, 26, hMain, (HMENU)(INT_PTR)btns[i].id, hInst, NULL);
            SendMessageA(hB, WM_SETFONT, (WPARAM)hf, TRUE);
        }

        // Auto-login checkboxes.
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
            SendMessageA(hC, WM_SETFONT, (WPARAM)hf, TRUE);
        }

        // ClickMethod combo.
        HWND hS3 = CreateWindowExA(0, "STATIC", "Click method:",
            WS_CHILD | WS_VISIBLE, 0, 0, 100, 18, hMain,
            (HMENU)(INT_PTR)(IDC_LBL_FIRST + 3), hInst, NULL);
        SendMessageA(hS3, WM_SETFONT, (WPARAM)hf, TRUE);
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
            SendMessageA(hCombo, CB_ADDSTRING, 0, (LPARAM)methods[i]);
        SendMessageA(hCombo, CB_SETCURSEL, 0, 0);
        SendMessageA(hCombo, WM_SETFONT, (WPARAM)hf, TRUE);

        // Feature checkboxes.
        HWND hS4 = CreateWindowExA(0, "STATIC", "Bot features:",
            WS_CHILD | WS_VISIBLE, 0, 0, 100, 18, hMain,
            (HMENU)(INT_PTR)(IDC_LBL_FIRST + 4), hInst, NULL);
        SendMessageA(hS4, WM_SETFONT, (WPARAM)hf, TRUE);
        for (int i = 0; i < kFeatureCount; i++)
        {
            HWND hC = CreateWindowExA(0, "BUTTON", kFeatures[i].label,
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
                0, 0, 130, 20, hMain,
                (HMENU)(INT_PTR)(IDC_CHK_FEAT_FIRST + i), hInst, NULL);
            SendMessageA(hC, WM_SETFONT, (WPARAM)hf, TRUE);
        }

        // Status bar.
        HWND hSt = CreateWindowExA(0, "STATIC", "",
            WS_CHILD | WS_VISIBLE | SS_LEFTNOWORDWRAP,
            0, 0, 100, 20, hMain, (HMENU)(INT_PTR)IDC_STATIC_STATUS, hInst, NULL);
        SendMessageA(hSt, WM_SETFONT, (WPARAM)hf, TRUE);

        // Data.
        BuildPaths();
        LoadAll();
        RefreshList(hMain);
        if (g_selAccount >= 0)
            GuiShowAccount(hMain, g_selAccount);
        else
            GuiClearFields(hMain); // add-mode defaults
        EnsureClientPath(hMain);
        SetStatus(hMain, "%d account(s) loaded", (int)g_accounts.size());
        return 0;
    }

    case WM_SIZE:
        if (wParam != SIZE_MINIMIZED)
            Layout(hMain);
        return 0;

    case WM_GETMINMAXINFO:
    {
        MINMAXINFO* mmi = (MINMAXINFO*)lParam;
        mmi->ptMinTrackSize.x = 620;
        mmi->ptMinTrackSize.y = 540;
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
                // Deselected (clicked empty space) - name becomes editable.
                g_selAccount = -1;
                GuiClearFields(hMain);
                SetStatus(hMain, "No account selected (name editable - type one and press Add)");
            }
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
            Account a = AccountFromGui(hMain, g_accounts[g_selAccount].name);
            a.extraKeys = g_accounts[g_selAccount].extraKeys;
            a.hasStatus = g_accounts[g_selAccount].hasStatus;
            g_accounts[g_selAccount] = a;
            WriteAccountIni(a);
            RefreshList(hMain);
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
            // Wipe every key (incl. unknown Feature.*), then drop the section.
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
        }
        break;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcA(hMain, msg, wParam, lParam);
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------
int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, PWSTR, int nCmdShow)
{
    BuildPaths();

    INITCOMMONCONTROLSEX icc;
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_LISTVIEW_CLASSES;
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
        WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 620, 540,
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
