#include <windows.h>
#include <stdint.h> 
#include <string>   
#include <vector>   
#include "MinHook.h"
#include <cstdio>   
#include <cstring>  
#include <cstdarg>  
#include "common.h"

extern GameWindowInfo g_gameWindow;

// ============================================================================
// Auto Login + Auto Relogin - Conquer.exe client 7937 (image base 0x400000)
// ----------------------------------------------------------------------------
// Reads credentials from auto_login.ini (next to Conquer.exe) and drives the
// game's OWN login chain - no overlay UI, no packet forging, no extra threads.
//
// Config file format:
//   [accounts]
//   enabled  = 1        ; feature master switch
//   selected = 0        ; WHICH account block to use (0-based)
//
//   [account_0]
//   server   = DevServer    ; fallback server name (the dialog's own selected
//                            ; realm is used first - see below)
//   account  = MyUser
//   password = MyPass
//
//   [account_1] ...        ; etc
//
// Reverse-engineered chain (verified in Ghidra, client 7937, base 0x400000):
//
//   1. The account-login dialog lives at *(void**)0x01A594F0 + 0x39B948
//      (the CMyShellDlg main window object, ~37MB, runtime-set; the game's own
//      message dispatcher FUN_0089ca75 reads it as `DAT_01a594f0 + 0x39b948`
//      and gates it with FUN_00bfee7b - see 0x0089cf2f. The dispatcher
//      FUN_00a525b4 saves the same this at 0x00a525ec and the Login-button
//      call site at 0x00a5b8dd-0x00a5b8fe reads dialog+0x39B948).
//      The dialog's HWND is at dialog+0x20.
//
//      Ghidra-verified 2026-08: the Login button handler invoked at
//      0x00a5b8fe (after the IsWindowVisible gate) is FUN_008a8fba, not
//      FUN_008cec7d. FUN_008cec7d is a vtable[+0xd1d0][32] handler for
//      a different control (it crashes when called directly as the
//      Login button). The dialog's account SSO is at +0x13B88 and the
//      password wrapper (CGameInputStr) is at +0x13BD0 — these are the
//      fields FUN_008a8fba reads in its classic path (mode 0) and that
//      the keyboard handler (FUN_0089c003) writes on manual input.
//
//   2. The game itself only invokes the Login handler while the dialog is
//      visible: at 0x00a5b896/0x00a5b8eb it calls FUN_00bfee7b(dialog,1) =
//      IsWindow/IsWindowVisible(dialog+0x20) before CALL 0x008a8fba. We gate
//      the auto-submit on the SAME condition. Sending before the dialog is up
//      queues the packet into a dead socket and the client silently drops it
//      (this was the "no login sequence at boot" bug).
//
//   3. The Login button handler (FUN_008a8fba, __thiscall ECX=dialog)
//      reads the typed account/password from the dialog's own fields
//      and drives the credential send via the network layer:
//
//          FUN_0101bfe7(account_cstr, password_obj, serverName_cstr, mode, port)
//
//      - account   : SSO string at dialog+0x13B88 (the classic mode-0
//                    path ALWAYS uses this pair, never +0x13938/+0x13980
//                    which belong to the QR fallback FUN_008a964f).
//                    SSO layout: inline data at +0..+0xF, length at +0x14;
//                    length > 0xF means heap (pointer at +0).
//      - password  : wrapper object at dialog+0x13BD0 (A) / +0x13980 (B).
//                    The send reads its length at +0x104 (0x0101c03e, fails
//                    >= 0x81), a count at +0x100 and the ENCRYPTED text at
//                    +0x108 (FUN_00ed335e -> VM ordinals 47/1/65).
//                    The wrapper is CGameInputStr (encryptdata.cpp): text is
//                    XOR-encrypted in place against the wrapper's own +0..0xFF
//                    random key table (set once per boot by the dialog ctor);
//                    the ONLY correct way to fill it is the game's own
//                    SetPassword FUN_00ea1692(ECX=wrapper, text) - it writes
//                    len@+0x104 + encrypted text@+0x108 + terminator@+0x207.
//                    NOTE: passing a plain char* here is WRONG - the send
//                    interprets the pointer as this object and reads
//                    [ptr+0x104] (garbage >= 0x81 -> "invalid Account or Psw"
//                    -> 0xFFFFFFFF). That was the original auto-login bug.
//      - serverName: the dialog's own selected realm string at dialog+0x13628.
//                    NOTE: this field is an ATL CSimpleStringT<char,1> (a
//                    CString), NOT an SSO std::string - the game reads it via
//                    its own operator_char_const_ (IAT slot 0x014F4E38, called
//                    at 0x008a903f) and uses it verbatim as arg3 in the
//                    non-poker path. Treating it with SsoCStr was the old bug
//                    (CStringData* pointer garbage). We now call the game's
//                    own imported method exactly like the button handler does.
//      - port      : atoi(dialog+0x13BB8 SSO string), but only when the int
//                    flag at dialog+0x13BC8 != 0, else 0 (0x008a91b2).
//      - mode 0    = classic account/password (CMsgAccountEx).
//      Returns 0 when the send was queued, 0xFFFFFFFF on local rejection.
//
//   4. After logout/disconnect the game runs FUN_00a37821 (the big
//      "reset and return to account login" routine) which calls
//      FUN_00c3ac82 (CQMain_BackToLogin) from 0x00a37c4f (and 0x00a267da in an
//      unanalyzed region - the hook catches both).
//
// So this module:
//   - passes EVERY game login through unmodified (passthrough hook) - manual
//     logins now work exactly as before; the hook only marks that an attempt
//     is in flight so the auto-submit does not double-fire,
//   - watches FUN_00c3ac82 (back to login) to re-arm for the next auto
//     re-login,
//   - auto-submits once the dialog is visible by writing the configured
//     credentials into the dialog's OWN fields (exactly what typing + clicking
//     Login produces) and calling FUN_0101bfe7 with the game-identical
//     argument shapes.
//
// Known residual: none expected on the password side - the fill calls the
// game's own CGameInputStr::SetPassword (FUN_00ea1692) on the dialog's
// wrapper object, byte-identical to what typing produces. The only field the
// packet hash reads that SetPassword does not touch is the +0x100 count
// (set by the wrapper ctor); if the server still rejects the auto-login while
// a manual login with the same creds works, verify dynamically (compare
// wrapper+0x100 after a manual typing vs. after the auto-fill) and mirror it.
//
// Ghidra-verified 2026-08: dialog+0x13628 is an ATL CSimpleStringT (CString),
// not an SSO std::string - read it through the game's own operator_char_const_
// (IAT slot 0x014F4E38) exactly like the login-button handler at 0x008a903f.
// And the classic path (mode 0) always uses account/password pair A (+0x13B88/
// +0x13BD0); the 0x13620 flag only selects the pair in the poker path (mode 2).
// ============================================================================

static void AutoLoginLog(const char* fmt, ...);

namespace AutoLogin
{
	// ------------------------------------------------------------------
	// Native anchors (client 7937). Prologue-verified before hooking.
	// ------------------------------------------------------------------
	// FUN_0101bfe7 - the credential send (gamemain.cpp):
	//   PUSH 0x408; MOV EAX,0x14B2D62; CALL 0x01260F55
	const uintptr_t LOGIN_SEND_ADDRESS = 0x0101BFE7;

	// FUN_00c3ac82 - CQMain_BackToLogin (callers: FUN_00a37821 @ 0x00a37c4f
	// and 0x00a267da).  PUSH 0x16CE374; CALL FUN_0043e5d1
	const uintptr_t BACK_TO_LOGIN_ADDRESS = 0x00C3AC82;

	// FUN_008a8fba - the Login button handler (dlglogin.cpp), dispatched
	// by the game at 0x00a5b8fe (ECX = dialog, after the IsWindowVisible
	// gate at 0x00a5b8eb). Its classic mode-0 path reads the account SSO
	// at dialog+0x13B88 and the password wrapper at dialog+0x13BD0, calls
	// GetServerInfo (FUN_008827c2), resolves the realm and sends via
	// FUN_0101bfe7. Calling it directly (instead of the raw send) is the
	// only way to start a real login sequence that the server responds to.
	// NOT FUN_008cec7d - that is a vtable[+0xd1d0][32] handler for a
	// different control and crashes when invoked as the Login button.
	extern const uintptr_t LOGIN_BUTTON_HANDLER = 0x008A8FBA;

	// Offset of the CGameInputStr WRAPPER inside the login dialog.
	// The game's own login button handler (FUN_008a8fba, dispatched at
	// 0x00a5b8fe) reads the wrapper at dialog+0x13BD0 and passes it as
	// arg2 (password) to FUN_0101bfe7(mode 0). The keyboard handler
	// FUN_0089c003 also writes to this wrapper when the password edit
	// has focus. The wrapper's +0x000..+0x0FF holds the per-boot XOR
	// key table (set by the dialog ctor; never write to it - SsoSet
	// would clobber it and all subsequent SetPassword calls would
	// encrypt against garbage, which is what produced the original
	// "wrong password" server reject).
	const uintptr_t DLG_PASSWORD_WRAPPER = 0x13BD0;

	// Offset of the account SSO string inside the login dialog.
	// FUN_008a8fba's classic path (mode 0) reads the account from
	// dialog+0x13B88 (length at +0x13B9C = +0x14) and passes it as arg1
	// to FUN_0101bfe7. The keyboard handler FUN_0089c003 writes the
	// typed account here too.
	const uintptr_t DLG_ACCOUNT_SSO      = 0x13B88;

	// Client object + login dialog (see header comment).
	const uintptr_t MAIN_CLIENT_GLOBAL  = 0x01A594F0; // CMyShellDlg main window (runtime-set, ~37MB)
	const uintptr_t LOGIN_DIALOG_OFFSET = 0x39B948;   // dialog = client + 0x39B948
	const uintptr_t DLG_HWND_OFFSET     = 0x20;       // dialog+0x20 = HWND
	const uintptr_t DLG_PAIR_FLAG       = 0x13620;    // byte != 0 -> pair B (poker-only)
	const uintptr_t DLG_SERVER_NAME     = 0x13628;    // ATL CSimpleStringT (CString, not SSO)
	const uintptr_t DLG_PORT_STR        = 0x13BB8;    // SSO string (port text)
	const uintptr_t DLG_PORT_FLAG       = 0x13BC8;    // int != 0 -> use port text
	const uintptr_t DLG_ACCOUNT_B       = 0x13938;
	const uintptr_t DLG_PASSWORD_B      = 0x13980;
	const uintptr_t SSO_LEN_OFFSET      = 0x14;       // SSO: len > 0xF -> heap ptr at +0

	// (DLG_ACCOUNT_B = 0x13938 and DLG_PASSWORD_B = 0x13980 are read by
	//  FUN_008a964f, the QR/relogin fallback path - mode 1.)

	// Server-selection fields the login button handler reads (dlglogin.cpp):
	//   dialog+0x135f8 = active group index, dialog+0x135fc = active server.
	//   -1 = none selected yet (boot).  FUN_00883ec4 selects the first group
	//   from the loaded server list and stores the selection in the client.
	const uintptr_t DLG_ACTIVE_GROUP    = 0x135f8;
	const uintptr_t DLG_ACTIVE_SERVER   = 0x135fc;

	// FUN_00883ec4 - CDlgLogin server-selection (dlglogin.cpp): picks the
	// first group from m_vecGroup, sets dialog+0x135f8/+0x135fc and the client
	// global.  Called by the dialog init (FUN_0088f258) and by the server
	// buttons.  __fastcall(ECX = dialog).
	const uintptr_t SERVER_SELECT_HANDLER = 0x00883EC4;

	// ATL::CSimpleStringT<char,1>::operator_char_const_ - delay-loaded import
	// whose IAT slot the game's own login-button handler calls at 0x008a903f.
	// Slot is resolved to the real function address by the delay-load thunk on
	// first use, so calling through the IAT pointer replicates the game exactly.
	const uintptr_t CSTRING_OPERATOR_IAT = 0x014F4E38;

	// CStringT::operator=(const char*) - ATL CString assignment, used by the
	// dialog init (FUN_0088f258 @ 0x0088f38b) to set the server name CString
	// at dialog+0x13628.  __thiscall(ECX = this, stack = text).
	const uintptr_t CSTRING_ASSIGN_IAT = 0x014F5020;

	// FUN_00ea1692 - CGameInputStr::SetPassword (encryptdata.cpp):
	//   __thiscall(ECX = wrapper, stack = plaintext), RET 4. Writes len@+0x104,
	//   XOR-encrypts the text into +0x108 (key = the wrapper's own +0..0xFF
	//   random key table installed by the dialog ctor), terminator@+0x207.
	//   Asserts strlen(text) < 0x100 - caller must truncate.
	const uintptr_t SET_PASSWORD_ADDRESS = 0x00EA1692;

	// Manual-sequence recording anchors:
	//   FUN_008a9348 - realm-ROW button handler (resolves realm, persists
	//                  PlaySetUP.ini, establishes the ACCOUNT-SERVER connection
	//                  via FUN_010188fb -> FUN_0101aa52 -> FUN_010234e9(1,...)).
	//   FUN_008827c2 - CDlgLogin::GetServerInfo (mode 1 = account server).
	const uintptr_t REALM_ROW_HANDLER = 0x008A9348;
	const uintptr_t GET_SERVER_INFO   = 0x008827C2;
	typedef void(__fastcall* SetPasswordFn)(void* pswObj, void* /*edx_dummy*/, const char* text);

	// cdecl, 5 params; the caller cleans the stack (bare RET at 0x0101C250).
	// NOTE: arg2 is the dialog's password WRAPPER OBJECT, not a char*.
	typedef int (__cdecl* LoginSendFn)(const char* account, void* password, const char* serverInfo, int mode, int port);

	typedef void (__cdecl* BackToLoginFn)(void);

	LoginSendFn    g_OriginalLoginSend = nullptr;
	BackToLoginFn  g_OriginalBackToLogin = nullptr;

	// ------------------------------------------------------------------
	// Config (auto_login.ini next to Conquer.exe)
	// ------------------------------------------------------------------
	char  g_cfgPath[MAX_PATH] = {0};
	bool  g_enabled = false;
	int   g_selectedAccount = 0;
	char  g_account[128] = {0};
	char  g_password[128] = {0};
	char  g_server[128] = {0};

	unsigned long g_bootWaitMs   = 6000;   // first submit delay after attach
	unsigned long g_reloginWaitMs = 6000;  // submit delay after a disconnect
	// Resubmit cadence once PRIME owns the dialing: short nudges are fine now
	// (the old dial-starvation problem is gone because PRIME connects
	// deterministically). Covers the first-packet reject -> resend window.
	unsigned long g_retryMs      = 6000;
	int           g_maxRetries   = 12;     // per-cycle budget (~72s at default retry_ms)

	// ------------------------------------------------------------------
	// runtime state
	// ------------------------------------------------------------------
	bool  g_hooks = false;
	bool  g_attemptDone = false;      // a login was sent this cycle (auto or manual)
	bool  g_backToLoginSeen = false;  // we returned to the account screen
	bool  g_debugTypePasswordInAccount = false; // debug: type password into the VISIBLE account box
	bool  g_manualCapture = false;    // manual-capture mode: automation frozen, probes record
	bool  g_autoLearnPassword = false; // on successful login, save the typed password bytes to ini
	HANDLE g_instanceMutex = nullptr;  // single-instance guard: owner of all hooks
	unsigned long g_cycleStartTick = 0;
	unsigned long g_lastAttemptTick = 0;
	int   g_retryCount = 0;
	bool  g_autoSubmitInFlight = false; // last queued send was ours (not manual)
	int   g_failedCycles = 0;           // consecutive quick fail -> back-to-login
	unsigned long g_submitCount = 0;
	unsigned long g_postGraceUntil = 0; // no re-submit while the game thread processes a posted submit
	char  g_lastResult[64] = "idle";

	// Forward declarations for helpers defined further below in this file.
	static void* GetLoginDialog();
	static void DecryptStoredPassword(void* wrapper, unsigned char* outPlain, unsigned int cap);
	static unsigned long FnvHashBytes(const unsigned char* p, int n);

	// ------------------------------------------------------------------
	// Wire probe (temporary diagnostics): log real socket traffic for ~20s
	// after a login send fires. Answers definitively whether the queued
	// login packet leaves the process and whether anything comes back -
	// without this, "queued" (ret=0) proves delivery only to the local
	// stack buffer, not to the server.
	// ------------------------------------------------------------------
	typedef int (__stdcall *SendFn)(void*, const char*, int, int);
	typedef int (__stdcall *RecvFn)(void*, char*, int, int);
	struct WsaBuf { unsigned long len; char* buf; };
	typedef int (__stdcall *WSASendFn)(void*, WsaBuf*, unsigned long, unsigned long*, unsigned long, void*, void*);
	typedef int (__stdcall *WSARecvFn)(void*, WsaBuf*, unsigned long, unsigned long*, unsigned long*, void*, void*);

	SendFn    g_OrigSend    = nullptr;
	RecvFn    g_OrigRecv    = nullptr;
	WSASendFn g_OrigWSASend = nullptr;
	WSARecvFn g_OrigWSARecv = nullptr;
	unsigned long g_wireProbeUntil = 0;

	// connect()/WSAConnect() - ALWAYS logged (ungated; connects are rare and
	// show exactly which endpoint each stage of the login chain dials,
	// including the boot-time server-list fetch that precedes any submit).
	typedef int (__stdcall *ConnectFn)(void*, const void*, int);
	typedef int (__stdcall *WSAConnectFn)(void*, const void*, int, void*, void*, void*, void*);
	ConnectFn    g_OrigConnect    = nullptr;
	WSAConnectFn g_OrigWSAConnect = nullptr;
	unsigned long s_lastDialTick = 0;   // when the client last dialed anything (gates PRIME)
	int s_fullDumpCount = 0;            // full-payload dumps this probe window

	// Probe is live during the 20s post-send window, the whole time while
	// manual-capture mode records a human login, or whenever auto-learn is
	// enabled (so a successful MANUAL login gets its password captured and
	// persisted as password_hex regardless of the probe window).
	static bool WireProbeActive()
	{
		return AutoLogin::g_autoLearnPassword || AutoLogin::g_manualCapture ||
			GetTickCount() < g_wireProbeUntil;
	}

	static void LogConnectTarget(void* sock, const void* addr, int addrlen)
	{
		if (!addr || addrlen < 4)
			return;
		s_lastDialTick = GetTickCount();
		unsigned short family = *(const unsigned short*)addr;
		if (family != 2) { // AF_INET
			AutoLoginLog("wire C sock=%p family=%u (non-inet)", sock, (unsigned)family);
			return;
		}
		const unsigned char* a = (const unsigned char*)addr;
		unsigned port = ((unsigned)a[2] << 8) | a[3];
		AutoLoginLog("wire C sock=%p -> %u.%u.%u.%u:%u", sock, a[4], a[5], a[6], a[7], port);
		// Game-server redirect = auth succeeded and the client is moving to the
		// world. Close the cycle so no further auto-submits fire mid-transition.
		if (port == 19000 && !AutoLogin::g_attemptDone) {
			AutoLoginLog("WIRE: game-server redirect (:19000) - login complete");
			AutoLogin::g_attemptDone = true;
			strcpy_s(AutoLogin::g_lastResult, "login complete (:19000)");
		}
	}

	int __stdcall HookedWireConnect(void* sock, const void* addr, int addrlen)
	{
		LogConnectTarget(sock, addr, addrlen);
		return g_OrigConnect ? g_OrigConnect(sock, addr, addrlen) : -1;
	}

	int __stdcall HookedWireWSAConnect(void* sock, const void* addr, int addrlen,
		void* callerData, void* calleeData, void* sqos, void* gqos)
	{
		LogConnectTarget(sock, addr, addrlen);
		return g_OrigWSAConnect ? g_OrigWSAConnect(sock, addr, addrlen, callerData, calleeData, sqos, gqos) : -1;
	}

	static void WireHexLog(char dir, void* sock, const char* buf, int len)
	{
		int n = (len < 24) ? len : 24;
		char hex[64];
		static const char* digits = "0123456789ABCDEF";
		for (int i = 0; i < n; ++i) {
			hex[i*2]   = digits[(buf[i] >> 4) & 0xF];
			hex[i*2+1] = digits[buf[i] & 0xF];
		}
		hex[n*2] = 0;
		AutoLoginLog("wire %c sock=%p len=%d head=%s", dir, sock, len, hex);
	}

	int __stdcall HookedWireSend(void* sock, const char* buf, int len, int flags)
	{
		if (g_OrigSend && WireProbeActive() && buf && len > 0)
		{
			WireHexLog('>', sock, buf, len);
			// Full payload dump - limited count per probe window - so an auto
			// packet can be diffed byte-for-byte against a manual-login packet.
			if (len <= 600 && s_fullDumpCount < 4) {
				s_fullDumpCount++;
				for (int off = 0; off < len; off += 64) {
					char line[200];
					int n = 0;
					int end = off + 64 < len ? off + 64 : len;
					n += _snprintf_s(line + n, sizeof(line) - n, _TRUNCATE, "SEND[%d] +%03d:", s_fullDumpCount, off);
					for (int i = off; i < end && n > 0; ++i)
						n += _snprintf_s(line + n, sizeof(line) - n, _TRUNCATE, " %02X", (unsigned char)buf[i]);
					AutoLoginLog("%s", line);
				}
			}
		}
		return g_OrigSend ? g_OrigSend(sock, buf, len, flags) : -1;
	}

	int __stdcall HookedWireRecv(void* sock, char* buf, int len, int flags)
	{
		int r = g_OrigRecv ? g_OrigRecv(sock, buf, len, flags) : -1;
		// Log successful reads only - async sockets hammer WSAEWOULDBLOCK.
		if (g_OrigRecv && WireProbeActive() && r > 0 && buf)
			WireHexLog('<', sock, buf, r);
		// 10-byte payload during the login window = the auth-ACCEPT message
		// (manual logins get it; rejects are 6 bytes). Close the cycle so no
		// further auto-submits fire while the client transitions into the world.
		if (g_OrigRecv && WireProbeActive() && r == 10 &&
		    !AutoLogin::g_attemptDone)
		{
			AutoLoginLog("WIRE: auth ACCEPT (10B) received - closing cycle");
			AutoLogin::g_attemptDone = true;
			strcpy_s(AutoLogin::g_lastResult, "login accepted (server ACK)");

			// Learn the credentials that just SUCCEEDED: decrypt the live
			// password wrapper at dialog+0x13BD0 (the field FUN_008a8fba's
			// mode-0 path reads) and persist its exact bytes as password_hex
			// in the ini, so auto-login replays them byte-for-byte next time -
			// regardless of keyboard layout or character encoding.
			if (AutoLogin::g_autoLearnPassword) {
				void* dialog = AutoLogin::GetLoginDialog();
				if (dialog && !IsBadReadPtr(dialog, 0x12F00)) {
					unsigned char* dlg = (unsigned char*)dialog;
					void* pswObj = dlg + AutoLogin::DLG_PASSWORD_WRAPPER;
					unsigned char plain[0x100];
					AutoLogin::DecryptStoredPassword(pswObj, plain, sizeof(plain));
					unsigned int plen = *(unsigned int*)((unsigned char*)pswObj + 0x104);
					if (plen > 0x100) plen = 0x100;
					if (plen > 0) {
						char hexBuf[3 * 0x100 + 1] = {0};
						int o = 0;
						for (unsigned int i = 0; i < plen; ++i)
							o += _snprintf_s(hexBuf + o, sizeof(hexBuf) - o, _TRUNCATE, "%02X ", plain[i]);
						char sect[32];
						sprintf_s(sect, "account_%d", AutoLogin::g_selectedAccount);
						WritePrivateProfileStringA(sect, "password_hex", hexBuf, AutoLogin::g_cfgPath);
						AutoLoginLog("LEARNED: saved %u password bytes as password_hex into [%s] (fnv=%08lX)",
							plen, sect, AutoLogin::FnvHashBytes(plain, (int)plen));
					}
				}
			}
		}
		return r;
	}

	int __stdcall HookedWireWSASend(void* sock, WsaBuf* bufs, unsigned long count,
		unsigned long* sent, unsigned long flags, void* overlapped, void* completion)
	{
		int r = g_OrigWSASend ? g_OrigWSASend(sock, bufs, count, sent, flags, overlapped, completion) : -1;
		if (g_OrigWSASend && GetTickCount() < g_wireProbeUntil && bufs && count > 0)
			WireHexLog('>', sock, bufs[0].buf, (int)bufs[0].len);
		return r;
	}

	int __stdcall HookedWireWSARecv(void* sock, WsaBuf* bufs, unsigned long count,
		unsigned long* recvd, unsigned long* flagsOut, void* overlapped, void* completion)
	{
		int r = g_OrigWSARecv ? g_OrigWSARecv(sock, bufs, count, recvd, flagsOut, overlapped, completion) : -1;
		if (g_OrigWSARecv && GetTickCount() < g_wireProbeUntil && bufs && count > 0 &&
		    recvd && *recvd > 0 && bufs[0].buf)
			WireHexLog('<', sock, bufs[0].buf, (int)*recvd);
		return r;
	}

	// Forward declarations: these helpers are defined further below.
	static void* GetLoginDialog();
	static const char* SsoCStr(const void* obj);

	// ------------------------------------------------------------------
	// Password-verification helpers. The SetPassword cipher (FUN_00ea1692)
	// is a per-byte XOR: enc[i] = ((i*'g'-0x7F)*i) ^ key[i&0xFF]
	//                       ^ ((i>>4)*'f') ^ plain[i] ^ 0xB9
	// which is fully invertible - we can recover what the game STORES and
	// hash-compare it against the ini without ever printing the plaintext.
	// ------------------------------------------------------------------
	static unsigned long FnvHashBytes(const unsigned char* p, int n)
	{
		unsigned long h = 2166136261u;
		for (int i = 0; i < n; ++i) { h ^= p[i]; h *= 16777619u; }
		return h;
	}

	static unsigned long FnvHashStr(const char* s)
	{
		return s ? FnvHashBytes((const unsigned char*)s, (int)strlen(s)) : 2166136261u;
	}

	static void DecryptStoredPassword(void* wrapper, unsigned char* outPlain, unsigned int cap)
	{
		unsigned char* w = (unsigned char*)wrapper;
		unsigned int len = *(unsigned int*)(w + 0x104);
		if (len > 0xFF) len = 0xFF;
		if (len > cap)  len = cap;
		for (unsigned int i = 0; i < len; ++i) {
			unsigned int ci  = i & 0xFF;
			char c           = (char)ci;
			unsigned int a   = (unsigned int)(((int)c * 0x67 - 0x7F) * (int)c) & 0xFF;
			char hi          = (char)(i >> 4);
			unsigned int cc  = (unsigned int)(hi * 0x66) & 0xFF;
			outPlain[i] = (unsigned char)(w[0x108 + i] ^ w[ci] ^ a ^ cc ^ 0xB9);
		}
		if (len < cap) outPlain[len] = 0;
	}

	// ------------------------------------------------------------------
	// Popup logger - capture what the CLIENT says (error boxes etc.) during
	// the login phase. Without this, silent failures are undiagnosable.
	// ------------------------------------------------------------------
	typedef int (__stdcall *MessageBoxAFn)(HWND, const char*, const char*, unsigned);
	typedef int (__stdcall *MessageBoxWFn)(HWND, const wchar_t*, const wchar_t*, unsigned);
	MessageBoxAFn g_OrigMsgBoxA = nullptr;
	MessageBoxWFn g_OrigMsgBoxW = nullptr;
	SetPasswordFn g_OrigSetPassword = nullptr;

	// Manual-sequence recorders (installed always; they only LOG, never alter
	// behaviour - so we see the exact call order a HUMAN login produces):
	typedef void (__fastcall *RealmRowFn)(void* self, void* edx);
	typedef char (__fastcall *GetServerInfoFn)(void* self, void* edx, int mode,
		char* outIP, int cap, int* outPort);
	RealmRowFn     g_OrigRealmRow     = nullptr;
	GetServerInfoFn g_OrigGetServerInfo = nullptr;

	void __fastcall HookedRealmRow(void* self, void* edx)
	{
		AutoLoginLog("SEQ: realm-row handler ENTER dialog=%p (resolves realm + connects account server)", self);
		if (g_OrigRealmRow)
			g_OrigRealmRow(self, edx);
		AutoLoginLog("SEQ: realm-row handler RETURN");
	}

	char __fastcall HookedGetServerInfo(void* self, void* edx, int mode,
		char* outIP, int cap, int* outPort)
	{
		char r = g_OrigGetServerInfo ? g_OrigGetServerInfo(self, edx, mode, outIP, cap, outPort) : 0;
		AutoLoginLog("SEQ: GetServerInfo(mode=%d) -> %d ip='%s' port=%d",
			mode, (int)r, outIP ? outIP : "?", outPort ? *outPort : -1);
		return r;
	}

	int __stdcall HookedMessageBoxA(HWND hwnd, const char* text, const char* caption, unsigned type)
	{
		AutoLoginLog("POPUP-A cap='%s' text='%s'", caption?caption:"", text?text:"");
		return g_OrigMsgBoxA ? g_OrigMsgBoxA(hwnd, text, caption, type) : 0;
	}

	int __stdcall HookedMessageBoxW(HWND hwnd, const wchar_t* text, const wchar_t* caption, unsigned type)
	{
		char t[192] = {0}, c[64] = {0};
		if (text)    WideCharToMultiByte(CP_ACP, 0, text, -1, t, sizeof(t), 0, 0);
		if (caption) WideCharToMultiByte(CP_ACP, 0, caption, -1, c, sizeof(c), 0, 0);
		AutoLoginLog("POPUP-W cap='%s' text='%s'", c, t);
		return g_OrigMsgBoxW ? g_OrigMsgBoxW(hwnd, text, caption, type) : 0;
	}

	// SetPassword probe: hash (never print) whatever plaintext reaches
	// CGameInputStr::SetPassword. The auto fill and a manual typing session
	// MUST produce the same fnv hash + length - if they differ, the ini
	// password is not what the user types by hand. Fires for BOTH paths since
	// the game's own keyboard handler (FUN_0089c003) ends in the same call.
	void __fastcall HookedSetPassword(void* self, void* edx, const char* text)
	{
		unsigned long h = 2166136261u;
		int n = text ? (int)strlen(text) : -1;
		for (int i = 0; i < n; ++i) {
			h ^= (unsigned char)text[i];
			h *= 16777619u;
		}
		// Throttle: the login renderer re-encrypts into a display wrapper every
		// frame (clear+set pairs); log at most 2 lines per second per object.
		static unsigned long s_lastLogTick = 0;
		static void* s_lastObj = nullptr;
		unsigned long now = GetTickCount();
		bool logIt = (self != s_lastObj) || (now - s_lastLogTick > 500);
		if (logIt) {
			s_lastObj = self;
			s_lastLogTick = now;
			// Ground truth: decrypt what THIS wrapper now stores and hash it.
			// If storedFNV != fnv(text) the encryption/fill path is broken;
			// if two different sources produce equal hashes they are identical.
			char storedLine[96] = "";
			__try {
				unsigned char plain[0x100];
				DecryptStoredPassword(self, plain, sizeof(plain));
				unsigned int slen = *(unsigned int*)((unsigned char*)self + 0x104);
				if (slen > 0x100) slen = 0x100;
				_snprintf_s(storedLine, _TRUNCATE, " | storedLen=%u storedFNV=%08lX",
					slen, FnvHashBytes(plain, (int)slen));
			} __except(EXCEPTION_EXECUTE_HANDLER) {
				_snprintf_s(storedLine, _TRUNCATE, " | decrypt EXCEPTION");
			}
			AutoLoginLog("SETPSW obj=%p len=%d fnv=%08lX%s%s", self, n, h,
				n < 0 ? " (null)" : "", storedLine);
		}
		if (g_OrigSetPassword)
			g_OrigSetPassword(self, edx, text);
	}

	// ------------------------------------------------------------------
	// Real-input typing: push the credentials through the dialog's ACTUAL
	// edit controls (WM_CHAR) on the game thread, so every game-side
	// notification handler (EN_CHANGE / EN_UPDATE / kill-focus / ...) fires
	// exactly as during a manual login - including whichever one establishes
	// the account-server connection. Direct memory fills never trigger it.
	// ------------------------------------------------------------------
	struct EditList { HWND h[8]; int n; };

	static BOOL CALLBACK EditEnumProc(HWND hwnd, LPARAM lp)
	{
		EditList* list = (EditList*)lp;
		char cls[32] = {0};
		GetClassNameA(hwnd, cls, sizeof(cls));
		if (_stricmp(cls, "edit") != 0)
			return TRUE;
		if (!(GetWindowLongA(hwnd, GWL_STYLE) & WS_VISIBLE))
			return TRUE;
		if (list->n < 8)
			list->h[list->n++] = hwnd;
		return TRUE;
	}

	static void TypeIntoEdit(HWND edit, const char* text)
	{
		::SetFocus(edit);                       // legal here: we are on the dialog's own thread
		SendMessageA(edit, EM_SETSEL, 0, -1);   // select any existing content
		for (const char* p = text; p && *p; ++p)
			SendMessageA(edit, WM_CHAR, (unsigned char)*p, 0x00010001);
	}

	void AutoLoginTypeViaControls()
	{
		void* dialog = GetLoginDialog();
		if (!dialog)
			return;
		unsigned char* dlg = (unsigned char*)dialog;
		HWND dlgHwnd = *(HWND*)(dlg + DLG_HWND_OFFSET);
		if (!dlgHwnd || !IsWindow(dlgHwnd))
			return;

		// The game's own keyboard handler (FUN_0089c003, dlglogin.cpp) routes
		// typing through two MFC CWnd members of the dialog:
		//   account CWnd @ dlg+0x0cd0, password CWnd @ dlg+0x0fe8 (HWND @ +0x20)
		// Those are the ONLY targets whose message handlers feed pair A - the
		// zero-size 'Edit' children found by class enumeration are unrelated
		// slot-name boxes. Prefer the member HWNDs; fall back to Edit children.
		HWND acctEdit = *(HWND*)(dlg + 0x0cd0);
		HWND pswEdit  = *(HWND*)(dlg + 0x0fe8);
		bool useMemberWnds = acctEdit && IsWindow(acctEdit) && pswEdit && IsWindow(pswEdit);

		// One-shot dump of the dialog's child controls (class/rect) so the
		// account-vs-password mapping can be verified/corrected from the log.
		static bool s_dumpedChildren = false;
		if (!s_dumpedChildren) {
			s_dumpedChildren = true;
			struct ChildCtx { int i; } ctx = { 0 };
			EnumChildWindows(dlgHwnd, [](HWND h, LPARAM lp)->BOOL {
				char cls[48] = {0};
				RECT r = {0};
				GetClassNameA(h, cls, sizeof(cls));
				GetWindowRect(h, &r);
				AutoLoginLog("CHILD[%d] hwnd=%p cls='%s' rect=(%ld,%ld)-(%ld,%ld)",
					((ChildCtx*)lp)->i++, h, cls, r.left, r.top, r.right, r.bottom);
				return TRUE;
			}, (LPARAM)&ctx);
			AutoLoginLog("TARGETS: member acct=%p psw=%p", (void*)acctEdit, (void*)pswEdit);
		}

		if (!useMemberWnds)
		{
			EditList list = {};
			EnumChildWindows(dlgHwnd, EditEnumProc, (LPARAM)&list);
			if (list.n >= 2) {
				acctEdit = list.h[0];
				pswEdit  = list.h[1];
				useMemberWnds = true;
			}
		}

		if (useMemberWnds)
		{
			// Debug mode: type the PASSWORD into the visible ACCOUNT box so the
			// user can visually confirm what our WM_CHAR typing produces.
			const char* acctText = AutoLogin::g_debugTypePasswordInAccount
				? AutoLogin::g_password : AutoLogin::g_account;
			if (AutoLogin::g_debugTypePasswordInAccount)
				AutoLoginLog("DEBUG MODE: typing the INI PASSWORD into the ACCOUNT box - read it on screen!");
			TypeIntoEdit(acctEdit, acctText);
			Sleep(20);
			TypeIntoEdit(pswEdit, AutoLogin::g_password);

			// Ground truth: read back what the CONTROLS hold (WM_GETTEXT) and
			// hash-compare. This is independent of the wrapper state, so it
			// proves whether WM_CHAR typing itself works.
			char gotAcct[160] = {0}, gotPsw[160] = {0};
			GetWindowTextA(acctEdit, gotAcct, sizeof(gotAcct));
			GetWindowTextA(pswEdit, gotPsw, sizeof(gotPsw));
			unsigned long gotAcctF = AutoLogin::FnvHashStr(gotAcct);
			unsigned long gotPswF  = AutoLogin::FnvHashStr(gotPsw);
			unsigned long wantAcctF = AutoLogin::FnvHashStr(acctText);
			unsigned long wantPswF  = AutoLogin::FnvHashStr(AutoLogin::g_password);
			AutoLoginLog("EDITREADBACK account: text='%s' fnv=%08lX want=%08lX => %s",
				gotAcct, gotAcctF, wantAcctF, gotAcctF == wantAcctF ? "MATCH" : "*** MISMATCH ***");
			AutoLoginLog("EDITREADBACK password: len=%d fnv=%08lX want=%08lX => %s",
				(int)strlen(gotPsw), gotPswF, wantPswF, gotPswF == wantPswF ? "MATCH" : "*** MISMATCH ***");

			// Verify the game-side state actually received the text; if the
			// edit->field mapping is inverted this exposes it in the log.
			// dialog: SSO at dialog+0x13B88, wrapper at dialog+0x13BD0.
			const char* acct = SsoCStr(dlg + AutoLogin::DLG_ACCOUNT_SSO);
			unsigned int plen = *(unsigned int*)(dlg + AutoLogin::DLG_PASSWORD_WRAPPER + 0x104);
			AutoLoginLog("TYPED acct=%p psw=%p | verify acct='%s' pswlen=%u",
				(void*)acctEdit, (void*)pswEdit, acct?acct:"?", plen);
		}
		else
		{
			AutoLoginLog("TYPING skipped: no usable edit targets - keeping direct fill");
		}
	}

	// Simulates clicking the selected REALM ROW (the game's own handler for
	// that button, FUN_008a9348 @ 0x008A9348): resolves the realm, persists
	// PlaySetUP.ini and - critically - establishes the ACCOUNT-SERVER
	// connection via FUN_010188fb -> FUN_0101aa52 (reads [ServerInfo] from
	// ini/Info.ini) -> FUN_010234e9(1, ip, port, 10). A login packet sent
	// without this priming lands on a socket that never exists ("queued"
	// forever, no wire C, no server reply, no error popup). MUST run on the
	// game's message thread (invoked from HandleAutoLoginSubmit).
	void AutoLoginPrimeConnection()
	{
		void* dialog = GetLoginDialog();
		if (!dialog)
			return;
		// Skip if the account socket was dialed recently - FUN_010234e9 would
		// otherwise churn connections on every fast retry.
		unsigned long now = GetTickCount();
		if (s_lastDialTick != 0 && now - s_lastDialTick < 60000)
			return;
		__try {
			typedef void (__fastcall* RowSelectFn)(void*);
			((RowSelectFn)0x008A9348)(dialog);
			AutoLoginLog("PRIME: realm-row handler invoked (account-server connect chain)");
		} __except(EXCEPTION_EXECUTE_HANDLER) {
			AutoLoginLog("PRIME: row-select handler EXCEPTION");
		}
	}

	// ------------------------------------------------------------------
	// SSO helpers for the dialog's string fields
	// ------------------------------------------------------------------
	// Layout used by the game's own readers (e.g. 0x008a929f):
	//   obj+0x0..0xF inline data, obj+0x14 = length; length > 0xF -> heap,
	//   the real data is at *(void**)obj.
	static const char* SsoCStr(const void* obj)
	{
		const unsigned char* p = (const unsigned char*)obj;
		if (*(const unsigned long*)(p + SSO_LEN_OFFSET) > 0xF)
			return *(const char**)p;
		return (const char*)p;
	}

	// Writes an inline SSO string (creds are short; longer ones truncate).
	static void SsoSet(void* obj, const char* text)
	{
		unsigned char* p = (unsigned char*)obj;
		size_t n = strlen(text);
		if (n > 0xF)
			n = 0xF;
		memcpy(p, text, n);
		memset(p + n, 0, 0x10 - n);
		*(unsigned long*)(p + SSO_LEN_OFFSET) = (unsigned long)n;
	}

	// Reads an ATL CSimpleStringT<char,1> (CString) field by calling the game's
	// own imported operator_char_const_ (IAT slot CSTRING_OPERATOR_IAT) - the
	// same call the login-button handler makes at 0x008a903f. Returns the c_str
	// or "" (never null). Unlike SsoCStr this handles the CStringData* layout.
	static const char* CStringCStr(void* field)
	{
		__try {
			typedef const char* (__fastcall* OpCharConstFn)(void* obj, void* edxDummy);
			const void* iat = (const void*)CSTRING_OPERATOR_IAT;
			if (IsBadReadPtr(iat, sizeof(void*)))
				return "";
			OpCharConstFn fn = *(OpCharConstFn*)iat;
			if (!fn)
				return "";
			const char* s = fn(field, nullptr);
			return s ? s : "";
		} __except(EXCEPTION_EXECUTE_HANDLER) {
			return "";
		}
	}

	// Sets an ATL CString field using the game's own CStringT::operator=
	// (IAT slot CSTRING_ASSIGN_IAT - the same assignment the dialog init uses
	// at 0x0088f38b).  Needed for dialog+0x13628 (the server name): GetServerInfo
	// resolves the account server from that CString, and a raw SsoSet would
	// corrupt the CStringData.
	static void CStringAssign(void* field, const char* text)
	{
		__try {
			typedef void* (__fastcall* CStringAssignFn)(void* obj, void* edxDummy, const char* text);
			const void* iat = (const void*)CSTRING_ASSIGN_IAT;
			if (IsBadReadPtr(iat, sizeof(void*)))
				return;
			CStringAssignFn fn = *(CStringAssignFn*)iat;
			if (!fn)
				return;
			fn(field, nullptr, text);
		} __except(EXCEPTION_EXECUTE_HANDLER) {
		}
	}

	// The account-login dialog (null when the client object is not up yet).
	static void* GetLoginDialog()
	{
		void* client = nullptr;
		__try {
			if (IsBadReadPtr((void*)MAIN_CLIENT_GLOBAL, sizeof(void*)))
				return nullptr;
			client = *(void**)MAIN_CLIENT_GLOBAL;
		} __except(EXCEPTION_EXECUTE_HANDLER) {
			return nullptr;
		}
		if (!client)
			return nullptr;
		void* dialog = (unsigned char*)client + LOGIN_DIALOG_OFFSET;
		// Only probe the dialog's HWND field - the game's own visibility gate
		// (FUN_00bfee7b) reads [dialog+0x20] directly without any range probe.
		// A large IsBadReadPtr(client, LOGIN_DIALOG_OFFSET + 0x14000) would
		// fail on the client's large virtual-memory map (uncommitted pages),
		// even though the dialog itself is valid.  Match the game's approach.
		if (IsBadReadPtr(dialog, DLG_HWND_OFFSET + sizeof(HWND)))
			return nullptr;
		return dialog;
	}

	// Fallback: enumerate visible HWNDs owned by this process and try to
	// infer a dialog whose HWND matches dialog+0x20. This covers the case
	// where the global moved (client rebuild) but the HWND itself is still
	// discoverable. Returns dialog base or nullptr.
	static void* GetLoginDialogFallback()
	{
		struct Ctx { void* found; DWORD pid; };
		Ctx ctx = { nullptr, GetCurrentProcessId() };
		EnumWindows([](HWND hwnd, LPARAM lp)->BOOL {
			Ctx* c = (Ctx*)lp;
			if (!IsWindow(hwnd) || !IsWindowVisible(hwnd))
				return TRUE;
			DWORD pid = 0;
			GetWindowThreadProcessId(hwnd, &pid);
			if (pid != c->pid)
				return TRUE;
			// Heuristic: login dialog is a visible top-level or popup with
			// size typical for the login window; keep it cheap - just record
			// first visible candidate for diagnostics, not for auto-submit.
			// The real submit still requires the game struct path.
			return TRUE;
		}, (LPARAM)&ctx);
		return ctx.found;
	}

} // namespace AutoLogin

static void AutoLoginLog(const char* fmt, ...)
{
	char exePath[MAX_PATH] = {0};
	if (!GetModuleFileNameA(NULL, exePath, MAX_PATH))
		return;
	char* slash = strrchr(exePath, '\\');
	if (slash) *(slash+1) = '\0';
	char logPath[MAX_PATH];
	_snprintf_s(logPath, _TRUNCATE, "%sauto_login.log", exePath);
	FILE* f = nullptr;
	if (fopen_s(&f, logPath, "a") != 0 || !f) return;
	SYSTEMTIME st; GetLocalTime(&st);
	fprintf(f, "[%02d:%02d:%02d.%03d] ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
	va_list ap; va_start(ap, fmt); vfprintf(f, fmt, ap); va_end(ap);
	fprintf(f, "\n");
	fclose(f);
}

// ============================================================================
// Config loading - UTF-8/UTF-16 tolerant, no GetPrivateProfile* dependency
// ============================================================================
static void AutoLoginSetPath()
{
	if (AutoLogin::g_cfgPath[0])
		return;
	// Put the ini next to Conquer.exe (same folder the DLL proxy lives in).
	GetModuleFileNameA(NULL, AutoLogin::g_cfgPath, MAX_PATH);
	char* slash = strrchr(AutoLogin::g_cfgPath, '\\');
	if (slash)
		*(slash + 1) = '\0';
	strncat_s(AutoLogin::g_cfgPath, "auto_login.ini", _TRUNCATE);
}

// Load file as narrow (handles BOM UTF-8 and UTF-16 LE/BE). Returns bytes in narrow[].
static size_t LoadIniNarrow(const char* iniPath, char* narrow, size_t narrowCap)
{
	FILE* f = nullptr;
	if (fopen_s(&f, iniPath, "rb") != 0 || !f)
		return 0;
	unsigned char buf[8192];
	size_t n = fread(buf, 1, sizeof(buf)-1, f);
	fclose(f);
	if (n == 0) { narrow[0]=0; return 0; }
	const unsigned char* p = buf;
	size_t rem = n;
	bool wideLE=false, wideBE=false;
	if (n>=3 && buf[0]==0xEF && buf[1]==0xBB && buf[2]==0xBF) { p+=3; rem-=3; }
	else if (n>=2 && buf[0]==0xFF && buf[1]==0xFE) { wideLE=true; p+=2; rem-=2; }
	else if (n>=2 && buf[0]==0xFE && buf[1]==0xFF) { wideBE=true; p+=2; rem-=2; }
	size_t m=0;
	if (wideLE || wideBE) {
		// Convert wide -> ANSI PROPERLY through the system codepage (CP_ACP,
		// e.g. Arabic Windows-1256). The previous low-byte truncation silently
		// destroyed every non-ASCII credential character (UTF-16LE U+0627 ->
		// 0x27 '!'), making loaded passwords differ from typed ones.
		int wchars = (int)(rem / 2);
		if (wchars > 0 && (size_t)wchars * 2 <= rem) {
			wchar_t* wbuf = new(std::nothrow) wchar_t[wchars];
			if (wbuf) {
				if (wideLE) {
					memcpy(wbuf, p, (size_t)wchars * 2);
				} else { // UTF-16 BE: swap byte pairs
					for (int i = 0; i < wchars; ++i) {
						((unsigned char*)&wbuf[i])[0] = p[i*2+1];
						((unsigned char*)&wbuf[i])[1] = p[i*2];
					}
				}
				int cap = (int)(narrowCap - m - 1);
				int wrote = WideCharToMultiByte(CP_ACP, 0, wbuf, wchars,
					narrow + m, cap > 0 ? cap : 0, NULL, NULL);
				if (wrote > 0)
					m += (size_t)wrote;
				delete[] wbuf;
			}
		}
	} else {
		for (size_t i=0; i<rem && m+1<narrowCap; ++i)
			narrow[m++] = (char)p[i];
	}
	narrow[m]=0;
	return m;
}

static bool IniFindSection(const char* narrow, const char* section, const char** outSecStart, const char** outSecEnd)
{
	char needle[64];
	_snprintf_s(needle, _TRUNCATE, "[%s]", section);
	// case-insensitive search for section header
	size_t nlen = strlen(needle);
	size_t tlen = strlen(narrow);
	for (size_t i=0;i+ nlen <= tlen; ++i) {
		bool match=true;
		for (size_t k=0;k<nlen;++k) {
			char a = narrow[i+k], b = needle[k];
			if (a>='A' && a<='Z') a+=32;
			if (b>='A' && b<='Z') b+=32;
			if (a!=b) { match=false; break; }
		}
		if (match) {
			const char* s = narrow + i + nlen;
			// section content until next '[' at line start or EOF
			const char* e = strchr(s, '[');
			if (!e) e = narrow + tlen;
			// backtrack to start of line containing '['
			// simplistic: take e as end
			*outSecStart = s;
			*outSecEnd = e;
			return true;
		}
	}
	return false;
}

static bool IniGetString(const char* narrow, const char* section, const char* key, char* out, size_t outCap, const char* def)
{
	if (outCap==0) return false;
	out[0]=0;
	if (def) { strncpy_s(out, outCap, def, _TRUNCATE); }
	const char* secStart=nullptr; const char* secEnd=nullptr;
	if (!IniFindSection(narrow, section, &secStart, &secEnd))
		return false;
	size_t klen = strlen(key);
	// iterate lines in section
	const char* p = secStart;
	while (p < secEnd) {
		const char* lineEnd = strchr(p, '\n');
		if (!lineEnd) lineEnd = secEnd;
		// trim leading whitespace
		const char* ls = p;
		while (ls < lineEnd && (*ls==' '||*ls=='\t'||*ls=='\r')) ++ls;
		if (ls < lineEnd && *ls!=';' && *ls!='#' && *ls!='[') {
			// compare key
			const char* eq = (const char*)memchr(ls, '=', lineEnd - ls);
			if (eq) {
				// trim key end whitespace
				const char* ke = eq-1;
				while (ke>ls && (*ke==' '||*ke=='\t')) --ke;
				size_t curKlen = (ke - ls + 1);
				if (curKlen==klen) {
					bool kMatch=true;
					for (size_t i=0;i<klen;++i) {
						char a=ls[i], b=key[i];
						if (a>='A'&&a<='Z') a+=32;
						if (b>='A'&&b<='Z') b+=32;
						if (a!=b) {kMatch=false; break;}
					}
					if (kMatch) {
						const char* vs = eq+1;
						while (vs < lineEnd && (*vs==' '||*vs=='\t')) ++vs;
						const char* ve = lineEnd;
						while (ve>vs && (ve[-1]==' '||ve[-1]=='\t'||ve[-1]=='\r')) --ve;
						// Strip trailing inline comment (; or #)
						const char* comment = (const char*)memchr(vs, ';', ve - vs);
						if (!comment) comment = (const char*)memchr(vs, '#', ve - vs);
						if (comment && comment > vs) ve = comment;
						// Trim whitespace again after comment removal
						while (ve>vs && (ve[-1]==' '||ve[-1]=='\t')) --ve;
						size_t vlen = ve - vs;
						if (vlen >= outCap) vlen = outCap-1;
						memcpy(out, vs, vlen);
						out[vlen]=0;
						return true;
					}
				}
			}
		}
		if (lineEnd==secEnd) break;
		p = lineEnd+1;
	}
	return false;
}

static int IniGetInt(const char* narrow, const char* section, const char* key, int def)
{
	char buf[64];
	if (!IniGetString(narrow, section, key, buf, sizeof(buf), nullptr))
		return def;
	return atoi(buf);
}

static void LoadConfig()
{
	AutoLoginSetPath();

	char narrow[8192] = {0};
	size_t n = LoadIniNarrow(AutoLogin::g_cfgPath, narrow, sizeof(narrow));
	bool fileExists = (n>0) || (GetFileAttributesA(AutoLogin::g_cfgPath)!=INVALID_FILE_ATTRIBUTES);

	// Fallback to GetPrivateProfile* if our narrow load somehow missed (empty file)
	// but prefer our tolerant parser which handles UTF-16 LE/BE and BOM.
	if (n==0 && fileExists) {
		// Try legacy API as fallback for very small files or read failure
		AutoLogin::g_enabled = (GetPrivateProfileIntA("accounts", "enabled", 0, AutoLogin::g_cfgPath) != 0);
		AutoLogin::g_selectedAccount = GetPrivateProfileIntA("accounts", "selected", 0, AutoLogin::g_cfgPath);
	} else if (n>0) {
		AutoLogin::g_enabled = (IniGetInt(narrow, "accounts", "enabled", 0) != 0);
		AutoLogin::g_selectedAccount = IniGetInt(narrow, "accounts", "selected", 0);
	} else {
		AutoLogin::g_enabled = false;
		AutoLogin::g_selectedAccount = 0;
	}
	if (AutoLogin::g_selectedAccount < 0)
		AutoLogin::g_selectedAccount = 0;

	char section[32];
	sprintf_s(section, "account_%d", AutoLogin::g_selectedAccount);

	if (n>0) {
		IniGetString(narrow, section, "account",  AutoLogin::g_account,  sizeof(AutoLogin::g_account),  "");
		IniGetString(narrow, section, "password", AutoLogin::g_password, sizeof(AutoLogin::g_password), "");
		IniGetString(narrow, section, "server",   AutoLogin::g_server,   sizeof(AutoLogin::g_server),   "");
		// password_hex overrides password: raw ANSI bytes (space-separated hex)
		// captured from a successful manual login - byte-exact regardless of
		// keyboard layout or character encoding.
		{
			char hexBuf[1024] = {0};
			if (IniGetString(narrow, section, "password_hex", hexBuf, sizeof(hexBuf), nullptr) && hexBuf[0]) {
				size_t out = 0;
				const char* p = hexBuf;
				while (*p && out + 1 < sizeof(AutoLogin::g_password)) {
					while (*p == ' ' || *p == '\t') ++p;
					if (!*p) break;
					char two[3] = { p[0], p[1], 0 };
					if (!isxdigit((unsigned char)two[0]) || !isxdigit((unsigned char)two[1])) break;
					AutoLogin::g_password[out++] = (char)strtoul(two, nullptr, 16);
					p += 2;
				}
				AutoLogin::g_password[out] = 0;
				AutoLoginLog("LoadConfig: using password_hex (%d bytes) - overrides password=", (int)out);
			}
		}
		// Diagnostic: hex codes of the loaded credentials so a mismatch between
		// the ini file and what the user intends can be seen byte-exactly
		// (ASCII letters = plain codes; anything else shows the ANSI mapping).
		{
			char hx[3*64+1] = {0}; int o = 0;
			for (const unsigned char* q = (const unsigned char*)AutoLogin::g_account; *q && o < (int)sizeof(hx)-4; ++q)
				o += _snprintf_s(hx+o, sizeof(hx)-o, _TRUNCATE, "%02X ", *q);
			AutoLoginLog("INIACCT len=%d bytes=%s", (int)strlen(AutoLogin::g_account), hx);
			o = 0; hx[0] = 0;
			for (const unsigned char* q = (const unsigned char*)AutoLogin::g_password; *q && o < (int)sizeof(hx)-4; ++q)
				o += _snprintf_s(hx+o, sizeof(hx)-o, _TRUNCATE, "%02X ", *q);
			AutoLoginLog("INIPSW len=%d bytes=%s", (int)strlen(AutoLogin::g_password), hx);
		}
		char buf[32];
		if (IniGetString(narrow, "accounts", "boot_wait_ms", buf, sizeof(buf), nullptr)) {
			AutoLogin::g_bootWaitMs = atoi(buf);
		} else AutoLogin::g_bootWaitMs = 6000;
		if (AutoLogin::g_bootWaitMs < 500) AutoLogin::g_bootWaitMs = 500;
		if (IniGetString(narrow, "accounts", "relogin_wait_ms", buf, sizeof(buf), nullptr)) {
			AutoLogin::g_reloginWaitMs = atoi(buf);
		} else AutoLogin::g_reloginWaitMs = 6000;
		if (AutoLogin::g_reloginWaitMs < 500) AutoLogin::g_reloginWaitMs = 500;
		if (IniGetString(narrow, "accounts", "retry_ms", buf, sizeof(buf), nullptr)) {
			AutoLogin::g_retryMs = atoi(buf);
		} else AutoLogin::g_retryMs = 6000;
		if (AutoLogin::g_retryMs < 250) AutoLogin::g_retryMs = 250;
		AutoLogin::g_maxRetries = IniGetInt(narrow, "accounts", "max_retries", 12);
		AutoLogin::g_debugTypePasswordInAccount =
			IniGetInt(narrow, "accounts", "debug_password_into_account", 0) != 0;
		AutoLogin::g_autoLearnPassword =
			IniGetInt(narrow, "accounts", "auto_learn_password", 0) != 0;
	} else {
		// Legacy fallback
		GetPrivateProfileStringA(section, "account",  "", AutoLogin::g_account,  sizeof(AutoLogin::g_account),  AutoLogin::g_cfgPath);
		GetPrivateProfileStringA(section, "password", "", AutoLogin::g_password, sizeof(AutoLogin::g_password), AutoLogin::g_cfgPath);
		GetPrivateProfileStringA(section, "server",   "", AutoLogin::g_server,   sizeof(AutoLogin::g_server),   AutoLogin::g_cfgPath);
		char buf[32];
		GetPrivateProfileStringA("accounts", "boot_wait_ms", "6000", buf, 32, AutoLogin::g_cfgPath);
		AutoLogin::g_bootWaitMs = atoi(buf);
		if (AutoLogin::g_bootWaitMs < 500) AutoLogin::g_bootWaitMs = 500;
		GetPrivateProfileStringA("accounts", "relogin_wait_ms", "6000", buf, 32, AutoLogin::g_cfgPath);
		AutoLogin::g_reloginWaitMs = atoi(buf);
		if (AutoLogin::g_reloginWaitMs < 500) AutoLogin::g_reloginWaitMs = 500;
		GetPrivateProfileStringA("accounts", "retry_ms", "6000", buf, 32, AutoLogin::g_cfgPath);
		AutoLogin::g_retryMs = atoi(buf);
		if (AutoLogin::g_retryMs < 250) AutoLogin::g_retryMs = 250;
		AutoLogin::g_maxRetries = GetPrivateProfileIntA("accounts", "max_retries", 12, AutoLogin::g_cfgPath);
		AutoLogin::g_debugTypePasswordInAccount =
			GetPrivateProfileIntA("accounts", "debug_password_into_account", 0, AutoLogin::g_cfgPath) != 0;
		AutoLogin::g_autoLearnPassword =
			GetPrivateProfileIntA("accounts", "auto_learn_password", 0, AutoLogin::g_cfgPath) != 0;
	}
	if (AutoLogin::g_maxRetries < 0)
		AutoLogin::g_maxRetries = 0;

	// If no file at all, create a commented template so the user sees the format.
	if (!fileExists) {
		FILE* tf=nullptr;
		if (fopen_s(&tf, AutoLogin::g_cfgPath, "w")==0 && tf) {
			fprintf(tf,
				"; Auto login config - place next to Conquer.exe (same folder as D3DX9_43.dll)\n"
				"; Fill account/password and set enabled=1. File is reloaded live every ~1.5s.\n"
				"[accounts]\n"
				"enabled=0\n"
				"selected=0\n"
				"boot_wait_ms=6000\n"
				"relogin_wait_ms=6000\n"
				"retry_ms=6000\n"
				"max_retries=12\n"
				"\n"
				"[account_0]\n"
				"; server = fallback realm name (leave empty to use the dialog's selected realm)\n"
				"server=\n"
				"account=\n"
				"password=\n"
			);
			fclose(tf);
			AutoLoginLog("LoadConfig: created template at %s", AutoLogin::g_cfgPath);
		}
	}
	// Diagnostics: never leave "idle" when disabled - show why.
	if (!fileExists) {
		strcpy_s(AutoLogin::g_lastResult, "no auto_login.ini (template created)");
		AutoLoginLog("LoadConfig: no file at %s (template just created)", AutoLogin::g_cfgPath);
	} else if (!AutoLogin::g_enabled) {
		strcpy_s(AutoLogin::g_lastResult, "disabled in ini");
		AutoLoginLog("LoadConfig: disabled enabled=0 path=%s sel=%d", AutoLogin::g_cfgPath, AutoLogin::g_selectedAccount);
	} else if (!AutoLogin::g_account[0]) {
		strcpy_s(AutoLogin::g_lastResult, "no account in ini");
		AutoLoginLog("LoadConfig: enabled but account empty sel=%d path=%s", AutoLogin::g_selectedAccount, AutoLogin::g_cfgPath);
	} else {
		sprintf_s(AutoLogin::g_lastResult, "config loaded: %s", AutoLogin::g_account);
		AutoLoginLog("LoadConfig: ok enabled=1 account=%s server=%s boot=%lu relogin=%lu retry=%lu max=%d path=%s",
			AutoLogin::g_account, AutoLogin::g_server[0]?AutoLogin::g_server:"(dialog)", AutoLogin::g_bootWaitMs, AutoLogin::g_reloginWaitMs, AutoLogin::g_retryMs, AutoLogin::g_maxRetries, AutoLogin::g_cfgPath);
	}
}

// ============================================================================
// Support check: the two anchor prologues must match this build.
// ============================================================================
static bool IsSupported()
{
	if (IsBadReadPtr((const void*)AutoLogin::LOGIN_SEND_ADDRESS, 12)) {
		AutoLoginLog("IsSupported: LOGIN_SEND bad ptr %p", (void*)AutoLogin::LOGIN_SEND_ADDRESS);
		return false;
	}
	const unsigned char* p = (const unsigned char*)AutoLogin::LOGIN_SEND_ADDRESS;
	// STRICT on purpose: the DLL loads twice (proxy + injected sibling). Only
	// the copy that arrives first must install/submit; letting a second copy
	// past this check makes it hook the already-hooked address with its own
	// MinHook instance and DOUBLE-SUBMIT the login (two identical packets).
	if (p[0] != 0x68 || p[1] != 0x08 || p[2] != 0x04 || p[3] != 0x00 || p[4] != 0x00) {
		AutoLoginLog("IsSupported: LOGIN_SEND mismatch %02X %02X %02X %02X %02X", p[0],p[1],p[2],p[3],p[4]);
		return false;
	}

	// FUN_00c3ac82: 68 74 E3 6C 01  E8 45 39 80 FF (PUSH 0x16CE374; CALL)
	if (IsBadReadPtr((LPCVOID)AutoLogin::BACK_TO_LOGIN_ADDRESS, 6)) {
		AutoLoginLog("IsSupported: BACK_TO_LOGIN bad ptr %p", (void*)AutoLogin::BACK_TO_LOGIN_ADDRESS);
		return false;
	}
	p = (const unsigned char*)AutoLogin::BACK_TO_LOGIN_ADDRESS;
	if (p[0] != 0x68 || p[1] != 0x74 || p[2] != 0xE3 || p[3] != 0x6C || p[4] != 0x01) {
		AutoLoginLog("IsSupported: BACK_TO_LOGIN mismatch %02X %02X %02X %02X %02X", p[0],p[1],p[2],p[3],p[4]);
		return false;
	}

	return true;
}

// ============================================================================
// Hooks
// ============================================================================
int __cdecl HookedLoginSend(const char* account, void* password, const char* serverInfo, int mode, int port)
{
	// Passthrough. The game (or the user's Login click) initiated a login with
	// ITS OWN argument shapes - pass them through untouched. The old version
	// injected ini char* into the password slot, but FUN_0101bfe7 treats arg2
	// as a wrapper object and reads [ptr+0x104] as its length - a char* there
	// is garbage >= 0x81 and the send rejects with "invalid Account or Psw"
	// (0xFFFFFFFF). That is why manual logins showed a wrong password.
	//
	// We only record that an attempt is in flight so the auto-submit does not
	// double-fire while the user is logging in manually.
	// g_autoSubmitInFlight tells ours (posted submit) from a user click. Do NOT
	// clear it here - HookedBackToLogin needs it to classify the cycle and
	// clears it itself.
	bool ours = AutoLogin::g_autoSubmitInFlight;
	// NOTE: intentionally NOT setting g_attemptDone here anymore. The account
	// socket often does not exist yet when the first send is queued (the client
	// dials 170.33.x.x:16000 on its own ~20s internal retry), and that first
	// packet vanishes. Wire-probe evidence (2026-08-01 log): the game re-fires
	// the login itself once connected and logs in fine. So we keep the cycle
	// open and let AutoLoginTick re-submit every retry_ms while the dialog is
	// still visible; the cycle closes when the dialog disappears (accepted).
	if (!AutoLogin::g_attemptDone)
	{
		strcpy_s(AutoLogin::g_lastResult, ours ? "auto login send" : "manual login send");
	}
	AutoLoginLog("HookedLoginSend: %s pass-through account=%s mode=%d port=%d server=%s",
		ours ? "auto" : "manual", account?account:"(null)", mode, port, serverInfo?serverInfo:"(null)");
	// Dump the exact wrapper state the send is about to read: count@+0x100,
	// length@+0x104, first encrypted bytes@+0x108. Fires for BOTH auto and
	// manual sends - diffing an auto line against a manual-typed line isolates
	// any field the auto-fill leaves different (known suspect: +0x100 count,
	// which SetPassword does not touch but the packet hash may include).
	if (password && !IsBadReadPtr(password, 0x210))
	{
		unsigned char* w = (unsigned char*)password;
		__try {
			AutoLoginLog("HookedLoginSend: pswdump cnt=%u len=%u enc=%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X term=%02X",
				*(unsigned int*)(w + 0x100), *(unsigned int*)(w + 0x104),
				w[0x108], w[0x109], w[0x10A], w[0x10B],
				w[0x10C], w[0x10D], w[0x10E], w[0x10F],
				w[0x110], w[0x111], w[0x112], w[0x113],
				w[0x114], w[0x115], w[0x116], w[0x117], w[0x207]);
		} __except(EXCEPTION_EXECUTE_HANDLER) {
			AutoLoginLog("HookedLoginSend: pswdump exception");
		}
	}
	if (AutoLogin::g_OriginalLoginSend)
	{
		// Arm the wire probe: capture outbound/inbound socket traffic for the
		// next 20s so we can verify the packet actually leaves and whether
		// the server answers at all.
		AutoLogin::g_wireProbeUntil = GetTickCount() + 20000;
		AutoLogin::s_fullDumpCount = 0;   // fresh full-payload dumps per attempt
		int r = AutoLogin::g_OriginalLoginSend(account, password, serverInfo, mode, port);
		// 0 = queued onto the socket, 0xFFFFFFFF = rejected locally before any
		// wire traffic (field-length/count checks). This split decides whether
		// "nothing happens" is a client-side reject or a network/server issue.
		AutoLoginLog("HookedLoginSend: original returned %d (%s)", r, r == 0 ? "queued" : "REJECTED");
		return r;
	}
	AutoLoginLog("HookedLoginSend: no original, dropping");
	return 0;
}

void __cdecl HookedBackToLogin()
{
	AutoLoginLog("HookedBackToLogin: enter");
	// Call the original first (it must actually navigate back).
	if (AutoLogin::g_OriginalBackToLogin)
		AutoLogin::g_OriginalBackToLogin();

	// A cycle that returns to the login screen within a minute of our submit
	// is a credential rejection (the server answer arrives in seconds).
	// Longer sessions ending here are normal logouts/disconnects, not
	// credential failures.
	unsigned long now = GetTickCount();
	bool quickFailure = AutoLogin::g_autoSubmitInFlight &&
		(now - AutoLogin::g_lastAttemptTick) < 60000;
	AutoLogin::g_autoSubmitInFlight = false;

	if (quickFailure)
		AutoLogin::g_failedCycles++;
	else
		AutoLogin::g_failedCycles = 0;

	AutoLogin::g_backToLoginSeen = true;
	AutoLogin::g_cycleStartTick = GetTickCount();

	AutoLoginLog("HookedBackToLogin: quickFail=%d failedCycles=%d re-arming", quickFailure?1:0, AutoLogin::g_failedCycles);

	if (AutoLogin::g_failedCycles >= 3)
	{
		// Stop re-arming: wrong credentials would pop the server's error
		// dialog forever, and that modal dialog disables the game window
		// while it is up (frozen input for the user).
		AutoLogin::g_attemptDone = true;
		AutoLogin::g_retryCount = 0;
		strcpy_s(AutoLogin::g_lastResult, "stopped: check creds in auto_login.ini");
		AutoLoginLog("HookedBackToLogin: stopped after 3 failures");
		return;
	}

	AutoLogin::g_attemptDone = false;
	AutoLogin::g_retryCount = 0;
	strcpy_s(AutoLogin::g_lastResult, "back-to-login; re-arming");
}

bool  InstallHooks()
{
	if (AutoLogin::g_hooks)
		return true;

	// SINGLE-INSTANCE GUARD. The DLL loads twice in this setup (proxy +
	// injected copy). Two independent MinHook instances patching the SAME
	// game addresses produce chained hooks: every game call passes through
	// both copies' hooks -> doubled logs, doubled trampoline hops and,
	// for the login send, TWO REAL AUTH PACKETS per click (the server then
	// answers silence even when the credentials are correct).
	// First copy takes the mutex and owns ALL hooking; later copies stay
	// completely inert.
	{
		HANDLE m = CreateMutexA(nullptr, TRUE, "Local\\CDX9Hook_HookOwner");
		if (m == nullptr) {
			AutoLoginLog("InstallHooks: instance mutex create failed %u", GetLastError());
			strcpy_s(AutoLogin::g_lastResult, "instance mutex failed");
			return false;
		}
		if (GetLastError() == ERROR_ALREADY_EXISTS) {
			CloseHandle(m);
			AutoLoginLog("InstallHooks: another DLL copy owns the hooks - staying INERT");
			strcpy_s(AutoLogin::g_lastResult, "duplicate DLL copy - inert");
			return false;
		}
		AutoLogin::g_instanceMutex = m; // held for the lifetime of the process
	}

	if (!IsSupported())
	{
		strcpy_s(AutoLogin::g_lastResult, "unsupported build - inert");
		AutoLoginLog("InstallHooks: unsupported build prologues mismatch");
		return false;
	}

	MH_STATUS st = MH_Initialize();
	if (st != MH_OK && st != MH_ERROR_ALREADY_INITIALIZED)
	{
		strcpy_s(AutoLogin::g_lastResult, "MinHook init failed");
		AutoLoginLog("InstallHooks: MH_Initialize failed %d", st);
		return false;
	}

	st = MH_CreateHook((LPVOID)AutoLogin::LOGIN_SEND_ADDRESS, (LPVOID)HookedLoginSend,
		(LPVOID*)&AutoLogin::g_OriginalLoginSend);
	bool alreadyHooked = (st == MH_ERROR_ALREADY_CREATED);
	if (alreadyHooked) {
		// The DLL is loaded twice (proxy + another module), so a sibling copy
		// already installed this hook. That is fine - the sibling's trampoline
		// forwards to the game just the same. We cannot get the original pointer
		// (no MH_GetHook in this MinHook version), so leave g_OriginalLoginSend
		// null - the submit code already guards against that.
		AutoLoginLog("InstallHooks: LOGIN_SEND already hooked by another copy");
	} else if (st != MH_OK) {
		AutoLoginLog("InstallHooks: CreateHook LOGIN_SEND failed %d addr=%p", st, (void*)AutoLogin::LOGIN_SEND_ADDRESS);
		return false;
	}
	st = MH_EnableHook((LPVOID)AutoLogin::LOGIN_SEND_ADDRESS);
	if (st != MH_OK && !(alreadyHooked && st == MH_ERROR_ENABLED)) {
		AutoLoginLog("InstallHooks: EnableHook LOGIN_SEND failed %d", st);
		return false;
	}

	st = MH_CreateHook((LPVOID)AutoLogin::BACK_TO_LOGIN_ADDRESS, (LPVOID)HookedBackToLogin,
		(LPVOID*)&AutoLogin::g_OriginalBackToLogin);
	if (st != MH_OK && st != MH_ERROR_ALREADY_CREATED) {
		strcpy_s(AutoLogin::g_lastResult, "backtologin hook omitted");
		AutoLoginLog("InstallHooks: CreateHook BACK_TO_LOGIN failed %d (non-fatal)", st);
	} else {
		st = MH_EnableHook((LPVOID)AutoLogin::BACK_TO_LOGIN_ADDRESS);
		if (st != MH_OK && st != MH_ERROR_ENABLED) AutoLoginLog("InstallHooks: EnableHook BACK_TO_LOGIN failed %d", st);
	}

	// Wire probe hooks on ws2_32 (all non-fatal - diagnostics only).
	HMODULE ws2 = GetModuleHandleA("ws2_32.dll");
	if (!ws2)
		ws2 = LoadLibraryA("ws2_32.dll");
	int probeOk = 0;
	if (ws2) {
		void* pSend    = (void*)GetProcAddress(ws2, "send");
		void* pRecv    = (void*)GetProcAddress(ws2, "recv");
		void* pWSASend = (void*)GetProcAddress(ws2, "WSASend");
		void* pWSARecv = (void*)GetProcAddress(ws2, "WSARecv");
		if (pSend && MH_CreateHook(pSend, (LPVOID)&AutoLogin::HookedWireSend,
			(LPVOID*)&AutoLogin::g_OrigSend) == MH_OK &&
			MH_EnableHook(pSend) == MH_OK)
			probeOk |= 1;
		if (pRecv && MH_CreateHook(pRecv, (LPVOID)&AutoLogin::HookedWireRecv,
			(LPVOID*)&AutoLogin::g_OrigRecv) == MH_OK &&
			MH_EnableHook(pRecv) == MH_OK)
			probeOk |= 2;
		if (pWSASend && MH_CreateHook(pWSASend, (LPVOID)&AutoLogin::HookedWireWSASend,
			(LPVOID*)&AutoLogin::g_OrigWSASend) == MH_OK &&
			MH_EnableHook(pWSASend) == MH_OK)
			probeOk |= 4;
		if (pWSARecv && MH_CreateHook(pWSARecv, (LPVOID)&AutoLogin::HookedWireWSARecv,
			(LPVOID*)&AutoLogin::g_OrigWSARecv) == MH_OK &&
			MH_EnableHook(pWSARecv) == MH_OK)
			probeOk |= 8;
		void* pConn    = (void*)GetProcAddress(ws2, "connect");
		void* pWSAConn = (void*)GetProcAddress(ws2, "WSAConnect");
		if (pConn && MH_CreateHook(pConn, (LPVOID)&AutoLogin::HookedWireConnect,
			(LPVOID*)&AutoLogin::g_OrigConnect) == MH_OK &&
			MH_EnableHook(pConn) == MH_OK)
			probeOk |= 16;
		if (pWSAConn && MH_CreateHook(pWSAConn, (LPVOID)&AutoLogin::HookedWireWSAConnect,
			(LPVOID*)&AutoLogin::g_OrigWSAConnect) == MH_OK &&
			MH_EnableHook(pWSAConn) == MH_OK)
			probeOk |= 32;
	}
	AutoLoginLog("InstallHooks: wire probe ws2=%p ok=0x%X (1=send 2=recv 4=WSASend 8=WSARecv 16=connect 32=WSAConnect)", (void*)ws2, probeOk);

	// Popup probes: log every message box the client shows during login.
	HMODULE user32 = GetModuleHandleA("user32.dll");
	int popupOk = 0;
	if (user32) {
		void* pMBA = (void*)GetProcAddress(user32, "MessageBoxA");
		void* pMBW = (void*)GetProcAddress(user32, "MessageBoxW");
		if (pMBA && MH_CreateHook(pMBA, (LPVOID)&AutoLogin::HookedMessageBoxA,
			(LPVOID*)&AutoLogin::g_OrigMsgBoxA) == MH_OK && MH_EnableHook(pMBA) == MH_OK)
			popupOk |= 1;
		if (pMBW && MH_CreateHook(pMBW, (LPVOID)&AutoLogin::HookedMessageBoxW,
			(LPVOID*)&AutoLogin::g_OrigMsgBoxW) == MH_OK && MH_EnableHook(pMBW) == MH_OK)
			popupOk |= 2;
	}
	AutoLoginLog("InstallHooks: popup probe ok=0x%X (1=A 2=W)", popupOk);

	// SetPassword probe - hash-compare auto-filled vs manually typed passwords.
	{
		MH_STATUS sps = MH_CreateHook((LPVOID)AutoLogin::SET_PASSWORD_ADDRESS,
			(LPVOID)&AutoLogin::HookedSetPassword, (LPVOID*)&AutoLogin::g_OrigSetPassword);
		if (sps == MH_OK) {
			sps = MH_EnableHook((LPVOID)AutoLogin::SET_PASSWORD_ADDRESS);
			AutoLoginLog("InstallHooks: setpsw probe %s", sps == MH_OK ? "ok" : "ENABLE FAILED");
		} else {
			AutoLoginLog("InstallHooks: setpsw probe CREATE FAILED %d", sps);
		}
	}

	// Manual-sequence recorders.
	{
		MH_STATUS s1 = MH_CreateHook((LPVOID)AutoLogin::REALM_ROW_HANDLER,
			(LPVOID)&AutoLogin::HookedRealmRow, (LPVOID*)&AutoLogin::g_OrigRealmRow);
		if (s1 == MH_OK) {
			s1 = MH_EnableHook((LPVOID)AutoLogin::REALM_ROW_HANDLER);
			AutoLoginLog("InstallHooks: seq realm-row %s", s1 == MH_OK ? "ok" : "ENABLE FAILED");
		} else {
			AutoLoginLog("InstallHooks: seq realm-row CREATE FAILED %d", s1);
		}
		MH_STATUS s2 = MH_CreateHook((LPVOID)AutoLogin::GET_SERVER_INFO,
			(LPVOID)&AutoLogin::HookedGetServerInfo, (LPVOID*)&AutoLogin::g_OrigGetServerInfo);
		if (s2 == MH_OK) {
			s2 = MH_EnableHook((LPVOID)AutoLogin::GET_SERVER_INFO);
			AutoLoginLog("InstallHooks: seq getserverinfo %s", s2 == MH_OK ? "ok" : "ENABLE FAILED");
		} else {
			AutoLoginLog("InstallHooks: seq getserverinfo CREATE FAILED %d", s2);
		}
	}

	AutoLogin::g_hooks = true;
	strcpy_s(AutoLogin::g_lastResult, "hooks installed");
	AutoLoginLog("InstallHooks: ok login_send=%p back_to_login=%p", (void*)AutoLogin::LOGIN_SEND_ADDRESS, (void*)AutoLogin::BACK_TO_LOGIN_ADDRESS);
	return true;
}

// Hot-reload helper - checks mtime every 1500ms
static unsigned long g_lastConfigCheckTick = 0;
static FILETIME g_lastConfigWriteTime = {0};
static unsigned long g_lastDiagTick = 0;
static void MaybeReloadConfig(unsigned long now)
{
	if (now - g_lastConfigCheckTick < 1500)
		return;
	g_lastConfigCheckTick = now;
	if (!AutoLogin::g_cfgPath[0])
		return;
	WIN32_FILE_ATTRIBUTE_DATA fad;
	if (!GetFileAttributesExA(AutoLogin::g_cfgPath, GetFileExInfoStandard, &fad))
		return;
	if (fad.ftLastWriteTime.dwLowDateTime == g_lastConfigWriteTime.dwLowDateTime &&
	    fad.ftLastWriteTime.dwHighDateTime == g_lastConfigWriteTime.dwHighDateTime)
		return;
	g_lastConfigWriteTime = fad.ftLastWriteTime;
	// Preserve previous enabled/account to detect changes for logging.
	bool prevEnabled = AutoLogin::g_enabled;
	char prevAcc[128]; strcpy_s(prevAcc, AutoLogin::g_account);
	LoadConfig();
	if (prevEnabled != AutoLogin::g_enabled || strcmp(prevAcc, AutoLogin::g_account)!=0) {
		AutoLoginLog("MaybeReloadConfig: config changed enabled %d->%d account %s->%s", prevEnabled?1:0, AutoLogin::g_enabled?1:0, prevAcc, AutoLogin::g_account);
		// If we just became enabled, reset cycle so we don't wait full boot delay from old start.
		if (AutoLogin::g_enabled && !prevEnabled) {
			AutoLogin::g_attemptDone = false;
			AutoLogin::g_retryCount = 0;
			AutoLogin::g_cycleStartTick = now;
			AutoLogin::g_backToLoginSeen = false;
		}
	}
}

// ============================================================================
// Auto-submit tick - call every frame (even with the overlay closed).
// ============================================================================
void AutoLoginTick()
{
	// Static-load once.
	if (!AutoLogin::g_cfgPath[0])
		LoadConfig();

	// Hot-reload: pick up edits to auto_login.ini without restart.
	unsigned long nowEarly = GetTickCount();
	MaybeReloadConfig(nowEarly);

	// Manual-capture mode: every bit of automation is frozen; the probes
	// (wire / setpsw / seq hooks) keep recording passively so a human login
	// can be captured and compared against the auto sequence.
	if (AutoLogin::g_manualCapture)
		return;

	// Install hooks when EITHER auto-login is enabled OR auto-learn is armed.
	// The wire/setpsw probes must be live for a successful MANUAL login to be
	// captured as password_hex (that is the whole point of auto_learn_password).
	// When only learning (enabled=0), we never auto-submit - the caller still
	// needs the probes recording.
	if ((!AutoLogin::g_enabled || !AutoLogin::g_account[0]) &&
	    !AutoLogin::g_autoLearnPassword) {
		// Keep hooks installed even when disabled so manual logins still
		// show diagnostics, but don't attempt auto-submit.
		return;
	}

	if (!AutoLogin::g_hooks)
	{
		if (!InstallHooks()) {
			// Throttle diagnostics: only log once per second
			if (nowEarly - g_lastDiagTick > 1000) {
				g_lastDiagTick = nowEarly;
				AutoLoginLog("AutoLoginTick: InstallHooks failed, state=%s", AutoLogin::g_lastResult);
			}
			return;   // unsupported build: never touch the client
		}
		AutoLogin::g_cycleStartTick = GetTickCount();
		AutoLoginLog("AutoLoginTick: hooks ready, cycleStart=%lu", AutoLogin::g_cycleStartTick);
	}

	// Learn-only mode: probes are live but never auto-submit. Return here so a
	// human can log in and the wire probe captures the true password bytes.
	if (!AutoLogin::g_enabled)
		return;

	unsigned long now = GetTickCount();

	if (AutoLogin::g_attemptDone)
		return;   // a login was already sent this cycle; wait for the world.

	// Only the copy that owns the LOGIN_SEND hook drives the login. The DLL is
	// loaded twice (proxy + another module); the second copy finds the hook
	// already created and has no original trampoline (g_OriginalLoginSend is
	// null), so it must not touch the dialog's fields - writing the wrapper
	// while the owner submits would corrupt the in-flight login and crash.
	if (!AutoLogin::g_OriginalLoginSend)
		return;

	// Gate: the game only submits while the account-login dialog is actually
	// visible (its dispatcher checks IsWindowVisible(dialog+0x20) right before
	// invoking the Login handler). Sending earlier queues the packet into a
	// dead socket and the client silently drops it - the boot "nothing
	// happens" bug.
	void* dialog = AutoLogin::GetLoginDialog();
	HWND dlgHwnd = nullptr;
	bool dialogValid = false;
	__try {
		if (dialog && !IsBadReadPtr(dialog, AutoLogin::DLG_HWND_OFFSET + sizeof(HWND))) {
			dlgHwnd = *(HWND*)((unsigned char*)dialog + AutoLogin::DLG_HWND_OFFSET);
			dialogValid = (dlgHwnd != nullptr && IsWindow(dlgHwnd));
		}
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		dialogValid = false;
		dlgHwnd = nullptr;
	}
	bool visible = false;
	if (dialogValid) {
		__try { visible = IsWindowVisible(dlgHwnd) != 0; } __except(EXCEPTION_EXECUTE_HANDLER) { visible = false; }
	}
	if (!dialog || !dialogValid || !visible)
	{
		// Success detection: after we have submitted at least once, the login
		// dialog disappearing means the server accepted and the client is
		// transitioning into the world (or an error dialog took over - either
		// way this cycle is over; back-to-login re-arms if it was a failure).
		if (AutoLogin::g_submitCount > 0 && AutoLogin::g_retryCount > 0)
		{
			AutoLogin::g_attemptDone = true;
			strcpy_s(AutoLogin::g_lastResult, "login accepted (dialog gone)");
			AutoLoginLog("AutoLoginTick: dialog gone after %lu submit(s) - cycle done", AutoLogin::g_submitCount);
			return;
		}
		if (now - g_lastDiagTick > 1000) {
			g_lastDiagTick = now;
			void* clientPtr = nullptr;
			__try { if (!IsBadReadPtr((void*)AutoLogin::MAIN_CLIENT_GLOBAL, sizeof(void*))) clientPtr = *(void**)AutoLogin::MAIN_CLIENT_GLOBAL; } __except(EXCEPTION_EXECUTE_HANDLER) {}
			char diag[128];
			if (!dialog) _snprintf_s(diag, _TRUNCATE, "client=%p null", clientPtr);
			else if (!dialogValid) _snprintf_s(diag, _TRUNCATE, "hwnd invalid dlg=%p hwnd=%p", dialog, dlgHwnd);
			else _snprintf_s(diag, _TRUNCATE, "not visible hwnd=%p", dlgHwnd);
			AutoLoginLog("AutoLoginTick: waiting for login screen - %s", diag);
		}
		if (AutoLogin::g_retryCount == 0)
			strcpy_s(AutoLogin::g_lastResult, "waiting for login screen");
		return;
	}

	// Pick the wait base: after a back-to-login use the relogin delay, else boot.
	unsigned long waitMs = AutoLogin::g_backToLoginSeen
		? AutoLogin::g_reloginWaitMs
		: AutoLogin::g_bootWaitMs;

	// First submit waits from the current cycle start; a retry waits only the
	// short retry gap.
	if (AutoLogin::g_retryCount == 0)
	{
		if (now - AutoLogin::g_cycleStartTick < waitMs)
			return;
	}
	else if (now - AutoLogin::g_lastAttemptTick < AutoLogin::g_retryMs)
	{
		return;
	}

	// Anti-double-submit: PostMessage is async - the game thread needs time to
	// run FUN_008a8fba (which fires HookedLoginSend -> g_attemptDone). Do not
	// re-fill / re-post inside that window even though attemptDone is still
	// false; if the send truly never fires we retry after the grace expires.
	if (now < AutoLogin::g_postGraceUntil)
		return;

	// Retry cap for this cycle. The account socket typically comes up within
	// ~20-30s of boot, so the default budget (max_retries x retry_ms) should
	// comfortably cover it; HookedBackToLogin resets the counter for the next
	// cycle, and a fresh boot starts a fresh cycle.
	if (AutoLogin::g_retryCount >= AutoLogin::g_maxRetries)
	{
		if (now - g_lastDiagTick > 5000) {
			g_lastDiagTick = now;
			strcpy_s(AutoLogin::g_lastResult, "retries exhausted this cycle");
			AutoLoginLog("AutoLoginTick: retries exhausted (%d) - waiting for dialog/manual/back-to-login", AutoLogin::g_maxRetries);
		}
		return;
	}

	// Pair A/B selection: the game's button handler checks the flag byte at
	// 0x13620 ONLY in the poker path (mode 2).  In the classic path (mode 0,
	// which we always use here) the game always reads pair A (+0x13B88/0x13BD0)
	// regardless of the flag.  Match that: always use pair A.
	//
	// Claim this attempt NOW, before touching any dialog field: a concurrent
	// tick thread that passes all gates in the same millisecond would
	// otherwise double-fill and double-post (seen at retry=3/12 in the logs).
	AutoLogin::g_postGraceUntil = GetTickCount() + 2000;

	unsigned char* dlg = (unsigned char*)dialog;
	// Ghidra-verified 2026-08: the login handler FUN_008a8fba reads
	// account SSO at dialog+0x13B88, password wrapper at dialog+0x13BD0.
	// The keyboard handler FUN_0089c003 writes the same fields.
	unsigned char* accountObj       = dlg + AutoLogin::DLG_ACCOUNT_SSO;     // SSO account string
	void*         pswObj            = dlg + AutoLogin::DLG_PASSWORD_WRAPPER; // CGameInputStr wrapper (SetPassword target)

	// Fill the dialog's OWN credential fields - the exact inputs a manual
	// typing + Login click would produce.
	AutoLogin::SsoSet(accountObj, AutoLogin::g_account);
	AutoLoginLog("AutoLoginTick: filled account '%s' into %p (SSO @+0x13B88)", AutoLogin::g_account, accountObj);

	// Password: call the game's OWN CGameInputStr::SetPassword on the
	// dialog's wrapper at +0x13BD0. It writes len@+0x104, XOR-
	// encrypts the text into +0x108 against the wrapper's per-boot key
	// table and nulls +0x207 - byte-identical to what typing produces.
	// Do NOT touch the wrapper's +0..0xFF area by hand (SsoSet would
	// clobber the key table) and do NOT write +0x108 directly (the
	// packet hash expects the encrypted form).
	const char* pswText = AutoLogin::g_password;
	char pswTrunc[0x100];
	if (pswText && strlen(pswText) >= 0x100)
	{
		strncpy_s(pswTrunc, pswText, 0xFF);
		pswTrunc[0xFF] = '\0';
		pswText = pswTrunc;
	}
	if (pswText && *pswText)
	{
		__try {
			AutoLogin::SetPasswordFn setPsw = (AutoLogin::SetPasswordFn)AutoLogin::SET_PASSWORD_ADDRESS;
			setPsw(pswObj, nullptr, pswText);
			AutoLoginLog("AutoLoginTick: SetPassword ok wrapper=%p len=%u", pswObj, *(unsigned int*)((unsigned char*)pswObj + 0x104));
		} __except(EXCEPTION_EXECUTE_HANDLER) {
			AutoLoginLog("AutoLoginTick: SetPassword exception wrapper=%p", pswObj);
			strcpy_s(AutoLogin::g_lastResult, "SetPassword crash");
			return;
		}
	} else {
		AutoLoginLog("AutoLoginTick: empty password, skipping SetPassword");
	}

	// Realm: prefer the ini server value (stable, user-configured display name).
	// The game's own button handler resolves the selected realm through
	// GetServerInfo + a hash round-trip (FUN_0121ceab) before sending; passing
	// the dialog's raw CString (e.g. ".\Server") instead of the resolved
	// display name confused the server-response parser and crashed the client.
	// The dialog CString is only used as a fallback when the ini is empty.
	const char* serverName = AutoLogin::g_server;
	if (!serverName || !serverName[0])
		serverName = AutoLogin::CStringCStr(dlg + AutoLogin::DLG_SERVER_NAME);

	// Port argument: replicate the button handler (flag gate + atoi).
	int port = 0;
	if (*(int*)(dlg + AutoLogin::DLG_PORT_FLAG) != 0)
	{
		const char* ps = AutoLogin::SsoCStr(dlg + AutoLogin::DLG_PORT_STR);
		if (ps)
			port = atoi(ps);
	}

	AutoLoginLog("AutoLoginTick: submitting account='%s' server='%s' port=%d mode=0 retry=%d", AutoLogin::SsoCStr(accountObj), serverName?serverName:"(null)", port, AutoLogin::g_retryCount);

	AutoLogin::g_lastAttemptTick = now;
	AutoLogin::g_retryCount++;

	// Ensure a server is selected in the dialog.  The game's OWN login button
	// handler (FUN_008a8fba) reads the group/server indices at dialog+0x135f8/
	// +0x135fc and the server name CString at +0x13628, then resolves the
	// account-server IP/port via GetServerInfo (FUN_008827c2).  If no server
	// is selected (e.g. at boot before any server button click), GetServerInfo
	// resolves nothing, the account socket never connects, and the packet goes
	// into a dead socket — the "nothing happens" symptom.
	//
	// The server list (m_vecGroup at dialog+0x13ddc/0x13de0) is loaded from
	// the account server asynchronously.  Wait until it arrives, then select
	// the first group/server from the list so the indices are valid for the
	// current session (not stale ones loaded from ini/PlaySetUP.ini).
	__try {
		int* begin = *(int**)(dlg + 0x13ddc);
		int* end = *(int**)(dlg + 0x13de0);
		if (begin == end) {
			// Server list not loaded yet — wait.  The game's own init
			// populates this from the account server connection.
			AutoLoginLog("AutoLoginTick: waiting for server list (m_vecGroup empty)");
			return;
		}
		// Select the first group from the loaded list.
		typedef void (__fastcall* SelectServerFn)(void* dialog);
		((SelectServerFn)AutoLogin::SERVER_SELECT_HANDLER)(dlg);
		AutoLoginLog("AutoLoginTick: selected server group=%d server=%d",
			*(int*)(dlg + AutoLogin::DLG_ACTIVE_GROUP), *(int*)(dlg + AutoLogin::DLG_ACTIVE_SERVER));

	} __except(EXCEPTION_EXECUTE_HANDLER) {
		AutoLoginLog("AutoLoginTick: server selection exception");
		return;
	}

	// Submit the login on the GAME'S OWN MESSAGE THREAD.  The game's Login
	// button handler (FUN_008a8fba) runs GetServerInfo (connects the
	// account-server socket) then sends — but it is MFC-heavy and crashes if
	// called from the render thread.  So we PostMessage a custom message to
	// the login DIALOG's HWND; HookedWindowProcedure (installed on all
	// process windows, running on the game's message thread) receives it and
	// invokes FUN_008a8fba for us.
	//
	// We keep the LOGIN_SEND passthrough hook installed for diagnostics, but
	// the actual submit is driven here via the message, not by calling
	// FUN_0101bfe7 directly (that queues into a dead socket because
	// GetServerInfo was never allowed to run).
	// Pre-submit dump of every byte FUN_0101bfe7 reads from the pair-A fields,
	// so an auto run can be diffed against a manual login run:
	//   password wrapper: count@+0x100, len@+0x104, encrypted text@+0x108
	//   account SSO: inline text + length@+0x14
	//   dialog realm CString content (what the handler resolves the realm from)
	__try {
		// The live wrapper read by FUN_008a8fba's mode-0 send is at
		// dialog+0x13BD0 (DLG_PASSWORD_WRAPPER). Decrypt the stored
		// ciphertext and compare FNV against the ini password - if the
		// game doesn't hold the right bytes here, the server's compare
		// against its own stored hash will reject.
		unsigned char* liveWrapper = (unsigned char*)dlg + AutoLogin::DLG_PASSWORD_WRAPPER;
		unsigned int cnt = *(unsigned int*)(liveWrapper + 0x100);
		unsigned int len = *(unsigned int*)(liveWrapper + 0x104);
		const unsigned char* enc = liveWrapper + 0x108;
		const char* dlgSrv = AutoLogin::CStringCStr(dlg + AutoLogin::DLG_SERVER_NAME);
		unsigned char storedPlain[0x100];
		AutoLogin::DecryptStoredPassword(liveWrapper, storedPlain, sizeof(storedPlain));
		unsigned long storedF = AutoLogin::FnvHashBytes(storedPlain,
			len > 0x100 ? 0x100 : (int)len);
		unsigned long iniF = AutoLogin::FnvHashStr(AutoLogin::g_password);
		AutoLoginLog("AutoLoginTick: pre-submit psw(cnt=%u len=%u) enc=%02X%02X%02X%02X%02X%02X%02X%02X acct='%s' acctlen=%u dlgsrv='%s'",
			cnt, len, enc[0], enc[1], enc[2], enc[3], enc[4], enc[5], enc[6], enc[7],
			AutoLogin::SsoCStr(accountObj),
			*(unsigned long*)((unsigned char*)accountObj + AutoLogin::SSO_LEN_OFFSET),
			dlgSrv ? dlgSrv : "");
		AutoLoginLog("AutoLoginTick: PASSWORD CHECK: storedFNV=%08lX iniFNV=%08lX => %s%s",
			storedF, iniF,
			storedF == iniF ? "MATCH - game holds the ini password" : "*** MISMATCH - game does NOT hold the ini password ***",
			len != strlen(AutoLogin::g_password) ? " (len differs too)" : "");
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		AutoLoginLog("AutoLoginTick: pre-submit dump exception");
	}

	if (dlgHwnd)
	{
		if (PostMessageA(dlgHwnd, WM_AUTOLOGIN_SUBMIT, 0, (LPARAM)dlg))
		{
			AutoLogin::g_submitCount++;
			// Mark the in-flight attempt as OURS so HookedBackToLogin can
			// classify a quick return-to-login as an auto-login failure and
			// stop after repeated credential rejections.
			AutoLogin::g_autoSubmitInFlight = true;
			// (grace window already claimed before the fill - see above)
			// Do NOT set g_attemptDone here.  The send (FUN_0101bfe7) fires
			// synchronously inside the handler on the game thread; our
			// HookedLoginSend passthrough sets g_attemptDone when it actually
			// sees the send.  Leaving it false here means: if GetServerInfo
			// fails and the send never fires, AutoLoginTick retries next frame.
			strcpy_s(AutoLogin::g_lastResult, "auto-login submit posted");
			AutoLoginLog("AutoLoginTick: posted login submit to dialog hwnd=%p", dlgHwnd);
		}
		else
		{
			AutoLoginLog("AutoLoginTick: PostMessage failed hwnd=%p", dlgHwnd);
			strcpy_s(AutoLogin::g_lastResult, "PostMessage failed");
		}
	}
	else
	{
		AutoLoginLog("AutoLoginTick: no dialog hwnd for submit");
		strcpy_s(AutoLogin::g_lastResult, "no dialog hwnd - retrying");
	}
}

// Periodic refresh of the config (called from the topic too, cheap enough).
void AutoLoginReloadConfig()
{
	if (!AutoLogin::g_cfgPath[0])
		LoadConfig();
}

// ============================================================================
// Public entry points
// ============================================================================
// Logging helper for the cross-thread login handler (called from
// directx_hooks.cpp's HookedWindowProcedure when the login submit message
// arrives).  Writes to the same auto_login.log file as the main module.
void AutoLoginLogFromHook(const char* msg, void* dialog, HWND hwnd)
{
	AutoLoginLog("Hook: %s dialog=%p hwnd=%p", msg, dialog, hwnd);
}

// Runs every frame from the ImGui loop (menu open or closed), same slot as the
// other Apply*ClientState() helpers.
void ApplyAutoLoginClientState()
{
	AutoLoginTick();
}

// Debug/status readout for the overlay-free module (visible via a file log or
// just left as string state used by future diagnostics).
const char* GetAutoLoginStateString()     { return AutoLogin::g_lastResult; }
bool        GetAutoLoginEnabled()         { return AutoLogin::g_enabled; }
bool        GetAutoLoginHooksInstalled()  { return AutoLogin::g_hooks; }
unsigned long GetAutoLoginSubmitCount()   { return AutoLogin::g_submitCount; }
int         GetAutoLoginSelectedAccount() { return AutoLogin::g_selectedAccount; }
unsigned long GetAutoLoginLastAttemptTick(){ return AutoLogin::g_lastAttemptTick; }

// Manual-capture toggle (overlay button): freezes ALL auto-login automation
// and keeps the probes recording so a human login can be compared against.
void AutoLoginSetManualCapture(bool on)
{
	if (on == AutoLogin::g_manualCapture)
		return;
	AutoLogin::g_manualCapture = on;
	AutoLogin::s_fullDumpCount = 0;
	if (on) {
		AutoLoginLog("=== MANUAL CAPTURE START === auto-automation FROZEN - do the login by hand now; everything is recorded");
		strcpy_s(AutoLogin::g_lastResult, "manual capture ON");
	} else {
		AutoLoginLog("=== MANUAL CAPTURE STOP === auto-login resumed");
		strcpy_s(AutoLogin::g_lastResult, "manual capture off");
	}
}

bool AutoLoginGetManualCapture() { return AutoLogin::g_manualCapture; }