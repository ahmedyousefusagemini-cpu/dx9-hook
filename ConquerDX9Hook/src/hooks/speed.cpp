#include <stdio.h>
#include <signal.h>
#include <windows.h>
#include <stdint.h>
#include "imgui.h"

// ============================================================================
// Speed Control (CRole action speed fields) - Conquer.exe client 7937 (0x400000)
// ----------------------------------------------------------------------------
// IMPORTANT LIVE FINDING (2026-08-10): in the running game, the per-role
// action-interval virtual FUN_010afd05 is ALREADY hooked - its first 5 bytes
// are overwritten with  E9 66 3D 26 73  (JMP 0x74313A70, a dynamically
// allocated trampoline page). Something (server anti-cheat / launcher patch)
// watches the classic speed-hack spot, so this module uses NO code hooks at
// all and drives speed through the role's own speed fields instead:
//
// Inside the master interval computation FUN_00de86b2 (3drole\role.cpp), the
// final scaling for the role's current action (walk / attack / pickup) is:
//   interval = ceil(interval * 100 / (100 + role+0x44/100))   when role+0x48 != 0
// role+0x44 is in 1/100-percent units: 10000 -> divisor 200 -> 2x speed.
// This path has NO per-state cap (that cap table only gates role+0xc0).
//
// My-role discovery without hooks: the scan matches the client id fields
// against the role's id fields (two placements seen in the wild - this server
// leaves client+0x26c = 0 and uses client+0x268), then VALIDATES the
// candidate's class: its vtable must contain one of the interval functions
// (FUN_010afd05 / FUN_00de86b2 - only role classes have them), so a random
// object carrying the same id can't win the scan.
//
// Looting speed: the hunt brain (FUN_00f54058) only ticks when
//   timeGetTime() >= DAT_01a5cdb4 + 1000.
// Only the brain ever reads or writes that global (xref-verified). First
// version re-armed the gate EVERY frame (brain ticked at frame rate,
// ~30-60 loot/attack orders/sec) - the server's packet rate limiter
// disconnected the character (confirmed live). The overlay now re-arms the
// gate at a controlled rate instead (default 250 ms = 4 ticks/sec).
//
// XP skill speed boost (2026-08-11): AUTOMATION OF THE USER'S PROVEN MANUAL
// PROCESS. The user does this by hand and it is stable EVEN AT 2000%:
//   hunt at 100% -> XP skill lands -> drag the slider up -> when the buff is
//   consumed, drag it back to 100% (avoids a server disconnect).
// The automation does the identical swap through the identical write path,
// with the same human timing: a 400 ms settle delay after the buff lands
// (never boost in the cast frame), instant snap-back when the buff ends.
//
// XP-buff detection is PURE MEMORY READS - no game-code calls. The game's
// status checker FUN_00f1a1d8(client, id) -> FUN_00d4e0ae is just a bitmask
// lookup, decoded by disassembly:
//   status flags = 64-bit bitmask array at client+0x138;
//   entry = manager + (id >> 6) * 8, bit = id & 0x3F
//   (low 32 bits at entry+0, high 32 bits at entry+4; ids < 0x240).
// The flag ids come from the game's own XP code: the bar-fill function
// FUN_011154f5 refuses to refill while 0x96/0xC0/0xEB are up, and the XP
// dispatcher FUN_00a1d6bc skips re-casting while 0x5C/0x79/0x78/0x92/0x9F/
// 0xC0/0xEB are up. Union = the 8 ids polled below.
//
// v10 - crash FORENSICS (2026-08-11, late): the v9 crash reporter caught the
// crash - C0000005 (access violation) at Conquer.exe+0xE57F95 (VA 0x01257F95)
// dereferencing address 0 (accessTarget=00000000), i.e. a NULL pointer used
// with no field offset - the classic shape of a virtual call on a NULL object
// or a NULL global being dereferenced. The crash is in GAME code, not this
// DLL (dll base 0x736F0000), and the boost wrote NOTHING to game memory in
// the captured run (detect-only was on; no role was ever found). v10 extends
// the crash report with everything needed to identify the dying subsystem
// without a debugger:
//   - full register dump (which register held the NULL),
//   - the 8 instruction bytes at EIP (the exact faulting instruction),
//   - an EBP-frame stack walk (8 frames) - the return addresses name the
//     calling functions and therefore the game subsystem,
//   - a raw stack dump (esp..esp+32) as a fallback for frameless code.
// The trace file handle is now kept open for the whole session (opened once)
// so antivirus interference can't silently swallow mid-run marker lines
// (that is what made the v7b/v8 traces look like they stopped early).
//
// The v6-v9 diagnostics stay: stage tracer (speed_boost_trace.txt),
// detect-only safe mode (default ON), per-frame window markers, build tag.
//
// Safety: only data writes, nothing patched, no game-code calls. The game's
// interval math clamps divisors to >= 1 and the final interval to >= 1. All
// speed-up is client-side: the server may rubber-band movement or drop loot
// requests at extreme values - 500% is the live-validated stable ceiling.
// ============================================================================

namespace Speed
{
	const uintptr_t CLIENT_GLOBAL_ADDRESS  = 0x01A52960;  // DAT_01a52960 - client object*
	const uintptr_t HUNT_BRAIN_TICK_GLOBAL = 0x01A5CDB4;  // DAT_01a5cdb4 - last brain tick (timeGetTime)
	const uintptr_t ACTION_INTERVAL_FUNC   = 0x010AFD05;  // FUN_010afd05 - interval virtual (vtable check)
	const uintptr_t ACTION_INTERVAL_CORE   = 0x00DE86B2;  // FUN_00de86b2 - master computation (vtable check)
	const uintptr_t SPEED_CAP_TABLE        = 0x016F7E44;  // per-state nSpeedPercent caps (13 dwords)

	// Two id placements seen in the wild (this server leaves client+0x26c = 0):
	//  A: client+0x268 <-> role+0x54   (the game's own my-role match in FUN_00d3203a:
	//     "skip candidate unless role+0x54 == client+0x268")
	//  B: client+0x26c <-> role+0x268  (FUN_0098c58d getter / msg filter FUN_01000e06)
	const size_t CLIENT_MY_ID_A_OFFSET = 0x268;  // client+0x268: my id (variant A)
	const size_t CLIENT_MY_ID_B_OFFSET = 0x26c;  // client+0x26c: my id (variant B)
	const size_t ROLE_ID_A_OFFSET      = 0x54;   // role+0x54: entity id (variant A)
	const size_t ROLE_ID_B_OFFSET      = 0x268;  // role+0x268: entity id (variant B)
	const size_t ROLE_ACTION_STATE       = 0xb4;   // role+0xb4: action state dword (< 13)
	const size_t ROLE_SPEED_BOOST_OFFSET = 0x44;   // role+0x44: boost in 1/100 % (needs +0x48)
	const size_t ROLE_SPEED_BOOST_FLAG   = 0x48;   // role+0x48: byte, enables the +0x44 divisor
	const size_t ROLE_SPEED_DELTA_OFFSET = 0xc0;   // role+0xc0: nSpeedPercent delta (FUN_00deb537)

	// Status flags bitmask (the XP-buff detector; see the header comment).
	const size_t CLIENT_STATUS_FLAGS_OFFSET = 0x138;  // client+0x138: 64-bit flag array
	const size_t STATUS_FLAGS_SPAN = 9 * 8;           // ids < 0x240 -> 9 qwords = 72 bytes

	const int MIN_SPEED_PERCENT = 100;   // 100% = normal speed
	const int MAX_SPEED_PERCENT = 2000;  // user-requested test range (manually validated)

	// XP boost slider range - same engine, same range as the base slider.
	const int MIN_XP_BOOST_PERCENT = 100;
	const int MAX_XP_BOOST_PERCENT = 2000;

	// The user's crash-free manual process never applies the high speed in the
	// XP skill's cast frame - they react a moment after the buff lands. The
	// automation does the same (see the header comment).
	const DWORD BOOST_APPLY_DELAY_MS = 400;

	const int MIN_LOOT_TICK_INTERVAL_MS = 50;    // faster than ~20/sec trips rate limits
	const int MAX_LOOT_TICK_INTERVAL_MS = 1000;  // 1000 ms = stock brain rate

	const uintptr_t IMAGE_BASE = 0x00400000;   // Conquer.exe image base
	const uintptr_t IMAGE_TOP  = 0x02000000;   // vtable sanity range upper bound

	// Rendered in the UI so the running DLL version is verifiable from a
	// screenshot (stale-DLL confusion cost us several crash rounds).
	const char* const BUILD_TAG = "v10 (2026-08-11)";

	// XP-buff status flag ids (see the header comment for provenance).
	const unsigned int XP_STATUS_IDS[] = { 0x5C, 0x78, 0x79, 0x92, 0x96, 0x9F, 0xC0, 0xEB };

	// User settings.
	bool g_speedEnabled = false;
	int  g_speedPercent = 200;          // default 2x
	bool g_fastLootTick = false;        // re-arm the brain tick gate at a safe rate
	int  g_lootTickIntervalMs = 250;    // default: brain ticks at most every 250 ms (4/sec)
	bool g_xpBoostEnabled = false;      // speed up while an XP skill buff is active
	int  g_xpBoostPercent = 500;        // default 5x - the live-validated stable value
	bool g_xpBoostDetectOnly = true;    // SAFE DEFAULT: poll + display only, no speed writes
	bool g_traceEnabled = true;         // crash tracer -> speed_boost_trace.txt
	int  g_watchFrames = 0;             // frames of fine-grained tracing after enable
	int  g_traceFailures = 0;           // consecutive trace write failures

	// My-role cache + scan state (written by the scan thread, read per-frame).
	volatile uintptr_t g_myRoleAddress = 0;
	volatile long g_scanState = 0;      // 0 idle, 1 scanning, 2 done
	volatile unsigned long g_lastScanTick = 0;
	volatile unsigned int g_scanIdMatches = 0;  // id hits before strict checks
	volatile int g_matchedRule = 0;             // which id rule hit (0 none, 1 A, 2 B, 3 cross)
	volatile int g_vtableHasIntervalFn = 0;     // candidate's vtable passed the class check
	bool g_xpBuffActive = false;                // last status poll (for the UI)
	bool g_prevBuffActive = false;              // edge detection for the tracer + delay
	DWORD g_buffActivatedTick = 0;              // when the current buff was first seen
	bool g_firstPassPending = false;            // log the first tick's stages after enable
	bool g_renderLogged = false;                // log the first boost-section render
	bool g_anySpeedWasOn = false;               // last frame's wantSpeed (off-transition restore)
	unsigned int g_originalCaps[13] = {0};      // saved SPEED_CAP_TABLE contents
	bool g_capsRaised = false;
	unsigned int g_raisedCapValue = 0;          // what the table currently holds

	// Append raw text to a file in the game's working directory (per-event
	// open/close - used only by the crash reporter, which runs at most once).
	bool AppendLogLine(const char* fileName, const char* line, int len)
	{
		HANDLE h = CreateFileA(fileName, FILE_APPEND_DATA,
			FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS,
			FILE_ATTRIBUTE_NORMAL, NULL);
		if (h == INVALID_HANDLE_VALUE)
			return false;
		DWORD written = 0;
		WriteFile(h, line, (DWORD)len, &written, NULL);
		CloseHandle(h);
		return true;
	}

	// The crash reporter: runs on ANY unhandled exception, anywhere in the
	// client (not just our code). Writes the exception record, ALL registers,
// the instruction bytes at EIP, an EBP-frame stack walk, and a raw stack
	// dump to speed_boost_crash.txt - enough to identify the dying game
	// subsystem without a debugger. (The first capture proved the crash is a
	// NULL deref inside Conquer.exe itself, not in this DLL.)
	LONG WINAPI CrashFilter(EXCEPTION_POINTERS* ep)
	{
		EXCEPTION_RECORD* er = ep ? ep->ExceptionRecord : NULL;
		CONTEXT* ctx = ep ? ep->ContextRecord : NULL;
		if (er == NULL || ctx == NULL)
			return EXCEPTION_CONTINUE_SEARCH;

		DWORD accessTarget = 0;
		if (er->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && er->NumberParameters >= 2)
			accessTarget = (DWORD)er->ExceptionInformation[1];

		HMODULE hGame = GetModuleHandleA(NULL);           // Conquer.exe base
		HMODULE hSelf = NULL;                              // this DLL's base
		GetModuleHandleExA(
			GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
			(LPCSTR)&CrashFilter, &hSelf);

		char line[512];
		int len = _snprintf_s(line, sizeof(line), _TRUNCATE,
			"CRASH code=%08X addr=%08X accessTarget=%08X game=%08X dll=%08X\r\n",
			er->ExceptionCode, (DWORD)er->ExceptionAddress, accessTarget,
			(DWORD)hGame, (DWORD)hSelf);
		if (len > 0)
			AppendLogLine("speed_boost_crash.txt", line, len);

		len = _snprintf_s(line, sizeof(line), _TRUNCATE,
			"regs eax=%08X ebx=%08X ecx=%08X edx=%08X esi=%08X edi=%08X eip=%08X esp=%08X ebp=%08X\r\n",
			(DWORD)ctx->Eax, (DWORD)ctx->Ebx, (DWORD)ctx->Ecx, (DWORD)ctx->Edx,
			(DWORD)ctx->Esi, (DWORD)ctx->Edi, (DWORD)ctx->Eip, (DWORD)ctx->Esp, (DWORD)ctx->Ebp);
		if (len > 0)
			AppendLogLine("speed_boost_crash.txt", line, len);

		// The faulting instruction bytes (identifies which register was NULL).
		if (!IsBadReadPtr((const void*)ctx->Eip, 8))
		{
			const unsigned char* code = (const unsigned char*)ctx->Eip;
			len = _snprintf_s(line, sizeof(line), _TRUNCATE,
				"code@%08X: %02X %02X %02X %02X %02X %02X %02X %02X\r\n",
				(DWORD)ctx->Eip, code[0], code[1], code[2], code[3],
				code[4], code[5], code[6], code[7]);
			if (len > 0)
				AppendLogLine("speed_boost_crash.txt", line, len);
		}

		// EBP-frame stack walk: the return addresses name the callers.
		DWORD ebp = (DWORD)ctx->Ebp;
		for (int i = 0; i < 8; i++)
		{
			if (IsBadReadPtr((const void*)ebp, 8))
				break;
			DWORD returnAddress = *(const DWORD*)(ebp + 4);
			DWORD previousEbp = *(const DWORD*)ebp;
			len = _snprintf_s(line, sizeof(line), _TRUNCATE,
				"frame%d ret=%08X\r\n", i, returnAddress);
			if (len > 0)
				AppendLogLine("speed_boost_crash.txt", line, len);
			if (previousEbp <= ebp)  // the chain must grow upward; stop on junk
				break;
			ebp = previousEbp;
		}

		// Raw stack dwords (fallback for frameless code).
		if (!IsBadReadPtr((const void*)ctx->Esp, 32))
		{
			const DWORD* stackWords = (const DWORD*)ctx->Esp;
			len = _snprintf_s(line, sizeof(line), _TRUNCATE,
				"stack: %08X %08X %08X %08X %08X %08X %08X %08X\r\n",
				stackWords[0], stackWords[1], stackWords[2], stackWords[3],
				stackWords[4], stackWords[5], stackWords[6], stackWords[7]);
			if (len > 0)
				AppendLogLine("speed_boost_crash.txt", line, len);
		}

		return EXCEPTION_CONTINUE_SEARCH;  // let normal crash handling proceed
	}

	// CRT assert / abort() deaths don't raise SEH exceptions - catch them too.
	void __cdecl AbortHandler(int)
	{
		static const char msg[] = "CRASH abort() (CRT assert or purecall)\r\n";
		AppendLogLine("speed_boost_crash.txt", msg, (int)(sizeof(msg) - 1));
	}

	void InstallCrashReporter()
	{
		static bool installed = false;
		if (installed)
			return;
		installed = true;
		SetUnhandledExceptionFilter(CrashFilter);
		signal(SIGABRT, AbortHandler);
	}

	int GetClientObject()
	{
		if (IsBadReadPtr((const void*)CLIENT_GLOBAL_ADDRESS, sizeof(int)))
			return 0;
		return *(int*)CLIENT_GLOBAL_ADDRESS;
	}

	// Crash tracer: appends one line per stage/event to speed_boost_trace.txt
	// (game working directory). The file handle is opened ONCE and kept for
	// the session - the v7b/v8 traces proved that re-opening per line lets
	// antivirus software swallow lines mid-run. Bounded volume: click,
	// first-pass stages, watch-window frame markers, and buff transitions
	// only - never per-frame spam. Raw Win32 file APIs only (no CRT fopen).
	HANDLE g_traceFile = NULL;
	bool g_traceFileTried = false;

	void Trace(const char* stage)
	{
		if (!g_traceEnabled)
			return;
		if (!g_traceFileTried)
		{
			g_traceFileTried = true;
			g_traceFile = CreateFileA("speed_boost_trace.txt", FILE_APPEND_DATA,
				FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS,
				FILE_ATTRIBUTE_NORMAL, NULL);
			if (g_traceFile == INVALID_HANDLE_VALUE)
				g_traceFile = NULL;
		}
		if (g_traceFile == NULL)
			return;

		char line[256];
		int len = _snprintf_s(line, sizeof(line), _TRUNCATE,
			"[%lu] %s | client=%08X role=%08X boostPct=%d active=%d detectOnly=%d scan=%ld\r\n",
			(unsigned long)GetTickCount(), stage,
			(unsigned int)GetClientObject(), (unsigned int)g_myRoleAddress,
			g_xpBoostPercent, g_xpBuffActive ? 1 : 0, g_xpBoostDetectOnly ? 1 : 0,
			(long)g_scanState);
		if (len <= 0)
			return;
		DWORD written = 0;
		WriteFile(g_traceFile, line, (DWORD)len, &written, NULL);
	}

	void GetClientIds(int client, unsigned int* idA, unsigned int* idB)
	{
		*idA = 0;
		*idB = 0;
		// One 8-byte read at +0x268 covers both id fields.
		if (client == 0 || IsBadReadPtr((const void*)(client + CLIENT_MY_ID_A_OFFSET), 8))
			return;
		*idA = *(unsigned int*)(client + CLIENT_MY_ID_A_OFFSET);
		*idB = *(unsigned int*)(client + CLIENT_MY_ID_B_OFFSET);
	}

	bool IsMyRoleWritable(uintptr_t role)
	{
		return role != 0 &&
			!IsBadReadPtr((const void*)(role + ROLE_SPEED_BOOST_OFFSET), 8) &&
			!IsBadWritePtr((void*)(role + ROLE_SPEED_BOOST_OFFSET), 8) &&
			!IsBadWritePtr((void*)(role + ROLE_SPEED_DELTA_OFFSET), 4);
	}

	// Writes the speed-boost fields on my role for the given percent
	// (100 = stock/zeroes). Runs every frame so a game-side rewrite can't
	// knock them off (same pattern as the VIP spoof).
	void WriteSpeedFields(uintptr_t role, int percent)
	{
		bool enabled = percent > MIN_SPEED_PERCENT;
		// Path 1 (uncapped): the final divisor in FUN_00de86b2.
		*(unsigned char*)(role + ROLE_SPEED_BOOST_FLAG) = enabled ? 1 : 0;
		*(int*)(role + ROLE_SPEED_BOOST_OFFSET) =
			enabled ? (percent - MIN_SPEED_PERCENT) * 100 : 0;
		// Path 2 (nSpeedPercent, move states): the role+0xc0 delta, capped by the
		// (raised) cap table. Never write <= -100: the "nSpeedPercent > 0" assert
		// in FUN_00deb537 would force a zero interval.
		*(int*)(role + ROLE_SPEED_DELTA_OFFSET) =
			enabled ? percent - MIN_SPEED_PERCENT : 0;
	}

	// The cap the role+0xc0 path needs given which features are enabled.
	// Detect-only mode never raises caps (it never writes).
	unsigned int NeededCap()
	{
		unsigned int needed = 0;
		if (g_speedEnabled && (unsigned int)g_speedPercent > needed)
			needed = (unsigned int)g_speedPercent;
		if (g_xpBoostEnabled && !g_xpBoostDetectOnly && (unsigned int)g_xpBoostPercent > needed)
			needed = (unsigned int)g_xpBoostPercent;
		return needed;
	}

	// Restores the per-state speed caps used by the role+0xc0 path.
	void RestoreSpeedCaps()
	{
		if (!g_capsRaised)
			return;
		unsigned int* caps = (unsigned int*)SPEED_CAP_TABLE;
		if (!IsBadWritePtr(caps, 13 * 4))
		{
			for (int i = 0; i < 13; i++)
				caps[i] = g_originalCaps[i];
		}
		g_capsRaised = false;
		g_raisedCapValue = 0;
	}

	// Raises the cap table to what the enabled features need (and keeps it in
	// sync when the sliders move). The table sits in read-only data, so
	// VirtualProtect it first. Originals are saved once, on the first raise.
	void SyncSpeedCaps()
	{
		unsigned int needed = NeededCap();
		if (needed == 0)
		{
			RestoreSpeedCaps();
			return;
		}
		if (g_capsRaised && g_raisedCapValue == needed)
			return;

		if (g_firstPassPending) Trace("caps: VirtualProtect");
		DWORD oldProtect = 0;
		if (!VirtualProtect((void*)SPEED_CAP_TABLE, 13 * 4, PAGE_READWRITE, &oldProtect))
			return;
		unsigned int* caps = (unsigned int*)SPEED_CAP_TABLE;
		if (!g_capsRaised)
		{
			for (int i = 0; i < 13; i++)
				g_originalCaps[i] = caps[i];
		}
		for (int i = 0; i < 13; i++)
			caps[i] = needed;
		g_capsRaised = true;
		g_raisedCapValue = needed;
		if (g_firstPassPending) Trace("caps: written");
	}

	// Pure-read equivalent of the game's status check
	//   FUN_00f1a1d8(client, statusId) -> FUN_00d4e0ae(client+0x138, statusId):
	// the status flags are a 64-bit bitmask array at client+0x138;
	// entry = (id >> 6), bit = (id & 0x3F), low word at +0, high word at +4.
	bool IsStatusActive(int client, unsigned int statusId)
	{
		if (client == 0)
			return false;
		if (IsBadReadPtr((const void*)(client + CLIENT_STATUS_FLAGS_OFFSET), STATUS_FLAGS_SPAN))
			return false;
		uintptr_t entry = client + CLIENT_STATUS_FLAGS_OFFSET + (statusId >> 6) * 8;
		unsigned int bit = statusId & 0x3F;
		if (bit < 32)
			return ((*(const unsigned int*)entry >> bit) & 1) != 0;
		return ((*(const unsigned int*)(entry + 4) >> (bit - 32)) & 1) != 0;
	}

	// True while any XP-skill buff (Superman / Fatal Strike / ...) is running.
	bool IsXpSkillActive(int client)
	{
		for (int i = 0; i < _countof(XP_STATUS_IDS); i++)
		{
			if (IsStatusActive(client, XP_STATUS_IDS[i]))
				return true;
		}
		return false;
	}

	// Candidate class check: the vtable must point into the exe image, the action
	// state must be in range, and the vtable must contain one of the interval
	// functions - only role classes carry them. (Vtables hold code addresses;
	// the server's E9 hook patches code bytes, not vtable entries, so this
	// check works whether the hook is present or not.)
	bool LooksLikeRoleObject(uintptr_t base)
	{
		uintptr_t vtable = *(uintptr_t*)base;
		if (vtable < IMAGE_BASE || vtable >= IMAGE_TOP)
			return false;
		if (*(unsigned int*)(base + ROLE_ACTION_STATE) >= 13)
			return false;
		if (IsBadReadPtr((const void*)vtable, 64 * 4))
			return false;
		const uintptr_t* entry = (const uintptr_t*)vtable;
		for (int i = 0; i < 64; i++)
		{
			if (entry[i] == ACTION_INTERVAL_FUNC || entry[i] == ACTION_INTERVAL_CORE)
			{
				g_vtableHasIntervalFn = 1;
				return true;
			}
		}
		return false;
	}

	// Background scan: walk committed writable regions looking for the role
	// whose +0x268 dword equals my entity id. Same VirtualQuery pattern as the
	// memory scanner, but targeted at one dword so it's quick. The body runs
	// under an SEH guard so a bad region can never take the client down.
	void ScanBody()
	{
		unsigned int idA = 0, idB = 0;
		GetClientIds(GetClientObject(), &idA, &idB);
		if (idA == 0 && idB == 0)
		{
			g_scanState = 2;
			return;
		}

		uintptr_t address = 0x10000;
		while (address < 0x7FFE0000 && g_scanState == 1)
		{
			MEMORY_BASIC_INFORMATION mbi;
			if (VirtualQuery((const void*)address, &mbi, sizeof(mbi)) != sizeof(mbi))
				break;

			const DWORD readWrite = PAGE_READWRITE | PAGE_WRITECOPY |
			PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
			bool readable = (mbi.State == MEM_COMMIT) && (mbi.Protect & readWrite) != 0 &&
				(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) == 0;

			uintptr_t start = (uintptr_t)mbi.BaseAddress;
			uintptr_t end = start + mbi.RegionSize;

			if (readable)
			{
				// The whole object span (base .. base+0x26C) must stay in-region.
				for (uintptr_t p = start; p + ROLE_ID_B_OFFSET + 4 <= end; p += 4)
				{
					int rule = 0;
					if (idA != 0 && *(unsigned int*)(p + ROLE_ID_A_OFFSET) == idA)
						rule = 1;  // the game's own my-role match (FUN_00d3203a)
					else if (idB != 0 && *(unsigned int*)(p + ROLE_ID_B_OFFSET) == idB)
						rule = 2;
					else if (idA != 0 && *(unsigned int*)(p + ROLE_ID_B_OFFSET) == idA)
						rule = 3;  // cross-variant safety net

					if (rule == 0)
						continue;
					g_scanIdMatches++;  // id hit before the strict checks
					if (!LooksLikeRoleObject(p))
						continue;
					g_matchedRule = rule;
					g_myRoleAddress = p;
					g_scanState = 2;
					Trace("scan: role found");
					return;
				}
			}
			address = end;
		}
		g_scanState = 2;  // done (not found)
		Trace("scan: finished, no role");
	}

	DWORD WINAPI FindMyRoleThread(LPVOID)
	{
		__try
		{
			ScanBody();
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			g_scanState = 2;  // scan died on a bad region - just give up
			Trace("scan: EXCEPTION caught");
		}
		return 0;
	}

	void StartRoleScan()
	{
		if (g_scanState == 1)
			return;
		g_myRoleAddress = 0;
		g_scanState = 1;
		g_scanIdMatches = 0;
		g_matchedRule = 0;
		g_vtableHasIntervalFn = 0;
		g_lastScanTick = GetTickCount();
		CreateThread(NULL, 0, FindMyRoleThread, NULL, 0, NULL);
	}

	// Click handlers only flip the flag - every real action (cap table, role
	// scan, field writes) happens in the SEH-guarded per-frame tick, so
	// clicking a checkbox can never crash the client.
	void SetSpeedEnabled(bool enabled)
	{
		g_speedEnabled = enabled;
	}

	void SetXpBoostEnabled(bool enabled)
	{
		g_xpBoostEnabled = enabled;
		if (enabled)
		{
			g_firstPassPending = true;  // trace the first tick's stages
			g_renderLogged = false;     // and the first boost-section render
			g_watchFrames = 3;          // fine-grained frame markers for 3 frames
			Trace("click: boost ENABLED");
		}
		else
		{
			g_xpBuffActive = false;
			Trace("click: boost disabled");
		}
	}

	// Runs every frame (even with the menu closed), like auto-hunt's pass.
	void ApplyClientSideState()
	{
		InstallCrashReporter();  // first call only; catches crashes process-wide

		// EVERYTHING runs under an SEH guard: a stale client/role/global pointer
		// turns into a skipped frame instead of a crashed client. (The loot-tick
		// block moved inside the guard in v8 - it was the only unguarded part.)
		__try
		{
			if (g_watchFrames > 0) Trace("tick: entered");

			if (g_fastLootTick)
			{
				// Rate-limited re-arm of the brain's 1000 ms tick gate. Zeroing the
				// timestamp EVERY frame made the brain tick at frame rate (~30-60
				// loot/attack orders per second) - the server's packet rate limit
				// disconnected the character. Instead, only re-arm once the chosen
				// interval has passed since the brain's last real tick.
				// NOTE: the brain compares DAT_01a5cdb4 against timeGetTime();
				// GetTickCount shares the same millisecond time base.
				if (!IsBadReadPtr((const void*)HUNT_BRAIN_TICK_GLOBAL, sizeof(unsigned long)) &&
					!IsBadWritePtr((void*)HUNT_BRAIN_TICK_GLOBAL, sizeof(unsigned long)))
				{
					unsigned long lastTick = *(unsigned long*)HUNT_BRAIN_TICK_GLOBAL;
					unsigned long now = GetTickCount();
					if (now - lastTick >= (unsigned long)g_lootTickIntervalMs)
						*(unsigned long*)HUNT_BRAIN_TICK_GLOBAL = now - 1000;  // make the gate pass
				}
			}

			bool wantSpeed = g_speedEnabled || g_xpBoostEnabled;

			if (wantSpeed)
			{
				if (g_firstPassPending) Trace("tick: begin");
				DWORD now = GetTickCount();

				// Automation of the proven manual swap: the boost slider's value
				// is fed in while an XP skill buff runs - but only AFTER a short
				// settle delay, exactly like the user's manual timing (never in
				// the XP skill's cast frame). The moment the buff ends the base
				// slider (or stock 100%) takes over again instantly.
				int percent = MIN_SPEED_PERCENT;
				if (g_xpBoostEnabled)
				{
					int client = GetClientObject();
					bool active = false;
					if (client != 0)
					{
						// Only poll once fully in the game world (ids are 0 at login).
						unsigned int idA = 0, idB = 0;
						GetClientIds(client, &idA, &idB);
						if (idA != 0 || idB != 0)
						{
							if (g_firstPassPending) Trace("poll: reading status flags");
							active = IsXpSkillActive(client);
							if (g_firstPassPending) Trace("poll: done");
						}
						else if (g_firstPassPending) Trace("poll: skipped (not in world)");
					}
					else if (g_firstPassPending) Trace("poll: skipped (no client)");

					if (active != g_prevBuffActive)
					{
						Trace(active ? "buff: ON (settle delay armed)" : "buff: OFF");
						if (active)
							g_buffActivatedTick = now;
						g_prevBuffActive = active;
					}
					g_xpBuffActive = active;

					// Apply only after the settle delay - never in the cast frame.
					if (active && !g_xpBoostDetectOnly &&
						now - g_buffActivatedTick >= BOOST_APPLY_DELAY_MS)
					{
						percent = g_xpBoostPercent;
					}
				}
				if (percent == MIN_SPEED_PERCENT && g_speedEnabled)
					percent = g_speedPercent;

				SyncSpeedCaps();  // cheap no-op unless a slider changed

				uintptr_t role = g_myRoleAddress;
				if (IsMyRoleWritable(role))
				{
					if (g_firstPassPending) Trace("write: speed fields");
					WriteSpeedFields(role, percent);
					if (g_firstPassPending) Trace("write: done");
				}
				else if (g_myRoleAddress != 0)
				{
					// Role object went away (relog, map change) - drop it + rescan.
					g_myRoleAddress = 0;
				}
				else if (g_scanState != 1 && GetTickCount() - g_lastScanTick > 3000)
				{
					if (g_firstPassPending) Trace("scan: starting");
					StartRoleScan();  // throttled to one scan every few seconds
				}
				if (g_firstPassPending)
				{
					Trace("tick: first pass complete");
					g_firstPassPending = false;
				}
			}
			else if (g_anySpeedWasOn)
			{
				// Both features just turned off: restore stock once.
				if (IsMyRoleWritable(g_myRoleAddress))
					WriteSpeedFields(g_myRoleAddress, MIN_SPEED_PERCENT);
				RestoreSpeedCaps();
			}
			g_anySpeedWasOn = wantSpeed;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			// Never let a speed-feature hiccup kill the game client - and if it
			// tries, the trace file records that we even got an exception here.
			Trace("tick: EXCEPTION caught");
			g_firstPassPending = false;
		}

		if (g_watchFrames > 0)
			g_watchFrames--;
	}

	// Info line: shows what the live client currently has at the interval
	// function (E9 .. means something else hooked it - expected on this client).
	void GetTargetBytesHex(char* outBuffer, int maxBytes)
	{
		static const char* hexDigits = "0123456789ABCDEF";
		const unsigned char* code = (const unsigned char*)ACTION_INTERVAL_FUNC;
		int pos = 0;
		for (int i = 0; i < maxBytes; i++)
		{
			bool readable = !IsBadReadPtr(code + i, 1);
			unsigned char byteValue = readable ? code[i] : (unsigned char)0;
			if (i > 0)
				outBuffer[pos++] = ' ';
			outBuffer[pos++] = readable ? hexDigits[byteValue >> 4] : '?';
			outBuffer[pos++] = readable ? hexDigits[byteValue & 15] : '?';
		}
		outBuffer[pos] = 0;
	}
}

// Free wrappers so imgui_interface.cpp can drive the feature.
void ApplySpeedClientState()
{
	Speed::ApplyClientSideState();
}

// Called from imgui_interface.cpp between the per-frame feature ticks so the
// trace names which tick a crash happened in. Only writes during the short
// watch window right after the boost is enabled (bounded volume).
void SpeedTrace(const char* stage)
{
	if (Speed::g_watchFrames > 0)
		Speed::Trace(stage);
}

void RenderSpeedInterface()
{
	ImGui::Text("Speed Control");
	ImGui::TextDisabled("build %s", Speed::BUILD_TAG);  // verify the running DLL from a screenshot
	ImGui::Separator();

	int client = Speed::GetClientObject();
	unsigned int idA = 0, idB = 0;
	Speed::GetClientIds(client, &idA, &idB);

	bool enabled = Speed::g_speedEnabled;
	if (ImGui::Checkbox("Enable speed control (move + attack)", &enabled))
		Speed::SetSpeedEnabled(enabled);

	// The ids are only populated once the character is in the game world.
	if (client == 0)
		ImGui::TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), "Client object not found - game still loading?");
	else if (idA == 0 && idB == 0)
		ImGui::TextColored(ImVec4(1.0f, 0.7f, 0.3f, 1.0f), "Enter the game world first - ids are 0 at login");

	if (Speed::g_speedEnabled)
	{
		ImGui::SliderInt("Action speed %", &Speed::g_speedPercent, Speed::MIN_SPEED_PERCENT, Speed::MAX_SPEED_PERCENT);
		ImGui::TextDisabled("100 = normal, 200 = 2x. 500 is the validated stable ceiling;");
		ImGui::TextDisabled("above that is test territory (rubber-banding / instability).");
	}

	ImGui::Spacing();

	// XP boost: the manual 100% <-> high% slider swap, automated, with the same
	// human timing (a short settle delay after the buff lands).
	bool xpBoost = Speed::g_xpBoostEnabled;
	if (ImGui::Checkbox("XP skill speed boost", &xpBoost))
		Speed::SetXpBoostEnabled(xpBoost);

	if (Speed::g_xpBoostEnabled)
	{
		// Stage markers on the FIRST render of the section: if the crash log
		// stops between two of these, the crashing widget sits between them.
		bool logStages = !Speed::g_renderLogged;

		ImGui::Checkbox("Detect only (safe test - no speed change)", &Speed::g_xpBoostDetectOnly);
		if (Speed::g_xpBoostDetectOnly)
			ImGui::TextDisabled("Detect-only is ON: watches the buff, changes NOTHING.");
		ImGui::Checkbox("Trace to file (speed_boost_trace.txt)", &Speed::g_traceEnabled);
		if (logStages) Speed::Trace("render: checkboxes ok");

		ImGui::SliderInt("XP boost speed %", &Speed::g_xpBoostPercent,
			Speed::MIN_XP_BOOST_PERCENT, Speed::MAX_XP_BOOST_PERCENT);
		if (logStages) Speed::Trace("render: slider ok");

		if (Speed::g_xpBuffActive)
		{
			if (Speed::g_xpBoostDetectOnly)
				ImGui::TextColored(ImVec4(0.3f, 1.0f, 0.3f, 1.0f), "XP buff ACTIVE (detect-only: no speed change)");
			else if (GetTickCount() - Speed::g_buffActivatedTick < Speed::BOOST_APPLY_DELAY_MS)
				ImGui::TextColored(ImVec4(1.0f, 0.85f, 0.3f, 1.0f), "XP buff ACTIVE - applying in a moment...");
			else
				ImGui::TextColored(ImVec4(0.3f, 1.0f, 0.3f, 1.0f), "XP buff ACTIVE - boosting");
		}
		else
		{
			ImGui::TextDisabled("XP buff inactive - normal speed");
		}
		ImGui::TextDisabled("Applies ~0.4s after the buff lands (like your manual timing) and");
		ImGui::TextDisabled("snaps back to 100% the instant the buff ends - no disconnect.");
		ImGui::TextDisabled("Start at 500 or less - very high values can be unstable.");

		if (logStages)
		{
			Speed::Trace("render: section complete");
			Speed::g_renderLogged = true;
		}
	}

	if ((Speed::g_speedEnabled || Speed::g_xpBoostEnabled) && Speed::g_myRoleAddress == 0)
	{
		if (Speed::g_scanState == 1)
			ImGui::TextDisabled("Locating my role...");
		else
		{
			ImGui::TextColored(ImVec4(1.0f, 0.7f, 0.3f, 1.0f), "My role not found yet");
			if (ImGui::Button("Rescan"))
				Speed::StartRoleScan();
		}
	}

	ImGui::Checkbox("Fast auto-hunt/loot tick", &Speed::g_fastLootTick);
	if (Speed::g_fastLootTick)
	{
		ImGui::SliderInt("Loot tick interval (ms)", &Speed::g_lootTickIntervalMs,
			Speed::MIN_LOOT_TICK_INTERVAL_MS, Speed::MAX_LOOT_TICK_INTERVAL_MS);
		ImGui::TextDisabled("Lower = faster looting. Frame-rate ticking gets you DISCONNECTED.");
		ImGui::TextDisabled("If the server still kicks you, raise the interval.");
	}

	if (ImGui::TreeNode("Speed Debug"))
	{
		ImGui::Text("Client: 0x%08X", (unsigned int)client);
		ImGui::Text("Client id A (client+0x268): %u", idA);
		ImGui::Text("Client id B (client+0x26c): %u", idB);
		ImGui::Text("My role: 0x%08X", (unsigned int)Speed::g_myRoleAddress);
		ImGui::Text("Scan state: %s", Speed::g_scanState == 1 ? "scanning" :
			(Speed::g_scanState == 2 ? "done" : "idle"));
		ImGui::Text("Id matches last scan: %u", Speed::g_scanIdMatches);
		ImGui::Text("Matched rule: %d (1=A 2=B 3=cross)", Speed::g_matchedRule);
		ImGui::Text("XP buff active: %s", Speed::g_xpBuffActive ? "yes" : "no");
		if (Speed::g_myRoleAddress != 0 &&
			!IsBadReadPtr((const void*)Speed::g_myRoleAddress, 4) &&
			!IsBadReadPtr((const void*)(Speed::g_myRoleAddress + Speed::ROLE_SPEED_DELTA_OFFSET), 4))
		{
			ImGui::Text("role+0x44: %d  role+0x48: %u  role+0xc0: %d",
				*(int*)(Speed::g_myRoleAddress + Speed::ROLE_SPEED_BOOST_OFFSET),
				(unsigned int)*(unsigned char*)(Speed::g_myRoleAddress + Speed::ROLE_SPEED_BOOST_FLAG),
				*(int*)(Speed::g_myRoleAddress + Speed::ROLE_SPEED_DELTA_OFFSET));
			ImGui::Text("vtable: 0x%08X (interval fn: %s)",
				(unsigned int)*(uintptr_t*)Speed::g_myRoleAddress,
				Speed::g_vtableHasIntervalFn ? "yes" : "no");
		}
		ImGui::Text("Speed caps: %s (value %u)", Speed::g_capsRaised ? "raised" : "stock",
			Speed::g_raisedCapValue);
		char bytesText[64];
		Speed::GetTargetBytesHex(bytesText, 16);
		ImGui::TextDisabled("Interval fn @0x010AFD05: %s", bytesText);
		char traceDir[MAX_PATH];
		if (GetCurrentDirectoryA(MAX_PATH, traceDir) != 0)
			ImGui::TextDisabled("Trace file: %s\\speed_boost_trace.txt", traceDir);
		ImGui::TreePop();
	}
}
