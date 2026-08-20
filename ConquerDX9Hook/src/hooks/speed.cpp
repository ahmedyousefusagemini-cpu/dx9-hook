#include <windows.h>
#include <stdint.h>
#include "imgui.h"

// Buff 250 (Celestial Dance) status tracking, provided by buffs.cpp. These run
// every frame (PollBuffs) even with the overlay menu closed.
extern bool IsStatusActive(int statusId);
extern unsigned long GetStatusEndMs(int statusId);

// Auto-hunt state (defined in auto_hunt.cpp).
extern bool IsAutoHuntHunting();
extern bool IsAutoHuntInCombat();
extern bool IsAutoHuntMonsterNear();
extern void ClearAutoHuntTarget();

// ============================================================================
// Speed Control (CRole action speed fields) - Conquer.exe client 7937 (0x400000)
// ----------------------------------------------------------------------------
// IMPORTANT LIVE FINDING (2026-08-10): in the running game, the per-role
// action-interval virtual FUN_010b0a9a is ALREADY hooked - its first 5 bytes
// are overwritten with an E9 (JMP to a dynamically allocated trampoline
// page). Something (server anti-cheat / launcher patch) watches the classic
// speed-hack spot, so this module uses NO code hooks at all and drives speed
// through the role's own speed fields instead:
//
// Inside the master interval computation FUN_00de93e2 (3drole\role.cpp), the
// final scaling for the role's current action (walk / attack / pickup) is:
//   interval = ceil(interval * 100 / (100 + role+0x44/100))   when role+0x48 != 0
// role+0x44 is in 1/100-percent units: 10000 -> divisor 200 -> 2x speed.
// This path has NO per-state cap (that cap table only gates role+0xc0).
//
// My-role discovery without hooks: the scan matches the client id fields
// against the role's id fields (two placements seen in the wild - this server
// leaves client+0x26c = 0 and uses client+0x268), then VALIDATES the
// candidate's class: its vtable must contain one of the interval functions
// (FUN_010b0a9a / FUN_00de93e2 - only role classes have them), so a random
// object carrying the same id can't win the scan.
//
// Looting speed: the hunt brain (FUN_00f54df8) only ticks when
// timeGetTime() >= DAT_01a5dde4 + 1000. Only the brain reads or writes that
// global (verified by xrefs), so forcing it to 0 lets the brain issue
// find/attack/loot orders early. Resetting it EVERY frame made loot orders
// go out at frame rate and the server disconnected the client, so the reset
// is now throttled to a user interval (slider, 50-1000 ms, default 50 ms =>
// ~20 ticks/sec).
//
// Safety: only data writes, nothing patched. The game's interval math clamps
// divisors to >= 1 and the final interval to >= 1. All speed-up is
// client-side: the server may rubber-band movement or drop loot requests at
// extreme values, so the manual slider tops out at 500%. The separate "Auto
// Movement Speed" feature (below) can go up to 3000%, but only while the
// Celestial Dance buff (status 250) is active with > 2s remaining.
//
// Cancel Attack Animation (2026-08-20): the same +0x44 divisor scales the
// ATTACK action's interval too (the master interval computation FUN_00de93e2
// applies the final scaling to every action when role+0x48 != 0). So while
// the hunt brain is attacking a monster in range (mgr+4 != 0), an extreme
// boost collapses the attack interval to ~1 tick: the attack animation is
// effectively skipped and the next attack packet (CMsgAction, sent by
// FUN_00f67675 from the brain's FUN_0112112c call) fires at the brain-tick
// rate (fast-loot tick, default 50 ms). Walking between targets is NOT
// boosted - the boost is only written while mgr+4 holds a small tile value
// (attack X; the brain writes a loot pointer there while looting, which is
// excluded), and a stale mgr+4 left behind after a kill is cleared via the
// brain's own finder.
//
// Two write paths feed the interval math every frame (same assert pattern as
// the VIP spoof):  role+0x48=1 & role+0x44=(percent-100)*100  (the uncapped
// final divisor)  and  role+0xc0=percent-100  (the nSpeedPercent path in
// FUN_00dec267, which IS capped per action-state by the 13-dword table at
// 0x016F8E84 - so while enabled we raise that table to 500; it only affects
// entities with a positive +0xc0, i.e. just us).
// ============================================================================

namespace Speed
{
	const uintptr_t CLIENT_GLOBAL_ADDRESS  = 0x01A53980;  // DAT_01a53980 - client object*
	const uintptr_t HUNT_BRAIN_TICK_GLOBAL = 0x01A5DDE4;  // DAT_01a5dde4 - last brain tick (timeGetTime)
	const uintptr_t ACTION_INTERVAL_FUNC   = 0x010B0A9A;  // FUN_010b0a9a - interval virtual (vtable check)
	const uintptr_t ACTION_INTERVAL_CORE   = 0x00DE93E2;  // FUN_00de93e2 - master computation (vtable check)
	const uintptr_t SPEED_CAP_TABLE        = 0x016F8E84;  // per-state nSpeedPercent caps (13 dwords)

	// Two id placements seen in the wild (this server leaves client+0x26c = 0):
	//  A: client+0x268 <-> role+0x54   (the game's own my-role match:
	//     "skip candidate unless role+0x54 == client+0x268")
	//  B: client+0x26c <-> role+0x268  (the id getter / msg filter)
	const size_t CLIENT_MY_ID_A_OFFSET = 0x268;  // client+0x268: my id (variant A)
	const size_t CLIENT_MY_ID_B_OFFSET = 0x26c;  // client+0x26c: my id (variant B)
	const size_t ROLE_ID_A_OFFSET      = 0x54;   // role+0x54: entity id (variant A)
	const size_t ROLE_ID_B_OFFSET      = 0x268;  // role+0x268: entity id (variant B)
	const size_t ROLE_ACTION_STATE       = 0xb4;   // role+0xb4: action state dword (< 13)
	const size_t ROLE_SPEED_BOOST_OFFSET = 0x44;   // role+0x44: boost in 1/100 % (needs +0x48)
	const size_t ROLE_SPEED_BOOST_FLAG   = 0x48;   // role+0x48: byte, enables the +0x44 divisor
	const size_t ROLE_SPEED_DELTA_OFFSET = 0xc0;   // role+0xc0: nSpeedPercent delta (FUN_00dec267)

	const int MIN_SPEED_PERCENT = 100;   // 100% = normal speed
	const int MAX_SPEED_PERCENT = 500;   // manual slider max (server rubber-bands beyond)
	const int AUTO_MIN_SPEED_PERCENT = 100;   // auto move-speed slider min
	const int AUTO_MAX_SPEED_PERCENT = 3000;  // auto move-speed slider max

	// Attack-only boost (animation cancel). The attack interval is
	// ceil(base * 100 / (100 + boost/100)); boost = 13,000,000 collapses a
	// ~1300 ms attack to 1 tick. Only written while the brain is in combat,
	// so movement keeps the manual slider speed.
	const int ATTACK_MIN_SPEED_PERCENT = 100;
	const int ATTACK_MAX_SPEED_PERCENT = 20000000;
	const int ATTACK_DEFAULT_SPEED_PERCENT = 13000000;

	const uintptr_t IMAGE_BASE = 0x00400000;   // Conquer.exe image base
	const uintptr_t IMAGE_TOP  = 0x02000000;   // vtable sanity range upper bound

	// User settings.
	bool g_speedEnabled = false;
	int  g_speedPercent = 200;          // default 2x
	bool g_fastLootTick = false;        // force the brain tick gate open
	int  g_fastLootIntervalMs = 50;     // min delay between forced ticks (slider)
	unsigned long g_lastFastLootReset = 0;  // GetTickCount() of last forced reset

	// Auto Movement Speed (buff 250 Celestial Dance gated).
	bool g_autoMoveSpeedEnabled = false;
	int  g_autoMovePercent = 500;       // initial value 500%, adjustable 100..3000

	// Cancel Attack Animation (combat-only extreme boost, auto-hunt gated).
	bool g_attackSpeedEnabled = false;
	int  g_attackSpeedPercent = ATTACK_DEFAULT_SPEED_PERCENT;
	unsigned long g_lastAttackStateCheck = 0;  // rate limit for the mgr+4 cleanup

	// Always-on buff-250 tracker (updated every frame even with the menu closed).
	bool         g_buff250Active = false;      // bit 250 set right now
	bool         g_buff250JustStarted = false; // rising edge (0 -> 1) this frame
	unsigned long g_buff250RemainingMs = 0;    // ms left (0 = inactive/unknown/expired)
	bool         g_buff250Expiring = false;    // active & <= 2000 ms remaining
	bool         g_autoBoostActive = false;    // actually writing the boost right now

	// My-role cache + scan state (written by the scan thread, read per-frame).
	volatile uintptr_t g_myRoleAddress = 0;
	volatile long g_scanState = 0;      // 0 idle, 1 scanning, 2 done
	volatile unsigned long g_lastScanTick = 0;
	volatile unsigned int g_scanIdMatches = 0;  // id hits before strict checks
	volatile int g_matchedRule = 0;             // which id rule hit (0 none, 1 A, 2 B, 3 cross)
	volatile int g_vtableHasIntervalFn = 0;     // candidate's vtable passed the class check
	unsigned int g_originalCaps[13] = {0};      // saved SPEED_CAP_TABLE contents
	bool g_capsRaised = false;
	int  g_capsTarget = 0;                      // % the cap table is currently raised to

	int GetClientObject()
	{
		if (IsBadReadPtr((const void*)CLIENT_GLOBAL_ADDRESS, sizeof(int)))
			return 0;
		return *(int*)CLIENT_GLOBAL_ADDRESS;
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

	// Writes (or clears) the speed-boost fields on my role. Runs every frame so
	// a game-side rewrite can't knock them off (same pattern as the VIP spoof).
	// percent is the target percentage (100 = normal / no boost); enabled=false
	// clears all fields back to stock.
	void WriteSpeedFields(uintptr_t role, bool enabled, int percent)
	{
		// Path 1 (uncapped): the final divisor in FUN_00de86b2.
		*(unsigned char*)(role + ROLE_SPEED_BOOST_FLAG) = enabled ? 1 : 0;
		*(int*)(role + ROLE_SPEED_BOOST_OFFSET) =
			enabled ? (percent - MIN_SPEED_PERCENT) * 100 : 0;
		// Path 2 (nSpeedPercent, move states): the role+0xc0 delta, capped by the
		// (raised) cap table. Never write <= -100: the "nSpeedPercent > 0" assert
		// in FUN_00dec267 would force a zero interval.
		*(int*)(role + ROLE_SPEED_DELTA_OFFSET) =
			enabled ? percent - MIN_SPEED_PERCENT : 0;
	}

	// (forward decl - RestoreSpeedCaps is defined below SetSpeedCapsTo)
	void RestoreSpeedCaps();

	// Raises the per-state speed caps (used by the role+0xc0 path) to at least
	// the given percent, or restores the originals when targetPercent <= 100.
	// The table sits in read-only data, so VirtualProtect it first. Only grows
	// the table (never shrinks while still raised) to avoid repeated protects.
	void SetSpeedCapsTo(int targetPercent)
	{
		if (targetPercent <= MIN_SPEED_PERCENT)
		{
			if (g_capsRaised)
				RestoreSpeedCaps();
			return;
		}
		if (g_capsRaised && g_capsTarget >= targetPercent)
			return;

		DWORD oldProtect = 0;
		if (!VirtualProtect((void*)SPEED_CAP_TABLE, 13 * 4, PAGE_READWRITE, &oldProtect))
			return;

		if (!g_capsRaised)
		{
			unsigned int* caps = (unsigned int*)SPEED_CAP_TABLE;
			for (int i = 0; i < 13; i++)
				g_originalCaps[i] = caps[i];
		}
		unsigned int* caps = (unsigned int*)SPEED_CAP_TABLE;
		for (int i = 0; i < 13; i++)
			caps[i] = (unsigned int)targetPercent;
		g_capsTarget = targetPercent;
		g_capsRaised = true;
	}

	// Reconciles the cap table to the max % any currently-enabled feature may
	// write (manual slider, auto move-speed, or attack boost), restored when
	// none is enabled.
	void UpdateSpeedCaps()
	{
		int target = MIN_SPEED_PERCENT;
		if (g_speedEnabled && g_speedPercent > target)
			target = g_speedPercent;
		if (g_autoMoveSpeedEnabled && g_autoMovePercent > target)
			target = g_autoMovePercent;
		if (g_attackSpeedEnabled && g_attackSpeedPercent > target)
			target = g_attackSpeedPercent;
		SetSpeedCapsTo(target);
	}

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
		g_capsTarget = 0;
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
	// memory scanner, but targeted at one dword so it's quick.
	DWORD WINAPI FindMyRoleThread(LPVOID)
	{
		unsigned int idA = 0, idB = 0;
		GetClientIds(GetClientObject(), &idA, &idB);
		if (idA == 0 && idB == 0)
		{
			g_scanState = 2;
			return 0;
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
					return 0;
				}
			}
			address = end;
		}
		g_scanState = 2;  // done (not found)
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

	void SetSpeedEnabled(bool enabled)
	{
		if (!enabled && IsMyRoleWritable(g_myRoleAddress))
			WriteSpeedFields(g_myRoleAddress, false, MIN_SPEED_PERCENT);  // restore stock behavior

		g_speedEnabled = enabled;
		UpdateSpeedCaps();

		if (enabled && g_myRoleAddress == 0)
			StartRoleScan();
	}

	void SetAutoMoveSpeedEnabled(bool enabled)
	{
		if (!enabled && IsMyRoleWritable(g_myRoleAddress))
			WriteSpeedFields(g_myRoleAddress, false, MIN_SPEED_PERCENT);  // restore stock behavior

		g_autoMoveSpeedEnabled = enabled;
		UpdateSpeedCaps();

		if (enabled && g_myRoleAddress == 0)
			StartRoleScan();
	}

	void SetAttackSpeedEnabled(bool enabled)
	{
		if (!enabled && IsMyRoleWritable(g_myRoleAddress))
			WriteSpeedFields(g_myRoleAddress, false, MIN_SPEED_PERCENT);  // restore stock behavior

		g_attackSpeedEnabled = enabled;
		UpdateSpeedCaps();

		if (enabled && g_myRoleAddress == 0)
			StartRoleScan();
	}

	// Always-on buff-250 (Celestial Dance) tracker. Runs every frame even with
	// the menu closed so the boost engages on the buff's rising edge and drops
	// back to 100% the moment <= 2s remain.
	void TrackBuff250State()
	{
		bool active = ::IsStatusActive(250);
		unsigned long end = ::GetStatusEndMs(250);
		unsigned long now = GetTickCount();

		g_buff250JustStarted = active && !g_buff250Active;   // rising edge 0 -> 1
		g_buff250Active      = active;
		g_buff250RemainingMs = (active && end != 0 && now < end) ? (end - now) : 0;
		g_buff250Expiring    = active && g_buff250RemainingMs != 0 && g_buff250RemainingMs <= 2000UL;
		g_autoBoostActive    = g_autoMoveSpeedEnabled && active && !g_buff250Expiring;
	}

	// Runs every frame (even with the menu closed), like auto-hunt's pass.
	void ApplyClientSideState()
	{
		if (g_fastLootTick)
		{
			// Throttled: resetting the gate every frame made the brain spam loot
			// orders at frame rate and the server disconnected us. Only reset it
			// once per user-chosen interval instead.
			unsigned long now = GetTickCount();
			if (now - g_lastFastLootReset >= (unsigned long)g_fastLootIntervalMs)
			{
				// Force the brain's last-tick timestamp to 0 so its 1000 ms gate
				// passes on the brain's next check. Only FUN_00f54058 reads/writes
				// this global.
				if (!IsBadWritePtr((void*)HUNT_BRAIN_TICK_GLOBAL, sizeof(unsigned long)))
				{
					*(unsigned long*)HUNT_BRAIN_TICK_GLOBAL = 0;
					g_lastFastLootReset = now;
				}
			}
		}
		else
		{
			g_lastFastLootReset = 0;  // re-arm: next enable ticks immediately
		}

		// Always-on buff-250 (Celestial Dance) tracker - updated every frame.
		TrackBuff250State();

		// Decide the boost to write this frame. Cancel Attack Animation takes
		// precedence: while the hunt brain is attacking a monster in range
		// (mgr+4 != 0), write an extreme boost so the attack action's interval
		// collapses to ~1 tick (animation effectively skipped; the next attack
		// fires at the brain-tick rate). Otherwise the Auto Movement Speed
		// feature (if checked) drives the fields and takes precedence over the
		// manual slider; it only boosts while buff 250 is active with > 2s
		// remaining, otherwise it writes 100% (normal) so the character
		// returns to stock speed on buff expiry / the final 2 seconds.
		bool combatBoost = false;
		if (g_attackSpeedEnabled)
		{
			if (IsAutoHuntHunting() && IsAutoHuntInCombat())
			{
				combatBoost = true;
			}
			else
			{
				// Kill a stale mgr+4 (the brain leaves the last attack X
				// behind after a kill) so the combat signal doesn't stick on
				// during idle walks. Rate-limited: the finder runs at most
				// ~10x/sec from here.
				unsigned long now = GetTickCount();
				if (now - g_lastAttackStateCheck >= 100)
				{
					g_lastAttackStateCheck = now;
					if (!IsAutoHuntMonsterNear())
						ClearAutoHuntTarget();
				}
			}
		}

		bool wantBoost = false;
		int  boostPercent = MIN_SPEED_PERCENT;
		if (combatBoost)
		{
			wantBoost = true;
			boostPercent = g_attackSpeedPercent;
		}
		else if (g_autoMoveSpeedEnabled)
		{
			wantBoost = g_buff250Active && !g_buff250Expiring;
			boostPercent = g_autoMovePercent;
		}
		else if (g_speedEnabled)
		{
			wantBoost = true;
			boostPercent = g_speedPercent;
		}

		// Keep the per-state cap table high enough for the max % any enabled
		// feature may write (attack can go up to 20,000,000).
		UpdateSpeedCaps();

		if (wantBoost || g_speedEnabled || g_autoMoveSpeedEnabled || g_attackSpeedEnabled)
		{
			uintptr_t role = g_myRoleAddress;
			if (IsMyRoleWritable(role))
			{
				WriteSpeedFields(role, wantBoost, boostPercent);
			}
			else if (g_myRoleAddress != 0)
			{
				// Role object went away (relog, map change) - drop it and rescan,
				// throttled to one scan every few seconds.
				g_myRoleAddress = 0;
			}
			else if (g_scanState == 2 && GetTickCount() - g_lastScanTick > 3000)
			{
				StartRoleScan();
			}
		}
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

void RenderSpeedInterface()
{
	ImGui::Text("Speed Control");
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
		ImGui::TextDisabled("100 = normal, 200 = 2x. Too high may rubber-band (server check).");

		if (Speed::g_myRoleAddress == 0)
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
	}

	// ------------------------------------------------------------------
	// Auto Movement Speed (buff 250 Celestial Dance gated)
	// ------------------------------------------------------------------
	if (ImGui::Checkbox("Auto Movement Speed", &Speed::g_autoMoveSpeedEnabled))
		Speed::SetAutoMoveSpeedEnabled(Speed::g_autoMoveSpeedEnabled);
	ImGui::SameLine();
	if (Speed::g_autoMoveSpeedEnabled)
		ImGui::TextColored(ImVec4(0.3f, 1.0f, 0.3f, 1.0f), "ACTIVATED");
	else
		ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "NOT ACTIVATED");

	if (Speed::g_autoMoveSpeedEnabled)
	{
		ImGui::SliderInt("Speed when Celestial Dance (id 250)", &Speed::g_autoMovePercent,
			Speed::AUTO_MIN_SPEED_PERCENT, Speed::AUTO_MAX_SPEED_PERCENT);
		ImGui::TextDisabled("100 = normal, 500 = 5x, 3000 = 30x. Only while buff 250 is active and > 2s remain.");

		// Live buff-250 state - always tracked, even with the menu closed.
		ImGui::Text("Celestial Dance (id 250): %s", Speed::g_buff250Active ? "ACTIVE" : "inactive");
		if (Speed::g_buff250Active)
		{
			const char* boostTxt = Speed::g_autoBoostActive ? "ON" : "OFF (returning to 100%)";
			int shownPercent = Speed::g_autoBoostActive ? Speed::g_autoMovePercent : 100;
			ImGui::Text("Boost: %s  |  speed: %d%%", boostTxt, shownPercent);
			if (Speed::g_buff250RemainingMs != 0)
			{
				unsigned long secs = (Speed::g_buff250RemainingMs + 500) / 1000;
				ImGui::Text("Remaining: %lu s", secs);
			}
			else
			{
				ImGui::TextDisabled("Remaining: (no timer)");
			}
		}
	}

	// ------------------------------------------------------------------
	// Cancel Attack Animation (combat-only extreme boost, auto-hunt gated)
	// ------------------------------------------------------------------
	if (ImGui::Checkbox("Cancel attack animation (combat speed)", &Speed::g_attackSpeedEnabled))
		Speed::SetAttackSpeedEnabled(Speed::g_attackSpeedEnabled);
	ImGui::SameLine();
	if (Speed::g_attackSpeedEnabled)
		ImGui::TextColored(ImVec4(0.3f, 1.0f, 0.3f, 1.0f), "ACTIVATED");
	else
		ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "NOT ACTIVATED");

	if (Speed::g_attackSpeedEnabled)
	{
		ImGui::SliderInt("Attack speed %", &Speed::g_attackSpeedPercent,
			Speed::ATTACK_MIN_SPEED_PERCENT, Speed::ATTACK_MAX_SPEED_PERCENT);
		ImGui::TextDisabled("While auto-hunt fights, the attack animation is skipped (interval -> 1 tick).");
		ImGui::TextDisabled("Walking keeps the normal slider speed. Lower it if the server disconnects you.");
		ImGui::Text("In combat: %s", IsAutoHuntInCombat() ? "YES" : "no");
	}

	ImGui::Checkbox("Fast auto-hunt/loot tick", &Speed::g_fastLootTick);
	ImGui::TextDisabled("Brain ticks faster than 1/sec -> faster loot/attack orders");
	if (Speed::g_fastLootTick)
	{
		ImGui::SliderInt("Loot tick interval (ms)", &Speed::g_fastLootIntervalMs, 50, 1000);
		ImGui::TextDisabled("50 = fastest (~20 orders/sec). Raise it if the server disconnects you.");
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
		ImGui::Text("Attack cancel: combat=%s monsterNear=%s",
			IsAutoHuntInCombat() ? "yes" : "no",
			IsAutoHuntMonsterNear() ? "yes" : "no");
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
		ImGui::Text("Speed caps raised: %s", Speed::g_capsRaised ? "yes" : "no");
		char bytesText[64];
		Speed::GetTargetBytesHex(bytesText, 16);
		ImGui::TextDisabled("Interval fn @0x010B0A9A: %s", bytesText);
		ImGui::TreePop();
	}
}
