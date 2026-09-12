#include <windows.h>
#include <stdint.h>
#include <vector>

// ============================================================================
// Auto Hunt (CAutoHangUpMgr) - Conquer.exe client 7952 (image base 0x400000)
// ----------------------------------------------------------------------------
// The auto-hunt BEHAVIOR is client-driven: every frame the hunt brain
// (FUN_00f5589c) reads local game state and issues walk/attack calls. It only
// runs while  FUN_01117de4 == (client+0x5385 != 0 && mgr+0x11 != 0).
//
// The in-game toggle (FUN_00bd8035) only sends the 0x855 "CMsgHangUp" notify
// packet - it never writes either client-side flag. Worse, telling the server
// "I'm auto-hunting" makes it handle XP/loot differently (the user observed the
// XP bar resetting to zero). Since the hunting is client-driven, this feature
// now drives the client state DIRECTLY and does NOT send the notify packet by
// default, so the server treats the kills as normal gameplay.
//
// VIP spoof (2026-08-10): the VIP level is read from the client object by
// FUN_00fd3271 -> client+0x9e4 (or client+0x9ec). The auto-hunt feature gates
// (jump-search VIP3+, auto-pick VIP4+) just do  requiredLevel <= vipLevel. So
// forcing the client VIP field to 6 (max) passes every client-side gate.
//
// Waypoints / roam (2026-08-11): the character walks between a list of user
// points and hunts each one, moving on when the area is clear. Built from the
// brain's own helpers:
//   - player pos : FUN_00debdb2 walks the client's +0x98 chain to the role,
//                  (the obfuscated X/Y secure-pointer decode) /64.
//   - walk to x,y: FUN_00f49637(mgr, x, y, radius)  (__thiscall, ECX=mgr).
//   - monster?   : FUN_00f442cc(mgr, &pair)  (__thiscall) pair[0]==0 => clear.
//   - home anchor: mgr+0x20/+0x24 - where the brain returns when there's no
//                  target; we point it at the current waypoint.
// ============================================================================

namespace AutoHunt
{
	const uintptr_t TOGGLE_HANDLER_ADDRESS = 0x00BD8035;  // FUN_00bd8035 - notify packet
	const uintptr_t MANAGER_GLOBAL_ADDRESS = 0x01A55220;  // DAT_01a55220 - CAutoHangUpMgr*
	const uintptr_t CLIENT_GLOBAL_ADDRESS  = 0x01A549A0;  // DAT_01a549a0 - client object*
	const uintptr_t MANAGER_ACCESSOR_FUNC  = 0x00482805;  // FUN_00482805 - get/lazy-create mgr

	// Waypoint primitives (the brain's own helpers).
	const uintptr_t WALK_FUNC        = 0x00F49637;  // FUN_00f49637(mgr, x, y, radius)
	const uintptr_t FIND_TARGET_FUNC = 0x00F442CC;  // FUN_00f442cc(mgr, &outPair)

	const size_t CLIENT_AUTO_BATTLE_BYTE_OFFSET = 0x5385;  // client auto-battle byte
	const size_t CLIENT_HUNT_GATE_OFFSET        = 0x1da0;  // brain gate (client-side hunt flag)

	// VIP level fields read by the VIP getter FUN_00fd3271 (default / alt branch).
	const size_t CLIENT_VIP_LEVEL_FIELD_A = 0x9e4;
	const size_t CLIENT_VIP_LEVEL_FIELD_B = 0x9ec;

	const size_t MANAGER_STATE_WORD_OFFSET   = 0x10;  // 0x001 idle / 0x101 hunting
	const size_t MANAGER_HUNTING_BYTE_OFFSET = 0x11;  // hunting-active flag
	const size_t MANAGER_GATE_BYTE_OFFSET    = 0x12;  // per-frame gate byte
	const size_t MANAGER_TIMESTAMP_OFFSET    = 0x14;  // timeGetTime() of last toggle
	const size_t MANAGER_ANCHOR_X_OFFSET     = 0x20;  // walk-back/home anchor X
	const size_t MANAGER_ANCHOR_Y_OFFSET     = 0x24;  // walk-back/home anchor Y
	const size_t MANAGER_TARGET_X_OFFSET     = 0x4;   // brain's attack-target X (FUN_00f5589c)
	const size_t MANAGER_STRUCT_SIZE         = 0x44;

	// User intent - whether the hunt brain should be engaged.
	bool g_clientSideHunting = false;

	// Auto-start hunting when the character logs in (first login AND after
	// every auto-relogin). Default ON; persisted to coinfo.ini [AutoHunt].
	bool g_autoHuntOnLogin = true;

	// VIP spoof state (independent of hunting so it can stay on for the features).
	bool g_spoofVipLevel = false;
	int  g_vipLevel = 6;  // max, per "nVipLev >= 0 && nVipLev <= 6"

	// Whether to send the 0x855 notify packet to the server. Default OFF - the
	// packet tells the server the character is auto-hunting, which makes it reset
	// the XP bar / change loot handling. The hunting itself is client-driven, so
	// the packet is not needed for the overlay to work.
	bool g_notifyServer = false;

	// === Waypoints (roam between hunt spots) ===
	struct Waypoint { int x; int y; };
	std::vector<Waypoint> g_waypoints;
	bool g_waypointsEnabled = false;
	int  g_currentWaypoint = 0;
	int  g_newWaypointX = 0;
	int  g_newWaypointY = 0;
	int  g_arrivalThreshold = 4;        // tiles - how close counts as "arrived"
	int  g_clearedSeconds = 5;          // seconds with no monsters before moving on
	int  g_travelTimeoutSeconds = 30;   // give up on an unreachable waypoint

	static unsigned long g_lastWaypointTick = 0;
	static int  g_clearedChecks = 0;
	static bool g_traveling = false;
	static unsigned long g_travelStartMs = 0;
	static int  g_playerX = -1, g_playerY = -1;  // last good read (for the UI)

	typedef void (*ToggleFunc)();
	typedef int  (*ManagerAccessorFunc)();
	typedef void (__thiscall* WalkFunc)(void* mgr, int x, int y, int radius);
	typedef int* (__thiscall* FindTargetFunc)(void* mgr, int* outPair);

	bool IsClientSupported()
	{
		if (IsBadReadPtr((const void*)TOGGLE_HANDLER_ADDRESS, 3))
			return false;
		const unsigned char* code = (const unsigned char*)TOGGLE_HANDLER_ADDRESS;
		return code[0] == 0x6A && code[1] == 0x00 && code[2] == 0xE8;
	}

	int GetManagerObject()
	{
		if (IsBadReadPtr((const void*)MANAGER_GLOBAL_ADDRESS, sizeof(int)))
			return 0;
		return *(int*)MANAGER_GLOBAL_ADDRESS;
	}

	int GetOrCreateManager()
	{
		return ((ManagerAccessorFunc)MANAGER_ACCESSOR_FUNC)();
	}

	bool IsManagerValid(int manager)
	{
		return manager != 0 && !IsBadReadPtr((const void*)manager, MANAGER_STRUCT_SIZE);
	}

	// True while the brain is attacking a monster in range: the hunt brain
	// (FUN_00f5589c) writes mgr+4 = attack-position X (a small tile value)
	// when it decides to attack in place and zeroes it when the target is out
	// of range (walk branch). During looting the brain instead writes mgr+4 =
	// loot pointer (heap address) - excluded by the range check so looting
	// keeps the normal speed. After a kill the value can stay stale until the
	// brain's next walk/attack decision - callers may ClearAutoHuntTarget()
	// to reset it.
	bool IsInCombat()
	{
		int manager = GetManagerObject();
		if (!IsManagerValid(manager))
			return false;
		int value = *(int*)(manager + MANAGER_TARGET_X_OFFSET);
		return value != 0 && value < 0x100000;
	}

	int GetClientObject()
	{
		if (IsBadReadPtr((const void*)CLIENT_GLOBAL_ADDRESS, sizeof(int)))
			return 0;
		return *(int*)CLIENT_GLOBAL_ADDRESS;
	}

	bool IsClientValid(int client)
	{
		return client != 0 && !IsBadReadPtr((const void*)(client + CLIENT_AUTO_BATTLE_BYTE_OFFSET), 1);
	}

	// Mirrors the game's own is-hunting check (FUN_01117de4):
	// client+0x5385 != 0 && mgr+0x11 != 0.
	bool IsHunting()
	{
		int client = GetClientObject();
		if (!IsClientValid(client))
			return false;
		if (*(unsigned char*)(client + CLIENT_AUTO_BATTLE_BYTE_OFFSET) == 0)
			return false;

		int manager = GetManagerObject();
		if (!IsManagerValid(manager))
			return false;
		return *(unsigned char*)(manager + MANAGER_HUNTING_BYTE_OFFSET) != 0;
	}

	// Reads the VIP level exactly like the game's getter (FUN_00fd3271).
	int GetVipLevel()
	{
		int client = GetClientObject();
		if (!IsClientValid(client))
			return 0;
		return *(int*)(client + CLIENT_VIP_LEVEL_FIELD_A);
	}

	// Sends the 0x855 notify packet (only when the user opts in).
	void Toggle()
	{
		if (!IsClientSupported())
			return;
		((ToggleFunc)TOGGLE_HANDLER_ADDRESS)();
	}

	// Reads the player's tile position. Replicates the game's own read:
	// FUN_00debdb2 walks the client's +0x98 chain to the role, then decodes
	// the obfuscated X/Y (secure-pointer) into tiles.
	bool GetPlayerPos(int& outX, int& outY)
	{
		outX = -1; outY = -1;
		int client = GetClientObject();
		if (!IsClientValid(client))
			return false;

		// FUN_00debdb2: follow +0x98 to the tail node (the role).
		int role = client;
		for (int i = 0; i < 64; i++)
		{
			if (IsBadReadPtr((const void*)(role + 0x98), 4))
				return false;
			int next = *(int*)(role + 0x98);
			if (next == 0)
				break;
			role = next;
		}
		if (IsBadReadPtr((const void*)(role + 0x20), 4))
			return false;

		// The secure-pointer X/Y decode (mirrors the game's own read).
		unsigned int r20 = *(unsigned int*)(role + 0x20);
		unsigned int r1c = *(unsigned int*)(role + 0x1c);
		if (r1c != 0)
		{
			unsigned int addr = r20 ^ r1c;
			if (!IsBadReadPtr((const void*)addr, 4))
				outX = (int)((*(unsigned int*)addr) ^ r20) / 64;
		}

		// Y = (*(role[0x14] ^ role[0x10])) ^ role[0x14], then /64.
		unsigned int r14 = *(unsigned int*)(role + 0x14);
		unsigned int r10 = *(unsigned int*)(role + 0x10);
		if (r10 != 0)
		{
			unsigned int addr = r14 ^ r10;
			if (!IsBadReadPtr((const void*)addr, 4))
				outY = (int)((*(unsigned int*)addr) ^ r14) / 64;
		}
		return outX >= 0 && outY >= 0;
	}

	// Points the brain's "return to anchor" movement at (x,y).
	void SetAnchor(int manager, int x, int y)
	{
		if (!IsManagerValid(manager))
			return;
		*(int*)(manager + MANAGER_ANCHOR_X_OFFSET) = x;
		*(int*)(manager + MANAGER_ANCHOR_Y_OFFSET) = y;
	}

	// The brain's own walk-to-coordinate (FUN_00f48b93). No-op if already moving.
	void WalkTo(int manager, int x, int y)
	{
		if (!IsManagerValid(manager))
			return;
		((WalkFunc)WALK_FUNC)((void*)manager, x, y, 4);
	}

	// True when the brain's target finder (FUN_00f43828) sees an attackable monster.
	bool HasMonsterNear(int manager)
	{
		if (!IsManagerValid(manager))
			return false;
		int pair[2] = { 0, 0 };
		((FindTargetFunc)FIND_TARGET_FUNC)((void*)manager, pair);
		return pair[0] != 0;
	}

	// Drives the character between waypoints. Self rate-limits; called every frame.
	void UpdateWaypoints()
	{
		if (!g_clientSideHunting || !g_waypointsEnabled || g_waypoints.empty())
		{
			g_traveling = false;
			g_clearedChecks = 0;
			return;
		}

		unsigned long now = GetTickCount();
		if (now - g_lastWaypointTick < 400)  // ~2.5 checks/sec
			return;
		g_lastWaypointTick = now;

		int manager = GetOrCreateManager();
		if (!IsManagerValid(manager))
			return;

		if (g_currentWaypoint < 0 || g_currentWaypoint >= (int)g_waypoints.size())
			g_currentWaypoint = 0;
		const Waypoint& wp = g_waypoints[g_currentWaypoint];

		// Anchor the hunt on the current waypoint so the brain returns here.
		SetAnchor(manager, wp.x, wp.y);

		int px, py;
		if (GetPlayerPos(px, py)) { g_playerX = px; g_playerY = py; }
		else { px = g_playerX; py = g_playerY; }
		if (px < 0 || py < 0)
			return;

		// Monsters nearby -> let the brain fight them; stay in this area.
		if (HasMonsterNear(manager))
		{
			g_clearedChecks = 0;
			g_traveling = false;
			return;
		}

		// Area is clear. Head for the current waypoint.
		int dx = px - wp.x; if (dx < 0) dx = -dx;
		int dy = py - wp.y; if (dy < 0) dy = -dy;
		int dist = dx > dy ? dx : dy;  // chebyshev

		if (dist > g_arrivalThreshold)
		{
			// Not there yet - travel.
			g_clearedChecks = 0;
			if (!g_traveling) { g_traveling = true; g_travelStartMs = now; }
			else if (now - g_travelStartMs > (unsigned long)g_travelTimeoutSeconds * 1000UL)
			{
				// Couldn't reach it (blocked?) - skip to the next waypoint.
				g_traveling = false;
				g_currentWaypoint = (g_currentWaypoint + 1) % (int)g_waypoints.size();
				return;
			}
			WalkTo(manager, wp.x, wp.y);
		}
		else
		{
			// Arrived, and the area is clear.
			g_traveling = false;
			g_clearedChecks++;
			if (g_clearedChecks * 400 >= g_clearedSeconds * 1000)
			{
				g_clearedChecks = 0;
				g_currentWaypoint = (g_currentWaypoint + 1) % (int)g_waypoints.size();
			}
		}
	}

	// Runs every frame (even with the menu closed), like the memory scanner's
	// frozen-value pass. Applies each enabled override independently.
	void ApplyClientSideState()
	{
		if (g_clientSideHunting)
		{
			int client = GetClientObject();
			if (IsClientValid(client))
				*(unsigned char*)(client + CLIENT_AUTO_BATTLE_BYTE_OFFSET) = 1;  // auto-battle on

			int manager = GetOrCreateManager();
			if (IsManagerValid(manager))
				*(unsigned char*)(manager + MANAGER_HUNTING_BYTE_OFFSET) = 1;      // hunting on
		}

		if (g_spoofVipLevel)
		{
			int client = GetClientObject();
			if (IsClientValid(client))
			{
				*(int*)(client + CLIENT_VIP_LEVEL_FIELD_A) = g_vipLevel;
				*(int*)(client + CLIENT_VIP_LEVEL_FIELD_B) = g_vipLevel;
			}
		}

		UpdateWaypoints();  // self rate-limits
	}

	void Start()
	{
		if (g_clientSideHunting)
			return;
		g_clientSideHunting = true;
		ApplyClientSideState();      // engage the brain right away
		if (g_notifyServer)
			Toggle();                // optionally tell the server
	}

	void Stop()
	{
		if (!g_clientSideHunting)
			return;
		g_clientSideHunting = false;

		int manager = GetManagerObject();
		if (IsManagerValid(manager))
			*(unsigned char*)(manager + MANAGER_HUNTING_BYTE_OFFSET) = 0;

		int client = GetClientObject();
		if (IsClientValid(client))
			*(unsigned char*)(client + CLIENT_AUTO_BATTLE_BYTE_OFFSET) = 0;

		if (g_notifyServer)
			Toggle();                // optionally tell the server
	}
}

// Free wrapper so EndScene can run the per-frame assertion.
void ApplyAutoHuntClientState()
{
	AutoHunt::ApplyClientSideState();
}

bool IsAutoHuntHunting()
{
	return AutoHunt::IsHunting();
}

// The hunt brain is attacking a monster in range (mgr+4 != 0).
bool IsAutoHuntInCombat()
{
	return AutoHunt::IsInCombat();
}

// The brain's target finder (FUN_00f43828) sees an attackable monster.
bool IsAutoHuntMonsterNear()
{
	int manager = AutoHunt::GetManagerObject();
	return AutoHunt::HasMonsterNear(manager);
}

// Clears the brain's attack-target X so the combat signal doesn't stick on
// after a kill. The brain rewrites it on its next attack decision.
void ClearAutoHuntTarget()
{
	int manager = AutoHunt::GetManagerObject();
	if (manager != 0 &&
		!IsBadReadPtr((const void*)manager, 4) &&
		!IsBadWritePtr((void*)(manager + AutoHunt::MANAGER_TARGET_X_OFFSET), 4))
		*(int*)(manager + AutoHunt::MANAGER_TARGET_X_OFFSET) = 0;
}

