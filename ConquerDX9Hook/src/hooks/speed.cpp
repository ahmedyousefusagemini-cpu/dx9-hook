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
// My-role discovery without hooks: a role is ours when its entity id
// (role+0x268; player ids < 1000000) equals the client object's local id
// (client+0x26c, the game's own getter FUN_0098c58d). We scan committed
// writable memory once (background thread) for a dword == myId at offset
// 0x268 of an object whose vtable points into the Conquer.exe image and whose
// action state (role+0xb4) is < 13, then cache the pointer and rewrite the
// speed fields every frame (same pattern as the VIP spoof).
//
// Looting speed: unchanged from before - the hunt brain (FUN_00f54058) only
// ticks when  timeGetTime() >= DAT_01a5cdb4 + 1000. Only the brain reads or
// writes that global (verified by xrefs), so forcing it to 0 every frame lets
// the brain issue find/attack/loot orders at frame rate instead of 1/sec.
//
// Safety: only data writes, nothing patched. The game's interval math clamps
// divisors to >= 1 and the final interval to >= 1. All speed-up is
// client-side: the server may rubber-band movement or drop loot requests at
// extreme values, so the slider tops out at 500%.
// ============================================================================

namespace Speed
{
	const uintptr_t CLIENT_GLOBAL_ADDRESS  = 0x01A52960;  // DAT_01a52960 - client object*
	const uintptr_t HUNT_BRAIN_TICK_GLOBAL = 0x01A5CDB4;  // DAT_01a5cdb4 - last brain tick (timeGetTime)
	const uintptr_t ACTION_INTERVAL_FUNC   = 0x010AFD05;  // FUN_010afd05 - for the info line only

	const size_t CLIENT_MY_ID_OFFSET     = 0x26c;  // client+0x26c: local player id (FUN_0098c58d)
	const size_t ROLE_ENTITY_ID_OFFSET   = 0x268;  // role+0x268: entity id (players < 1000000)
	const size_t ROLE_ACTION_STATE       = 0xb4;   // role+0xb4: action state dword (< 13)
	const size_t ROLE_SPEED_BOOST_OFFSET = 0x44;   // role+0x44: boost in 1/100 % (needs +0x48)
	const size_t ROLE_SPEED_BOOST_FLAG   = 0x48;   // role+0x48: byte, enables the +0x44 divisor

	const int MIN_SPEED_PERCENT = 100;  // 100% = normal speed
	const int MAX_SPEED_PERCENT = 500;  // beyond this the server rubber-bands hard

	const uintptr_t IMAGE_BASE = 0x00400000;   // Conquer.exe image base
	const uintptr_t IMAGE_TOP  = 0x02000000;   // vtable sanity range upper bound

	// User settings.
	bool g_speedEnabled = false;
	int  g_speedPercent = 200;          // default 2x
	bool g_fastLootTick = false;        // reset the brain tick gate every frame

	// My-role cache + scan state (written by the scan thread, read per-frame).
	volatile uintptr_t g_myRoleAddress = 0;
	volatile long g_scanState = 0;      // 0 idle, 1 scanning, 2 done
	volatile unsigned long g_lastScanTick = 0;

	int GetClientObject()
	{
		if (IsBadReadPtr((const void*)CLIENT_GLOBAL_ADDRESS, sizeof(int)))
			return 0;
		return *(int*)CLIENT_GLOBAL_ADDRESS;
	}

	unsigned int GetMyEntityId(int client)
	{
		if (client == 0 || IsBadReadPtr((const void*)(client + CLIENT_MY_ID_OFFSET), sizeof(unsigned int)))
			return 0;
		return *(unsigned int*)(client + CLIENT_MY_ID_OFFSET);
	}

	bool IsMyRoleWritable(uintptr_t role)
	{
		return role != 0 &&
			!IsBadReadPtr((const void*)(role + ROLE_SPEED_BOOST_OFFSET), 8) &&
			!IsBadWritePtr((void*)(role + ROLE_SPEED_BOOST_OFFSET), 8);
	}

	// Writes (or clears) the speed-boost fields on my role. Runs every frame so
	// a game-side rewrite can't knock them off (same pattern as the VIP spoof).
	void WriteSpeedFields(uintptr_t role, bool enabled)
	{
		*(unsigned char*)(role + ROLE_SPEED_BOOST_FLAG) = enabled ? 1 : 0;
		*(int*)(role + ROLE_SPEED_BOOST_OFFSET) =
			enabled ? (g_speedPercent - MIN_SPEED_PERCENT) * 100 : 0;
	}

	// Candidate check: object at base looks like a CRole instance and its entity
	// id matches the local player.
	bool LooksLikeMyRole(uintptr_t base, unsigned int myEntityId)
	{
		if (*(unsigned int*)(base + ROLE_ENTITY_ID_OFFSET) != myEntityId)
			return false;
		uintptr_t vtable = *(uintptr_t*)base;  // vtable must point into the exe image
		if (vtable < IMAGE_BASE || vtable >= IMAGE_TOP)
			return false;
		return *(unsigned int*)(base + ROLE_ACTION_STATE) < 13;
	}

	// Background scan: walk committed writable regions looking for the role
	// whose +0x268 dword equals my entity id. Same VirtualQuery pattern as the
	// memory scanner, but targeted at one dword so it's quick.
	DWORD WINAPI FindMyRoleThread(LPVOID)
	{
		unsigned int myEntityId = GetMyEntityId(GetClientObject());
		if (myEntityId == 0)
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
				for (uintptr_t p = start; p + ROLE_ENTITY_ID_OFFSET + 4 <= end; p += 4)
				{
					if (*(unsigned int*)(p + ROLE_ENTITY_ID_OFFSET) == myEntityId &&
						LooksLikeMyRole(p, myEntityId))
					{
						g_myRoleAddress = p;
						g_scanState = 2;
						return 0;
					}
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
		g_lastScanTick = GetTickCount();
		CreateThread(NULL, 0, FindMyRoleThread, NULL, 0, NULL);
	}

	void SetSpeedEnabled(bool enabled)
	{
		if (!enabled && IsMyRoleWritable(g_myRoleAddress))
			WriteSpeedFields(g_myRoleAddress, false);  // restore stock behavior

		g_speedEnabled = enabled;

		if (enabled && g_myRoleAddress == 0)
			StartRoleScan();
	}

	// Runs every frame (even with the menu closed), like auto-hunt's pass.
	void ApplyClientSideState()
	{
		if (g_fastLootTick)
		{
			// Force the brain's last-tick timestamp to 0 so its 1000 ms gate
			// passes every frame. Only FUN_00f54058 reads/writes this global.
			if (!IsBadWritePtr((void*)HUNT_BRAIN_TICK_GLOBAL, sizeof(unsigned long)))
				*(unsigned long*)HUNT_BRAIN_TICK_GLOBAL = 0;
		}

		if (g_speedEnabled)
		{
			uintptr_t role = g_myRoleAddress;
			if (IsMyRoleWritable(role))
			{
				WriteSpeedFields(role, true);
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
	unsigned int myEntityId = Speed::GetMyEntityId(client);
	if (client == 0 || myEntityId == 0)
	{
		ImGui::TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), "Game not ready - log in first");
		return;
	}

	bool enabled = Speed::g_speedEnabled;
	if (ImGui::Checkbox("Enable speed control (move + attack)", &enabled))
		Speed::SetSpeedEnabled(enabled);

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

	ImGui::Checkbox("Fast auto-hunt/loot tick", &Speed::g_fastLootTick);
	ImGui::TextDisabled("Brain ticks every frame instead of 1/sec -> faster loot/attack orders");

	if (ImGui::TreeNode("Speed Debug"))
	{
		ImGui::Text("Client: 0x%08X", (unsigned int)client);
		ImGui::Text("My entity id (client+0x26c): %u", myEntityId);
		ImGui::Text("My role: 0x%08X", (unsigned int)Speed::g_myRoleAddress);
		ImGui::Text("Scan state: %s", Speed::g_scanState == 1 ? "scanning" :
			(Speed::g_scanState == 2 ? "done" : "idle"));
		if (Speed::g_myRoleAddress != 0 && !IsBadReadPtr((const void*)(Speed::g_myRoleAddress + Speed::ROLE_SPEED_BOOST_OFFSET), 8))
		{
			ImGui::Text("role+0x44: %d  role+0x48: %u",
				*(int*)(Speed::g_myRoleAddress + Speed::ROLE_SPEED_BOOST_OFFSET),
				(unsigned int)*(unsigned char*)(Speed::g_myRoleAddress + Speed::ROLE_SPEED_BOOST_FLAG));
		}
		char bytesText[64];
		Speed::GetTargetBytesHex(bytesText, 16);
		ImGui::TextDisabled("Interval fn @0x010AFD05: %s", bytesText);
		ImGui::TreePop();
	}
}
