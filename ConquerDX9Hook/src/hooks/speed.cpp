#include <windows.h>
#include <stdint.h>
#include <string.h>
#include "MinHook.h"
#include "imgui.h"

// ============================================================================
// Speed Control (CRole action intervals) - Conquer.exe client 7937 (0x400000)
// ----------------------------------------------------------------------------
// Every role action (walk / run / attack / pickup / ...) gets its duration
// from ONE virtual: the per-role action-interval function FUN_010afd05
// (ECX = role, one stack arg = time delta, RET 4). It forwards to the master
// computation FUN_00de86b2 (3drole\role.cpp), which produces the interval for
// the role's current action state (role+0xb4, 13 states). Smaller interval =
// faster action, so scaling the return value of this ONE function speeds up
// movement AND attack AND the pickup animation at once.
//
// The hook only rescales the LOCAL player's role: a role is ours when its
// entity id (role+0x268; player ids are < 1000000) matches the client object's
// local id (client+0x26c, read by the game's own getter FUN_0098c58d via
// FUN_00fcd1e8). While hooked it also caches the my-role pointer so the debug
// tree can show it.
//
// Looting speed: the hunt brain (FUN_00f54058) is rate-limited by
//   if (timeGetTime() < DAT_01a5cdb4 + 1000) return;
// Only the brain ever reads/writes DAT_01a5cdb4 (verified by xrefs), so
// forcing it to 0 every frame makes the brain (target-find / attack / loot)
// tick at frame rate instead of once per second. Worst case the write races
// the brain's own timestamp update and it ticks every other frame - still
// ~30x faster than stock.
//
// Safety: the game's interval math clamps divisors to >= 1 and the final
// interval to >= 1, and this hook does the same - the client cannot hit a
// zero interval or a div-by-zero from these paths. All speed-up here is
// client-side; the server may rubber-band movement or drop loot requests at
// extreme values, so the slider tops out at 500%.
// ============================================================================

namespace Speed
{
	const uintptr_t ACTION_INTERVAL_FUNC   = 0x010AFD05;  // FUN_010afd05 - CRole interval virtual
	const uintptr_t CLIENT_GLOBAL_ADDRESS  = 0x01A52960;  // DAT_01a52960 - client object*
	const uintptr_t HUNT_BRAIN_TICK_GLOBAL = 0x01A5CDB4;  // DAT_01a5cdb4 - last brain tick (timeGetTime)

	const size_t ROLE_ENTITY_ID_OFFSET = 0x268;  // role+0x268: entity id (players < 1000000)
	const size_t CLIENT_MY_ID_OFFSET   = 0x26c;  // client+0x26c: local player id (FUN_0098c58d)

	const int MIN_SPEED_PERCENT = 100;  // 100% = normal speed (no scaling below this)
	const int MAX_SPEED_PERCENT = 500;  // beyond this the server rubber-bands hard

	// User settings.
	bool g_speedEnabled = false;
	int  g_speedPercent = 200;          // default 2x
	bool g_fastLootTick = false;        // reset the brain tick gate every frame

	// Local player's role pointer, captured inside the hook (for the debug tree).
	uintptr_t g_myRoleAddress = 0;

	// The target is __thiscall (ECX = role, one stack arg, RET 4). A MinHook
	// detour declared __fastcall receives ECX in arg1 and EDX in arg2 (unused),
	// with stack args following - so the register/stack state matches the
	// original call site exactly, and the trampoline is called the same way.
	typedef unsigned int (__fastcall* GetActionIntervalFunc)(uintptr_t role, void* unusedEdx, unsigned int timeDelta);
	GetActionIntervalFunc g_originalGetActionInterval = nullptr;
	bool g_isSpeedHookInstalled = false;

	bool IsClientSupported()
	{
		// FUN_010afd05 prologue on client 7937:
		//   55          PUSH EBP
		//   8B EC       MOV EBP,ESP
		//   56          PUSH ESI
		//   8B F1       MOV ESI,ECX
		//   83 BE F8 08 00 00 00   CMP dword ptr [ESI+0x8F8],0
		static const unsigned char expectedBytes[] =
			{ 0x55, 0x8B, 0xEC, 0x56, 0x8B, 0xF1, 0x83, 0xBE, 0xF8, 0x08, 0x00, 0x00, 0x00 };
		if (IsBadReadPtr((const void*)ACTION_INTERVAL_FUNC, sizeof(expectedBytes)))
			return false;
		return memcmp((const void*)ACTION_INTERVAL_FUNC, expectedBytes, sizeof(expectedBytes)) == 0;
	}

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

	bool IsLocalPlayerRole(uintptr_t role, unsigned int myEntityId)
	{
		if (myEntityId == 0 || IsBadReadPtr((const void*)(role + ROLE_ENTITY_ID_OFFSET), sizeof(unsigned int)))
			return false;
		return *(unsigned int*)(role + ROLE_ENTITY_ID_OFFSET) == myEntityId;
	}

	unsigned int __fastcall HookedGetActionInterval(uintptr_t role, void* unusedEdx, unsigned int timeDelta)
	{
		unsigned int interval = g_originalGetActionInterval(role, unusedEdx, timeDelta);

		if (!g_speedEnabled || g_speedPercent <= MIN_SPEED_PERCENT)
			return interval;

		int client = GetClientObject();
		unsigned int myEntityId = GetMyEntityId(client);
		if (!IsLocalPlayerRole(role, myEntityId))
			return interval;

		g_myRoleAddress = role;  // cache for the debug tree

		// interval * 100 / percent (200% -> half interval -> 2x speed).
		// The game's own code clamps the final interval to >= 1; mirror that.
		unsigned long long scaled = ((unsigned long long)interval * 100) / (unsigned int)g_speedPercent;
		return scaled == 0 ? 1 : (unsigned int)scaled;
	}

	void InstallSpeedHook()
	{
		if (g_isSpeedHookInstalled)
			return;
		if (!IsClientSupported())
			return;
		if (MH_CreateHook((LPVOID)ACTION_INTERVAL_FUNC, (LPVOID)HookedGetActionInterval, (LPVOID*)&g_originalGetActionInterval) != MH_OK)
			return;
		if (MH_EnableHook((LPVOID)ACTION_INTERVAL_FUNC) == MH_OK)
			g_isSpeedHookInstalled = true;
	}

	void SetSpeedEnabled(bool enabled)
	{
		if (enabled)
			InstallSpeedHook();  // no-op if already installed or the build check fails
		g_speedEnabled = enabled && g_isSpeedHookInstalled;
		if (!g_speedEnabled)
			g_myRoleAddress = 0;
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

	if (!Speed::IsClientSupported())
	{
		ImGui::TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), "Unsupported client build - speed control unavailable");
		return;
	}

	bool enabled = Speed::g_speedEnabled;
	if (ImGui::Checkbox("Enable speed control (move + attack)", &enabled))
		Speed::SetSpeedEnabled(enabled);

	if (Speed::g_speedEnabled)
	{
		ImGui::SliderInt("Action speed %", &Speed::g_speedPercent, Speed::MIN_SPEED_PERCENT, Speed::MAX_SPEED_PERCENT);
		ImGui::TextDisabled("100 = normal, 200 = 2x. Too high may rubber-band (server check).");
	}

	ImGui::Checkbox("Fast auto-hunt/loot tick", &Speed::g_fastLootTick);
	ImGui::TextDisabled("Brain ticks every frame instead of 1/sec -> faster loot/attack orders");

	if (ImGui::TreeNode("Speed Debug"))
	{
		int client = Speed::GetClientObject();
		ImGui::Text("Client: 0x%08X", (unsigned int)client);
		ImGui::Text("My entity id (client+0x26c): %u", Speed::GetMyEntityId(client));
		ImGui::Text("My role: 0x%08X", (unsigned int)Speed::g_myRoleAddress);
		ImGui::Text("Hook installed: %s", Speed::g_isSpeedHookInstalled ? "yes" : "no");
		ImGui::TreePop();
	}
}
