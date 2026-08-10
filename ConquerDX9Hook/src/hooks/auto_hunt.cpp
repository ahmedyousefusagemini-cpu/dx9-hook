#include <windows.h>
#include <stdint.h>
#include "imgui.h"

// ============================================================================
// Auto Hunt (CAutoHangUpMgr) - Conquer.exe client 7937 (image base 0x400000)
// ----------------------------------------------------------------------------
// The auto-hunt BEHAVIOR is client-driven: every frame the hunt brain
// (FUN_00f54058) reads local game state and issues walk/attack calls. It only
// runs while  FUN_0111621f == (client+0x5385 != 0 && mgr+0x11 != 0).
//
// The in-game toggle (FUN_00bd7355) only sends the 0x855 "CMsgHangUp" notify
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
// ============================================================================

namespace AutoHunt
{
	const uintptr_t TOGGLE_HANDLER_ADDRESS = 0x00BD7355;  // FUN_00bd7355 - notify packet
	const uintptr_t MANAGER_GLOBAL_ADDRESS = 0x01A531E0;  // DAT_01a531e0 - CAutoHangUpMgr*
	const uintptr_t CLIENT_GLOBAL_ADDRESS  = 0x01A52960;  // DAT_01a52960 - client object*
	const uintptr_t MANAGER_ACCESSOR_FUNC  = 0x00482705;  // FUN_00482705 - get/lazy-create mgr

	const size_t CLIENT_AUTO_BATTLE_BYTE_OFFSET = 0x5385;  // client auto-battle byte
	const size_t CLIENT_HUNT_GATE_OFFSET        = 0x1da0;  // brain gate (FUN_011ae8b7)

	// VIP level fields read by the VIP getter FUN_00fd3271 (default / alt branch).
	const size_t CLIENT_VIP_LEVEL_FIELD_A = 0x9e4;
	const size_t CLIENT_VIP_LEVEL_FIELD_B = 0x9ec;

	const size_t MANAGER_STATE_WORD_OFFSET   = 0x10;  // 0x001 idle / 0x101 hunting
	const size_t MANAGER_HUNTING_BYTE_OFFSET = 0x11;  // hunting-active flag
	const size_t MANAGER_GATE_BYTE_OFFSET    = 0x12;  // per-frame gate byte
	const size_t MANAGER_TIMESTAMP_OFFSET    = 0x14;  // timeGetTime() of last toggle
	const size_t MANAGER_STRUCT_SIZE         = 0x44;

	// User intent - whether the hunt brain should be engaged.
	bool g_clientSideHunting = false;

	// VIP spoof state (independent of hunting so it can stay on for the features).
	bool g_spoofVipLevel = false;
	int  g_vipLevel = 6;  // max, per "nVipLev >= 0 && nVipLev <= 6"

	// Whether to send the 0x855 notify packet to the server. Default OFF - the
	// packet tells the server the character is auto-hunting, which makes it reset
	// the XP bar / change loot handling. The hunting itself is client-driven, so
	// the packet is not needed for the overlay to work.
	bool g_notifyServer = false;

	typedef void (*ToggleFunc)();
	typedef int  (*ManagerAccessorFunc)();

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

	// Mirrors the game's own is-hunting check (FUN_0111621f):
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

// Free wrapper so imgui_interface.cpp can run the per-frame assertion.
void ApplyAutoHuntClientState()
{
	AutoHunt::ApplyClientSideState();
}

void RenderAutoHuntInterface()
{
	ImGui::Text("Auto Hunt");
	ImGui::Separator();

	if (!AutoHunt::IsClientSupported())
	{
		ImGui::TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), "Unsupported client build - auto hunt unavailable");
		return;
	}

	bool isHunting = AutoHunt::IsHunting();

	ImGui::Text("Status: ");
	ImGui::SameLine(0.0f, 0.0f);
	if (isHunting)
		ImGui::TextColored(ImVec4(0.3f, 1.0f, 0.3f, 1.0f), "HUNTING");
	else
		ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "Idle");

	if (AutoHunt::g_clientSideHunting)
	{
		if (ImGui::Button("Stop Auto Hunt"))
			AutoHunt::Stop();
	}
	else
	{
		if (ImGui::Button("Start Auto Hunt"))
			AutoHunt::Start();
	}

	// The 0x855 packet tells the server the character is auto-hunting (which made
	// it reset the XP bar). Off by default so the server treats kills as normal.
	ImGui::Checkbox("Notify server (0x855 packet)", &AutoHunt::g_notifyServer);
	ImGui::TextDisabled("Leave OFF so the server keeps filling XP normally");

	// VIP level spoof - unlocks the client-side VIP-gated auto-hunt features
	// (jump-search VIP3+, auto-pick VIP4+).
	ImGui::Spacing();
	ImGui::Checkbox("Spoof VIP level (client-side)", &AutoHunt::g_spoofVipLevel);
	if (AutoHunt::g_spoofVipLevel)
	{
		ImGui::SliderInt("VIP level", &AutoHunt::g_vipLevel, 0, 6);
		ImGui::TextDisabled("Real level: %d", AutoHunt::GetVipLevel());
	}

	if (ImGui::TreeNode("Auto Hunt Debug"))
	{
		int client = AutoHunt::GetClientObject();
		int manager = AutoHunt::GetManagerObject();

		ImGui::Text("Client: 0x%08X", (unsigned int)client);

		if (AutoHunt::IsClientValid(client))
		{
			ImGui::Text("AutoBattle byte (client+0x5385): %u",
				(unsigned int)*(unsigned char*)(client + AutoHunt::CLIENT_AUTO_BATTLE_BYTE_OFFSET));
			ImGui::Text("VIP level (client+0x9e4): %d",
				*(int*)(client + AutoHunt::CLIENT_VIP_LEVEL_FIELD_A));
		}

		if (client && !IsBadReadPtr((const void*)(client + AutoHunt::CLIENT_HUNT_GATE_OFFSET), 4))
		{
			ImGui::Text("Client gate (client+0x1da0): %u",
				(unsigned int)*(unsigned int*)(client + AutoHunt::CLIENT_HUNT_GATE_OFFSET));
		}

		ImGui::Text("Manager: 0x%08X", (unsigned int)manager);

		if (manager && !IsBadReadPtr((const void*)manager, AutoHunt::MANAGER_STRUCT_SIZE))
		{
			unsigned short stateWord = *(unsigned short*)(manager + AutoHunt::MANAGER_STATE_WORD_OFFSET);
			unsigned char huntingByte = *(unsigned char*)(manager + AutoHunt::MANAGER_HUNTING_BYTE_OFFSET);
			unsigned char gateByte = *(unsigned char*)(manager + AutoHunt::MANAGER_GATE_BYTE_OFFSET);
			unsigned long timestamp = *(unsigned long*)(manager + AutoHunt::MANAGER_TIMESTAMP_OFFSET);

			ImGui::Text("State word (mgr+0x10): 0x%03X", (unsigned int)stateWord);
			ImGui::Text("Hunting byte (mgr+0x11): %u", (unsigned int)huntingByte);
			ImGui::Text("Gate byte (mgr+0x12): %u", (unsigned int)gateByte);
			ImGui::Text("Last toggle (mgr+0x14): %lu", timestamp);
		}

		ImGui::TreePop();
	}
}
