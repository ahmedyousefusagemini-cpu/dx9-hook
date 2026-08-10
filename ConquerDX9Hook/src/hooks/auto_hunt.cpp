#include <windows.h>
#include <stdint.h>
#include "imgui.h"

// ============================================================================
// Auto Hunt (CAutoHangUpMgr) - Conquer.exe client 7937 (image base 0x400000)
// ----------------------------------------------------------------------------
// Finding (2026-08-10): the auto-hunt BEHAVIOR is client-driven. Every frame the
// hunt brain (FUN_00f54058) reads local game state (player position, nearby
// monsters, distances) and issues walk/attack calls. It only runs while
//     FUN_0111621f == (client+0x5385 != 0 && mgr+0x11 != 0).
//
// The in-game toggle (FUN_00bd7355) only sends the 0x855 "CMsgHangUp" notify
// packet - it never writes either client-side flag. That is why a bare packet
// toggle played the activation effect but never actually hunted.
//
// This feature therefore asserts BOTH client-side flags directly, every frame
// while enabled (so a server state update can't knock them back off), and still
// sends the notify packet so the server stays in sync.
// ============================================================================

namespace AutoHunt
{
	const uintptr_t TOGGLE_HANDLER_ADDRESS = 0x00BD7355;  // FUN_00bd7355 - notify packet
	const uintptr_t MANAGER_GLOBAL_ADDRESS = 0x01A531E0;  // DAT_01a531e0 - CAutoHangUpMgr*
	const uintptr_t CLIENT_GLOBAL_ADDRESS  = 0x01A52960;  // DAT_01a52960 - client object*
	const uintptr_t MANAGER_ACCESSOR_FUNC  = 0x00482705;  // FUN_00482705 - get/lazy-create mgr

	const size_t CLIENT_AUTO_BATTLE_BYTE_OFFSET = 0x5385;  // client auto-battle byte
	const size_t CLIENT_HUNT_GATE_OFFSET        = 0x1da0;  // brain gate (FUN_011ae8b7)

	const size_t MANAGER_STATE_WORD_OFFSET   = 0x10;  // 0x001 idle / 0x101 hunting
	const size_t MANAGER_HUNTING_BYTE_OFFSET = 0x11;  // hunting-active flag
	const size_t MANAGER_GATE_BYTE_OFFSET    = 0x12;  // per-frame gate byte
	const size_t MANAGER_TIMESTAMP_OFFSET    = 0x14;  // timeGetTime() of last toggle
	const size_t MANAGER_STRUCT_SIZE         = 0x44;

	// User intent - whether the hunt brain should be engaged. The per-frame
	// assertion (ApplyClientSideState) enforces it on the client.
	bool g_clientSideHunting = false;

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

	// The game's own accessor - lazy-creates the manager on first use.
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

	// Sends the same notify packet the in-game auto-hunt button sends.
	void Toggle()
	{
		if (!IsClientSupported())
			return;
		((ToggleFunc)TOGGLE_HANDLER_ADDRESS)();
	}

	// Runs every frame (even with the menu closed), like the memory scanner's
	// frozen-value pass. While the user wants hunting, keep BOTH client-side flags
	// set so the per-frame hunt brain stays engaged.
	void ApplyClientSideState()
	{
		if (!g_clientSideHunting)
			return;

		int client = GetClientObject();
		if (IsClientValid(client))
			*(unsigned char*)(client + CLIENT_AUTO_BATTLE_BYTE_OFFSET) = 1;  // auto-battle on

		int manager = GetOrCreateManager();
		if (IsManagerValid(manager))
			*(unsigned char*)(manager + MANAGER_HUNTING_BYTE_OFFSET) = 1;      // hunting on
	}

	void Start()
	{
		if (g_clientSideHunting)
			return;
		g_clientSideHunting = true;
		ApplyClientSideState();  // engage the brain right away
		Toggle();                // notify the server (same packet as the in-game button)
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

		Toggle();  // notify the server
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

	// Buttons reflect what the user asked for; the status text reflects the live
	// client state so we can see if the assertion is actually engaging the brain.
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

	if (ImGui::TreeNode("Auto Hunt Debug"))
	{
		int client = AutoHunt::GetClientObject();
		int manager = AutoHunt::GetManagerObject();

		ImGui::Text("Client: 0x%08X", (unsigned int)client);

		if (AutoHunt::IsClientValid(client))
		{
			ImGui::Text("AutoBattle byte (client+0x5385): %u",
				(unsigned int)*(unsigned char*)(client + AutoHunt::CLIENT_AUTO_BATTLE_BYTE_OFFSET));
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
