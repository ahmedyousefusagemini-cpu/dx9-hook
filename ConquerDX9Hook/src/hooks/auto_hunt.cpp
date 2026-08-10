#include <windows.h>
#include <stdint.h>
#include "imgui.h"

// ============================================================================
// Auto Hunt (CAutoHangUpMgr) - Conquer.exe client 7937 (image base 0x400000)
// ----------------------------------------------------------------------------
// Reverse-engineered entry points (see RESEARCH_NOTES.md):
//
//   FUN_00bd7355 (0x00BD7355) - exactly what the auto-hunt dialog's Begin
//     (0x201) and Stop (0x202) buttons both run:
//         PUSH 0
//         CALL FUN_00482705        ; EAX = CAutoHangUpMgr singleton (lazy init)
//         MOV  ECX, EAX
//         CALL FUN_00f2fcd5        ; mgr->Toggle(0): stamps mgr+0x14 with
//                                  ; timeGetTime(), builds a CMsgHangUp packet
//                                  ; (type 0x855 / 2133) and sends it through
//                                  ; the legitimate send path (FUN_010ce686)
//         RET
//     Begin and Stop send the SAME packet; the server performs the actual
//     toggle, so callers must gate on the current state (see IsHunting).
//
//   FUN_0111621f (0x0111621F) - the game's own "is hunting" check:
//     client+0x5385 != 0 && mgr+0x11 != 0. It expects the client object in
//     ECX (FUN_0111524b is `MOV AL,[ECX+0x5385]; RET`, no null check), so
//     instead of calling it we replicate it with plain memory reads.
//
//   DAT_01a52960 (0x01A52960) - client object global (null outside the game).
//   DAT_01a531e0 (0x01A531E0) - CAutoHangUpMgr singleton (null until 1st use).
// ============================================================================

namespace AutoHunt
{
	const uintptr_t TOGGLE_HANDLER_ADDRESS = 0x00BD7355;  // FUN_00bd7355
	const uintptr_t CLIENT_GLOBAL_ADDRESS  = 0x01A52960;  // DAT_01a52960
	const uintptr_t MANAGER_GLOBAL_ADDRESS = 0x01A531E0;  // DAT_01a531e0

	// client+0x5385: auto-battle byte (read by FUN_0111524b)
	const size_t CLIENT_AUTO_BATTLE_BYTE_OFFSET = 0x5385;

	// CAutoHangUpMgr fields
	const size_t MANAGER_STATE_WORD_OFFSET   = 0x10;  // 0x100 idle / 0x101 transition
	const size_t MANAGER_HUNTING_BYTE_OFFSET = 0x11;  // read by FUN_00f4761b
	const size_t MANAGER_GATE_BYTE_OFFSET    = 0x12;  // read by FUN_00f4761f
	const size_t MANAGER_TIMESTAMP_OFFSET    = 0x14;  // timeGetTime() of last toggle
	const size_t MANAGER_STRUCT_SIZE         = 0x44;

	typedef void (*ToggleAutoHuntFunc)();

	// The addresses above only match client 7937. FUN_00bd7355 starts with
	// 6A 00 E8 (PUSH 0; CALL ...) - verify before ever calling into it.
	bool IsClientSupported()
	{
		if (IsBadReadPtr((const void*)TOGGLE_HANDLER_ADDRESS, 3))
			return false;

		const unsigned char* code = (const unsigned char*)TOGGLE_HANDLER_ADDRESS;
		return code[0] == 0x6A && code[1] == 0x00 && code[2] == 0xE8;
	}

	int GetClientObject()
	{
		if (IsBadReadPtr((const void*)CLIENT_GLOBAL_ADDRESS, sizeof(int)))
			return 0;
		return *(int*)CLIENT_GLOBAL_ADDRESS;
	}

	int GetManagerObject()
	{
		if (IsBadReadPtr((const void*)MANAGER_GLOBAL_ADDRESS, sizeof(int)))
			return 0;
		return *(int*)MANAGER_GLOBAL_ADDRESS;
	}

	bool IsClientAutoBattleEnabled(int client)
	{
		if (!client || IsBadReadPtr((const void*)(client + CLIENT_AUTO_BATTLE_BYTE_OFFSET), 1))
			return false;
		return *(unsigned char*)(client + CLIENT_AUTO_BATTLE_BYTE_OFFSET) != 0;
	}

	// Same condition as the game's FUN_0111621f, but with null/bad-pointer
	// guards instead of the undocumented ECX=this calling convention.
	bool IsHunting()
	{
		int client = GetClientObject();
		if (!IsClientAutoBattleEnabled(client))
			return false;

		int manager = GetManagerObject();
		if (!manager || IsBadReadPtr((const void*)manager, MANAGER_STRUCT_SIZE))
			return false;

		return *(unsigned char*)(manager + MANAGER_HUNTING_BYTE_OFFSET) != 0;
	}

	// Sends the same CMsgHangUp toggle packet the dialog buttons send.
	// Runs inside HookedEndScene, i.e. the game thread on this client -
	// the same context the in-game dialog buttons execute in.
	void Toggle()
	{
		if (!IsClientSupported())
			return;

		((ToggleAutoHuntFunc)TOGGLE_HANDLER_ADDRESS)();
	}
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

	// Begin and Stop are the same request server-side, so one state-aware
	// button covers both directions.
	if (isHunting)
	{
		if (ImGui::Button("Stop Auto Hunt"))
			AutoHunt::Toggle();
	}
	else
	{
		if (ImGui::Button("Start Auto Hunt"))
			AutoHunt::Toggle();
	}

	// Live state dump for in-game verification of the toggle semantics.
	if (ImGui::TreeNode("Auto Hunt Debug"))
	{
		int client = AutoHunt::GetClientObject();
		int manager = AutoHunt::GetManagerObject();

		ImGui::Text("Client: 0x%08X", (unsigned int)client);

		if (client && !IsBadReadPtr((const void*)(client + AutoHunt::CLIENT_AUTO_BATTLE_BYTE_OFFSET), 1))
		{
			ImGui::Text("AutoBattle byte (client+0x5385): %u",
				(unsigned int)*(unsigned char*)(client + AutoHunt::CLIENT_AUTO_BATTLE_BYTE_OFFSET));
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
