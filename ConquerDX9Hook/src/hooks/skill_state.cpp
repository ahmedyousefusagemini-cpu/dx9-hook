#include <windows.h>
#include <stdint.h>
#include <cstring>
#include "imgui.h"

// ============================================================================
// Skill State indicator - Conquer.exe client 7937 (image base 0x400000)
// ----------------------------------------------------------------------------
// Shows whether the character's timed skills are ACTIVE right now:
//   - XP skill     "FatalStrike" (magic type 6011 = 0x177B) - glow, 500% dmg
//   - Weapon skill "Celestial"  (magic type 7030 = 0x1B76) - glow, move
//     speed + level-scaled damage, wide-area melee
// and the resulting mode: NORMAL / XP SKILL / WEAPON SKILL / COMBINED.
//
// How the client tracks it (mapped via Ghidra, CMsgMagicEffect 0x976 /
// CMsgMagicEffectTime handlers):
//   - The client object keeps the LEARNED magics in a vector at
//     client+0x1D88 (begin) / +0x1D8C (end), 8-byte entries; entry[0] points
//     at the magic's record (same walk as XpSkill::ScanMagics).
//   - record+0x70 = magic info struct (FUN_00d9612c); info+0x5C = type id.
//   - record+0x68 = a std::map of ACTIVE instances of that magic on the
//     local player (FUN_01056bd5 writes node+0x14 = expiry). Old MSVC
//     std::map node layout: +0x00 left, +0x04 parent, +0x08 right,
//     +0x0D isNil, +0x10 key, +0x14 expiry.
//   - Expiry uses the server-synced seconds clock (FUN_010f6da0):
//     now = (timeGetTime() - client+0x533C) / 1000 + client+0x5340.
//     GetTickCount shares the same millisecond base as timeGetTime.
//
// Read-only: no writes, no hooks - detection only, nothing the server can see.
// ============================================================================

namespace SkillState
{
	const uintptr_t CLIENT_GLOBAL_ADDRESS = 0x01A52960;  // DAT_01a52960 - client object*

	const size_t CLIENT_MAGIC_VEC_BEGIN = 0x1d88;  // learned-magic vector begin
	const size_t CLIENT_MAGIC_VEC_END   = 0x1d8c;  // learned-magic vector end
	const size_t RECORD_INFO_OFFSET     = 0x70;    // record + 0x70 = magic info (FUN_00d9612c)
	const size_t INFO_ID_OFFSET         = 0x5c;    // info + 0x5C = magic type id
	const size_t RECORD_MAP_OFFSET      = 0x68;    // record + 0x68 = active-instance map
	const size_t MAP_NODE_KEY_OFFSET    = 0x10;    // map node + 0x10 = key
	const size_t MAP_NODE_EXPIRY_OFFSET = 0x14;    // map node + 0x14 = expiry (synced seconds)
	const size_t MAP_NODE_NIL_OFFSET    = 0x0d;    // map node + 0x0D = isNil byte
	const size_t CLIENT_SYNC_TICK_OFFSET = 0x533c; // timeGetTime() at last clock sync
	const size_t CLIENT_SYNC_BASE_OFFSET = 0x5340; // synced base seconds

	const unsigned int MAGIC_ID_FATAL_STRIKE = 6011;  // 0x177B - XP skill
	const unsigned int MAGIC_ID_CELESTIAL    = 7030;  // 0x1B76 - weapon skill

	struct MagicState
	{
		bool learned;            // the character has this magic at all
		bool active;             // an unexpired active instance exists
		unsigned int secondsLeft;   // remaining time on the longest instance
		uintptr_t record;        // debug: the learned-magic record
		unsigned int mapSize;    // debug: active-instance count
	};

	int GetClientObject()
	{
		if (IsBadReadPtr((const void*)CLIENT_GLOBAL_ADDRESS, sizeof(int)))
			return 0;
		return *(int*)CLIENT_GLOBAL_ADDRESS;
	}

	// Mirrors FUN_010f6da0: the server-synced seconds clock the expiries use.
	unsigned int GetSyncedNowSeconds(int client)
	{
		if (IsBadReadPtr((const void*)(client + CLIENT_SYNC_TICK_OFFSET), 8))
			return 0;
		unsigned int syncTick = *(unsigned int*)(client + CLIENT_SYNC_TICK_OFFSET);
		unsigned int syncBase = *(unsigned int*)(client + CLIENT_SYNC_BASE_OFFSET);
		return (GetTickCount() - syncTick) / 1000 + syncBase;
	}

	// Walks the record's active-instance std::map; returns true when at least
	// one instance expires in the future. All reads guarded - the map mutates
	// on the game thread while we read it, so any node may vanish mid-walk.
	bool ScanActiveMap(uintptr_t record, unsigned int now, unsigned int* secondsLeft,
		unsigned int* nodeCount)
	{
		bool foundActive = false;
		unsigned int bestLeft = 0;
		*secondsLeft = 0;
		*nodeCount = 0;

		uintptr_t mapObject = record + RECORD_MAP_OFFSET;
		if (IsBadReadPtr((const void*)mapObject, 8))
			return false;

		uintptr_t head = *(uintptr_t*)mapObject;               // _Myhead sentinel
		unsigned int size = *(unsigned int*)(mapObject + 4);   // _Mysize
		if (head == 0 || size == 0 || size > 256)
			return false;
		if (IsBadReadPtr((const void*)head, 0x18))
			return false;

		uintptr_t node = *(uintptr_t*)head;                    // _Left = smallest
		for (unsigned int steps = 0; steps < size; steps++)
		{
			if (node == 0 || node == head || IsBadReadPtr((const void*)node, 0x18))
				break;
			if (*(unsigned char*)(node + MAP_NODE_NIL_OFFSET) != 0)
				break;

			(*nodeCount)++;
			unsigned int expiry = *(unsigned int*)(node + MAP_NODE_EXPIRY_OFFSET);
			if (expiry > now)
			{
				foundActive = true;
				unsigned int left = expiry - now;
				if (left > bestLeft)
					bestLeft = left;
			}

			// In-order successor: right subtree's leftmost, else first ancestor
			// for which we came from the left child. Stop at the sentinel.
			uintptr_t right = *(uintptr_t*)(node + 8);
			if (right != 0 && right != head && !IsBadReadPtr((const void*)right, 0x10) &&
				*(unsigned char*)(right + MAP_NODE_NIL_OFFSET) == 0)
			{
				node = right;
				for (;;)
				{
					uintptr_t left = *(uintptr_t*)node;
					if (left == 0 || left == head || IsBadReadPtr((const void*)left, 0x10) ||
						*(unsigned char*)(left + MAP_NODE_NIL_OFFSET) != 0)
						break;
					node = left;
				}
			}
			else
			{
				uintptr_t parent = *(uintptr_t*)(node + 4);
				while (parent != 0 && parent != head &&
					!IsBadReadPtr((const void*)parent, 0x10) &&
					*(unsigned char*)(parent + MAP_NODE_NIL_OFFSET) == 0 &&
					*(uintptr_t*)(parent + 8) == node)
				{
					node = parent;
					parent = *(uintptr_t*)(node + 4);
				}
				node = parent;
				if (node == head)
					break;
			}
		}

		*secondsLeft = bestLeft;
		return foundActive;
	}

	// Finds the learned magic by type id and checks its active-instance map.
	MagicState CheckMagic(int client, unsigned int magicId)
	{
		MagicState result;
		memset(&result, 0, sizeof(result));

		if (IsBadReadPtr((const void*)(client + CLIENT_MAGIC_VEC_BEGIN), 8))
			return result;
		uintptr_t begin = *(uintptr_t*)(client + CLIENT_MAGIC_VEC_BEGIN);
		uintptr_t end   = *(uintptr_t*)(client + CLIENT_MAGIC_VEC_END);
		if (begin == 0 || end < begin)
			return result;
		uintptr_t bytes = end - begin;
		if ((bytes & 7) != 0 || bytes > 0x8000)
			return result;

		for (uintptr_t entry = begin; entry < end; entry += 8)
		{
			if (IsBadReadPtr((const void*)entry, 8))
				break;
			uintptr_t record = *(uintptr_t*)entry;   // entry[0] = record ptr
			if (record == 0)
				continue;

			uintptr_t info = record + RECORD_INFO_OFFSET;
			if (IsBadReadPtr((const void*)(info + INFO_ID_OFFSET), 4))
				continue;
			if (*(unsigned int*)(info + INFO_ID_OFFSET) != magicId)
				continue;

			result.learned = true;
			result.record = record;
			unsigned int now = GetSyncedNowSeconds(client);
			result.active = ScanActiveMap(record, now, &result.secondsLeft, &result.mapSize);
			return result;
		}
		return result;
	}

	// Debug: how many learned magics the vector currently holds.
	unsigned int CountLearnedMagics(int client)
	{
		if (IsBadReadPtr((const void*)(client + CLIENT_MAGIC_VEC_BEGIN), 8))
			return 0;
		uintptr_t begin = *(uintptr_t*)(client + CLIENT_MAGIC_VEC_BEGIN);
		uintptr_t end   = *(uintptr_t*)(client + CLIENT_MAGIC_VEC_END);
		if (begin == 0 || end < begin || ((end - begin) & 7) != 0)
			return 0;
		uintptr_t count = (end - begin) / 8;
		return count > 0x1000 ? 0 : (unsigned int)count;
	}
}

void RenderSkillStateInterface()
{
	ImGui::Text("Skill State");
	ImGui::Separator();

	int client = SkillState::GetClientObject();
	if (client == 0 || IsBadReadPtr((const void*)(client + SkillState::CLIENT_MAGIC_VEC_BEGIN), 8))
	{
		ImGui::TextDisabled("Enter the game world to read skill state.");
		return;
	}

	SkillState::MagicState xp = SkillState::CheckMagic(client, SkillState::MAGIC_ID_FATAL_STRIKE);
	SkillState::MagicState weapon = SkillState::CheckMagic(client, SkillState::MAGIC_ID_CELESTIAL);

	// Mode banner.
	const char* modeText;
	ImVec4 modeColor;
	if (xp.active && weapon.active)
	{
		modeText = "COMBINED (XP + Weapon)";
		modeColor = ImVec4(0.3f, 1.0f, 0.3f, 1.0f);
	}
	else if (xp.active)
	{
		modeText = "XP SKILL";
		modeColor = ImVec4(1.0f, 0.85f, 0.2f, 1.0f);
	}
	else if (weapon.active)
	{
		modeText = "WEAPON SKILL";
		modeColor = ImVec4(0.3f, 0.8f, 1.0f, 1.0f);
	}
	else
	{
		modeText = "NORMAL";
		modeColor = ImVec4(0.7f, 0.7f, 0.7f, 1.0f);
	}
	ImGui::Text("Mode:");
	ImGui::SameLine();
	ImGui::TextColored(modeColor, modeText);

	// Per-skill lines.
	if (xp.active)
		ImGui::TextColored(ImVec4(1.0f, 0.85f, 0.2f, 1.0f),
			"XP Skill (FatalStrike): ACTIVE - %us left", xp.secondsLeft);
	else if (xp.learned)
		ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "XP Skill (FatalStrike): ready (not running)");
	else
		ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "XP Skill (FatalStrike): not learned");

	if (weapon.active)
		ImGui::TextColored(ImVec4(0.3f, 0.8f, 1.0f, 1.0f),
			"Weapon Skill (Celestial): ACTIVE - %us left", weapon.secondsLeft);
	else if (weapon.learned)
		ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "Weapon Skill (Celestial): ready (not running)");
	else
		ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "Weapon Skill (Celestial): not learned");

	if (ImGui::TreeNode("Skill State Debug"))
	{
		ImGui::Text("Client: 0x%08X", (unsigned int)client);
		ImGui::Text("Learned magics: %u", SkillState::CountLearnedMagics(client));
		ImGui::Text("Synced now (s): %u", SkillState::GetSyncedNowSeconds(client));
		ImGui::Text("FatalStrike rec: 0x%08X  map nodes: %u  left: %us",
			(unsigned int)xp.record, xp.mapSize, xp.secondsLeft);
		ImGui::Text("Celestial  rec: 0x%08X  map nodes: %u  left: %us",
			(unsigned int)weapon.record, weapon.mapSize, weapon.secondsLeft);
		ImGui::TreePop();
	}
}
