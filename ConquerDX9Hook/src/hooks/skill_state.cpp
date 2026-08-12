#include <windows.h>
#include <stdint.h>
#include <cstring>
#include <stdio.h>
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
// Detection (v2 - status bitmap):
//   v1 walked the learned-magic records' active-instance map (record+0x68);
//   that map stays EMPTY on this server - the live path is the status bitmap
//   the game itself reads via FUN_00f1a1d8(idx) -> FUN_00d4e0ae(client, idx):
//   the client object begins with a 576-bit status bitmap - 9 groups of 64
//   bits; group g lives at client + g*8 (low dword +0, high dword +4) and
//   status idx is bit (idx & 0x1F) of the (idx & 0x20 ? high : low) dword.
//   Verified against the CMsgMagicEffect handler (checks status 0x219 through
//   exactly this chain) and the interval function FUN_00de86b2 (gates every
//   buff modifier on it).
//
//   The two skills' status indices live in the server data files (not the
//   exe), so they are runtime-discovered: the debug tree lists every status
//   bit currently set - toggle a skill in-game and the appearing index is
//   that skill's status. The constants below get the discovered values.
//
// Read-only: no writes, no hooks - detection only, nothing the server can see.
// ============================================================================

namespace SkillState
{
	const uintptr_t CLIENT_GLOBAL_ADDRESS = 0x01A52960;  // DAT_01a52960 - client object*

	const size_t CLIENT_STATUS_BITMAP   = 0x00;    // status bitmap base = client+0x00
	const unsigned int STATUS_COUNT     = 0x240;   // 576 status bits (FUN_00f1a1d8 bound)
	const size_t CLIENT_MAGIC_VEC_BEGIN = 0x1d88;  // learned-magic vector begin
	const size_t CLIENT_MAGIC_VEC_END   = 0x1d8c;  // learned-magic vector end
	const size_t RECORD_INFO_OFFSET     = 0x70;    // record + 0x70 = magic info
	const size_t INFO_ID_OFFSET         = 0x5c;    // info + 0x5C = magic type id
	const size_t CLIENT_MAGIC_STATE_COMP = 0x16b0; // my active-magic component (XOR list)

	const unsigned int MAGIC_ID_FATAL_STRIKE = 6011;  // 0x177B - XP skill
	const unsigned int MAGIC_ID_CELESTIAL    = 7030;  // 0x1B76 - weapon skill

	// Status indices discovered at runtime (see the debug tree). -1 = unknown.
	int g_fatalStatusIdx  = -1;
	int g_celestialStatusIdx = -1;

	int GetClientObject()
	{
		if (IsBadReadPtr((const void*)CLIENT_GLOBAL_ADDRESS, sizeof(int)))
			return 0;
		return *(int*)CLIENT_GLOBAL_ADDRESS;
	}

	// Exact mirror of FUN_00d4e0ae (the game's own status-bit read).
	bool ReadStatus(int client, unsigned int idx)
	{
		if (idx >= STATUS_COUNT)
			return false;
		uintptr_t group = client + CLIENT_STATUS_BITMAP + (idx >> 6) * 8;
		if (IsBadReadPtr((const void*)group, 8))
			return false;
		unsigned int bit = 1u << (idx & 0x1f);
		if (idx & 0x20)
			return (*(unsigned int*)(group + 4) & bit) != 0;
		return (*(unsigned int*)(group + 0) & bit) != 0;
	}

	// Is the magic learned at all (walks the learned-magic vector).
	bool IsMagicLearned(int client, unsigned int magicId)
	{
		if (IsBadReadPtr((const void*)(client + CLIENT_MAGIC_VEC_BEGIN), 8))
			return false;
		uintptr_t begin = *(uintptr_t*)(client + CLIENT_MAGIC_VEC_BEGIN);
		uintptr_t end   = *(uintptr_t*)(client + CLIENT_MAGIC_VEC_END);
		if (begin == 0 || end < begin)
			return false;
		uintptr_t bytes = end - begin;
		if ((bytes & 7) != 0 || bytes > 0x8000)
			return false;
		for (uintptr_t entry = begin; entry < end; entry += 8)
		{
			if (IsBadReadPtr((const void*)entry, 8))
				break;
			uintptr_t record = *(uintptr_t*)entry;
			if (record == 0)
				continue;
			uintptr_t info = record + RECORD_INFO_OFFSET;
			if (IsBadReadPtr((const void*)(info + INFO_ID_OFFSET), 4))
				continue;
			if (*(unsigned int*)(info + INFO_ID_OFFSET) == magicId)
				return true;
		}
		return false;
	}

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

	// Debug: lists the status bits currently set in one 64-bit group.
	// Returns how many were appended; writes "12 45 78 " style.
	int DumpSetBits(int client, unsigned int group, char* outBuffer, int outSize)
	{
		uintptr_t address = client + CLIENT_STATUS_BITMAP + group * 8;
		if (IsBadReadPtr((const void*)address, 8))
			return 0;
		unsigned int lo = *(unsigned int*)address;
		unsigned int hi = *(unsigned int*)(address + 4);
		int written = 0;
		int pos = (int)strlen(outBuffer);
		for (unsigned int bit = 0; bit < 32 && pos < outSize - 8; bit++)
		{
			if (lo & (1u << bit))
				pos += snprintf(outBuffer + pos, outSize - pos, "%u ", group * 64 + bit);
			if (hi & (1u << bit))
				pos += snprintf(outBuffer + pos, outSize - pos, "%u ", group * 64 + 32 + bit);
		}
		(void)written;
		return pos;
	}

	// Debug: dumps a learned magic's info struct (record+0x70) as raw
	// offset:value dword pairs - one of these fields is the status bit the
	// magic sets while active (correlate with the set-bits dump above).
	bool DumpMagicInfo(int client, unsigned int magicId, char* outBuffer, int outSize)
	{
		if (IsBadReadPtr((const void*)(client + CLIENT_MAGIC_VEC_BEGIN), 8))
			return false;
		uintptr_t begin = *(uintptr_t*)(client + CLIENT_MAGIC_VEC_BEGIN);
		uintptr_t end   = *(uintptr_t*)(client + CLIENT_MAGIC_VEC_END);
		if (begin == 0 || end < begin || ((end - begin) & 7) != 0)
			return false;
		for (uintptr_t entry = begin; entry < end; entry += 8)
		{
			if (IsBadReadPtr((const void*)entry, 8))
				break;
			uintptr_t record = *(uintptr_t*)entry;
			if (record == 0)
				continue;
			uintptr_t info = record + RECORD_INFO_OFFSET;
			if (IsBadReadPtr((const void*)(info + INFO_ID_OFFSET), 4))
				continue;
			if (*(unsigned int*)(info + INFO_ID_OFFSET) != magicId)
				continue;
			int pos = 0;
			for (unsigned int field = 0; field < 32 && pos < outSize - 10; field++)
			{
				uintptr_t slot = info + field * 4;
				if (IsBadReadPtr((const void*)slot, 4))
					break;
				pos += snprintf(outBuffer + pos, outSize - pos, "%u:%u ", field * 4, *(unsigned int*)slot);
			}
			return true;
		}
		return false;
	}
}

void RenderSkillStateInterface()
{
	ImGui::Text("Skill State");
	ImGui::Separator();

	int client = SkillState::GetClientObject();
	if (client == 0 || IsBadReadPtr((const void*)client, 8))
	{
		ImGui::TextDisabled("Enter the game world to read skill state.");
		return;
	}

	bool xpKnown = SkillState::g_fatalStatusIdx >= 0;
	bool weaponKnown = SkillState::g_celestialStatusIdx >= 0;
	bool xpActive = xpKnown && SkillState::ReadStatus(client, (unsigned int)SkillState::g_fatalStatusIdx);
	bool weaponActive = weaponKnown && SkillState::ReadStatus(client, (unsigned int)SkillState::g_celestialStatusIdx);

	// Mode banner.
	const char* modeText;
	ImVec4 modeColor;
	if (xpActive && weaponActive)
	{
		modeText = "COMBINED (XP + Weapon)";
		modeColor = ImVec4(0.3f, 1.0f, 0.3f, 1.0f);
	}
	else if (xpActive)
	{
		modeText = "XP SKILL";
		modeColor = ImVec4(1.0f, 0.85f, 0.2f, 1.0f);
	}
	else if (weaponActive)
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
	if (!xpKnown)
		ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "XP Skill (FatalStrike): status bit not mapped yet");
	else if (xpActive)
		ImGui::TextColored(ImVec4(1.0f, 0.85f, 0.2f, 1.0f), "XP Skill (FatalStrike): ACTIVE");
	else
		ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "XP Skill (FatalStrike): ready (not running)");

	if (!weaponKnown)
		ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "Weapon Skill (Celestial): status bit not mapped yet");
	else if (weaponActive)
		ImGui::TextColored(ImVec4(0.3f, 0.8f, 1.0f, 1.0f), "Weapon Skill (Celestial): ACTIVE");
	else
		ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "Weapon Skill (Celestial): ready (not running)");

	ImGui::TextDisabled("FatalStrike learned: %s | Celestial learned: %s",
		SkillState::IsMagicLearned(client, SkillState::MAGIC_ID_FATAL_STRIKE) ? "yes" : "no",
		SkillState::IsMagicLearned(client, SkillState::MAGIC_ID_CELESTIAL) ? "yes" : "no");

	if (ImGui::TreeNode("Skill State Debug"))
	{
		ImGui::Text("Client: 0x%08X", (unsigned int)client);
		ImGui::Text("Learned magics: %u", SkillState::CountLearnedMagics(client));
		ImGui::TextDisabled("Status bits set per 64-bit group (toggle a skill and");
		ImGui::TextDisabled("watch which index appears - that is its status bit):");
		char line[512];
		for (unsigned int group = 0; group < 9; group++)
		{
			line[0] = 0;
			int pos = snprintf(line, sizeof(line), "g%u: ", group);
			SkillState::DumpSetBits(client, group, line, (int)sizeof(line));
			(void)pos;
			ImGui::Text("%s", line);
		}
		char info[768];
		info[0] = 0;
		if (SkillState::DumpMagicInfo(client, SkillState::MAGIC_ID_FATAL_STRIKE, info, (int)sizeof(info)))
			ImGui::Text("FS info: %s", info);
		info[0] = 0;
		if (SkillState::DumpMagicInfo(client, SkillState::MAGIC_ID_CELESTIAL, info, (int)sizeof(info)))
			ImGui::Text("CE info: %s", info);
		// The my-magic component head (client+0x16B0), raw - XOR-obfuscated list.
		if (!IsBadReadPtr((const void*)(client + SkillState::CLIENT_MAGIC_STATE_COMP), 0x20))
		{
			unsigned int* comp = (unsigned int*)(client + SkillState::CLIENT_MAGIC_STATE_COMP);
			ImGui::Text("MagicComp: %08X %08X %08X %08X %08X %08X %08X %08X",
				comp[0], comp[1], comp[2], comp[3], comp[4], comp[5], comp[6], comp[7]);
		}
		ImGui::TreePop();
	}
}
