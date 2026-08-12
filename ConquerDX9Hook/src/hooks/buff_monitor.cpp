#include <windows.h>
#include <stdint.h>
#include <cstring>
#include <stdio.h>
#include "imgui.h"

// ============================================================================
// Buff Monitor - Conquer.exe client 7937 (image base 0x400000)
// ----------------------------------------------------------------------------
// NEW INVESTIGATION (2026-08-12): where are the character's CURRENT BUFFS
// stored, and can we list them in the overlay?
//
// What is already proven (OFFSETS.md / RESEARCH_NOTES.md):
//   - The client keeps a 576-bit STATUS BITMASK (ids < 0x240, 9 qwords).
//     The game tests it via FUN_00f1a1d8(client, id) -> FUN_00d4e0ae(mgr, id):
//     entry = mgr + (id >> 6) * 8, bit = id & 0x3F (low dword +0, high +4).
//   - OFFSETS.md places the bitmap at client+0x138 (wrapper: ADD ECX,0x138).
//     skill_state.cpp v2 reads it at client+0x00 and was calibrated live -
//     RESOLVING THIS DISCREPANCY is step 1 (base offset selectable below).
//   - Known ids so far:
//       XP-buff ids {0x5C 0x78 0x79 0x92 0x96 0x9F 0xC0 0xEB} (bar fill
//       FUN_011154f5 + XP dispatcher FUN_00a1d6bc),
//       46 = FatalStrike running, 480 = Celestial running (skill_state.cpp),
//       0x219 (537) = status checked by the CMsgMagicEffect handler.
//   - Still open: bit -> buff-NAME mapping for the other ~560 bits, and WHERE
//     THE REMAINING TIME lives. Leads: the interval function FUN_00de86b2
//     gates every buff modifier on this bitmap, and the XOR-obfuscated
//     active-magic list at client+0x16B0 may hold per-buff instances.
//
// How to map a buff with this panel:
//   1. Stand still with no new effects and press "Capture baseline".
//   2. Pop ONE buff. Bits that flipped ON show up green ("NEW since baseline").
//   3. When it expires it lands in "Cleared since baseline" (red).
//   4. Note the id, add it to g_known[] below, commit, repeat.
//
// Read-only: pure memory reads, no game calls, no hooks, no file IO
// (v12 crash lesson: never create trace files from a click handler).
// ============================================================================

namespace BuffMonitor
{
	const uintptr_t CLIENT_GLOBAL_ADDRESS = 0x01A52960;  // DAT_01a52960 - client object*

	const unsigned int STATUS_COUNT = 0x240;              // 576 status bits
	const unsigned int GROUP_COUNT  = STATUS_COUNT / 64;  // 9 qwords
	const size_t MAGIC_STATE_COMP   = 0x16B0;             // active-magic component (XOR list) - duration lead

	// Bitmap base candidates: 0x138 per OFFSETS.md (the FUN_00f1a1d8 wrapper does
	// ADD ECX,0x138); 0x00 per skill_state.cpp v2 (calibrated against a live
	// dump). Radio buttons below switch between them so the truth is one
	// in-game glance away (the wrong base shows garbage/empty bits).
	int g_bitmapBaseOffset = 0x138;

	struct KnownStatus { unsigned int id; const char* name; };
	const KnownStatus g_known[] =
	{
		{ 46,   "FatalStrike running (skill_state)" },
		{ 480,  "Celestial running (skill_state)" },
		{ 537,  "checked by CMsgMagicEffect (0x219)" },
		{ 0x5C, "XP buff? (dispatcher id 0x5C)" },
		{ 0x78, "XP buff? (dispatcher id 0x78)" },
		{ 0x79, "XP buff? (dispatcher id 0x79)" },
		{ 0x92, "XP buff? (dispatcher id 0x92)" },
		{ 0x96, "XP buff (bar-fill gate id 0x96)" },
		{ 0x9F, "XP buff? (dispatcher id 0x9F)" },
		{ 0xC0, "XP buff (bar-fill gate id 0xC0)" },
		{ 0xEB, "XP buff (bar-fill gate id 0xEB)" },
	};

	// Baseline snapshot for the diff workflow.
	unsigned long long g_baseline[GROUP_COUNT];
	bool g_hasBaseline = false;

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
		uintptr_t group = (uintptr_t)client + g_bitmapBaseOffset + (idx >> 6) * 8;
		if (IsBadReadPtr((const void*)group, 8))
			return false;
		unsigned int bit = 1u << (idx & 0x1f);
		if (idx & 0x20)
			return (*(unsigned int*)(group + 4) & bit) != 0;
		return (*(unsigned int*)(group + 0) & bit) != 0;
	}

	bool ReadGroup(int client, unsigned int group, unsigned long long* out)
	{
		uintptr_t address = (uintptr_t)client + g_bitmapBaseOffset + group * 8;
		if (IsBadReadPtr((const void*)address, 8))
			return false;
		unsigned int lo = *(unsigned int*)address;
		unsigned int hi = *(unsigned int*)(address + 4);
		*out = ((unsigned long long)hi << 32) | lo;
		return true;
	}

	const char* LookupName(unsigned int id)
	{
		for (size_t i = 0; i < _countof(g_known); i++)
			if (g_known[i].id == id)
				return g_known[i].name;
		return nullptr;
	}

	bool BaselineBit(unsigned int idx)
	{
		return ((g_baseline[idx >> 6] >> (idx & 0x3F)) & 1ULL) != 0;
	}

	void CaptureBaseline(int client)
	{
		for (unsigned int group = 0; group < GROUP_COUNT; group++)
		{
			unsigned long long value = 0;
			ReadGroup(client, group, &value);
			g_baseline[group] = value;
		}
		g_hasBaseline = true;
	}
}

void RenderBuffMonitorInterface()
{
	ImGui::Text("Buff Monitor");
	ImGui::Separator();

	int client = BuffMonitor::GetClientObject();
	if (client == 0 || IsBadReadPtr((const void*)client, 8))
	{
		ImGui::TextDisabled("Enter the game world to read buffs.");
		return;
	}

	// Base selector - resolving the 0x138 vs 0x00 discrepancy is step 1.
	if (ImGui::RadioButton("bitmap @ client+0x138 (OFFSETS.md)", BuffMonitor::g_bitmapBaseOffset == 0x138))
		BuffMonitor::g_bitmapBaseOffset = 0x138;
	if (ImGui::RadioButton("bitmap @ client+0x000 (skill_state)", BuffMonitor::g_bitmapBaseOffset == 0x00))
		BuffMonitor::g_bitmapBaseOffset = 0x00;

	// Baseline diff controls.
	if (ImGui::Button("Capture baseline"))
		BuffMonitor::CaptureBaseline(client);
	if (BuffMonitor::g_hasBaseline)
	{
		ImGui::SameLine();
		if (ImGui::Button("Clear baseline"))
			BuffMonitor::g_hasBaseline = false;
	}
	ImGui::TextDisabled("Workflow: capture baseline -> pop ONE buff -> green bit = that buff.");

	// Live count of set bits.
	unsigned int setCount = 0;
	for (unsigned int id = 0; id < BuffMonitor::STATUS_COUNT; id++)
		if (BuffMonitor::ReadStatus(client, id))
			setCount++;
	ImGui::Text("Status bits set: %u / %u", setCount, BuffMonitor::STATUS_COUNT);

	if (ImGui::TreeNode("Active status bits"))
	{
		for (unsigned int id = 0; id < BuffMonitor::STATUS_COUNT; id++)
		{
			if (!BuffMonitor::ReadStatus(client, id))
				continue;
			const char* name = BuffMonitor::LookupName(id);
			bool isNew = BuffMonitor::g_hasBaseline && !BuffMonitor::BaselineBit(id);
			if (isNew)
				ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.3f, 1.0f, 0.3f, 1.0f));
			if (name != nullptr)
				ImGui::BulletText("%3u (0x%02X)  %s", id, id, name);
			else if (isNew)
				ImGui::BulletText("%3u (0x%02X)  <NEW since baseline>", id, id);
			else
				ImGui::BulletText("%3u (0x%02X)", id, id);
			if (isNew)
				ImGui::PopStyleColor();
		}
		if (setCount == 0)
			ImGui::TextDisabled("(no bits set - try the other bitmap base)");
		ImGui::TreePop();
	}

	// Bits that were set in the baseline but are now CLEAR (a buff expired).
	if (BuffMonitor::g_hasBaseline && ImGui::TreeNode("Cleared since baseline"))
	{
		unsigned int cleared = 0;
		for (unsigned int id = 0; id < BuffMonitor::STATUS_COUNT; id++)
		{
			if (!BuffMonitor::BaselineBit(id) || BuffMonitor::ReadStatus(client, id))
				continue;
			ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.4f, 0.4f, 1.0f));
			const char* name = BuffMonitor::LookupName(id);
			if (name != nullptr)
				ImGui::BulletText("%3u (0x%02X)  %s", id, id, name);
			else
				ImGui::BulletText("%3u (0x%02X)", id, id);
			ImGui::PopStyleColor();
			cleared++;
		}
		if (cleared == 0)
			ImGui::TextDisabled("(none)");
		ImGui::TreePop();
	}

	// Raw view: the 9 qwords + the active-magic component (duration lead).
	if (ImGui::TreeNode("Raw dump"))
	{
		for (unsigned int group = 0; group < BuffMonitor::GROUP_COUNT; group++)
		{
			unsigned long long value = 0;
			if (BuffMonitor::ReadGroup(client, group, &value))
				ImGui::Text("g%u  %016llX", group, value);
		}
		if (!IsBadReadPtr((const void*)(client + BuffMonitor::MAGIC_STATE_COMP), 0x20))
		{
			unsigned int* comp = (unsigned int*)(client + BuffMonitor::MAGIC_STATE_COMP);
			ImGui::Text("MagicComp (+0x16B0):");
			ImGui::Text("%08X %08X %08X %08X", comp[0], comp[1], comp[2], comp[3]);
			ImGui::Text("%08X %08X %08X %08X", comp[4], comp[5], comp[6], comp[7]);
		}
		ImGui::TreePop();
	}
}
