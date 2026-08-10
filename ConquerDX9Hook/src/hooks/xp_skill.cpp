#include <windows.h>
#include <stdint.h>
#include "imgui.h"

// ============================================================================
// XP Skills While Hunting - Conquer.exe client 7937 (image base 0x400000)
// ----------------------------------------------------------------------------
// While the auto-hunt state is active the client refuses XP skills with
// "[System] Unable to use XP skills when auto-fighting"
// (string key STR_CANNOT_USE_XP_WHEN_HANGUP @ 0x01741FA4).
//
// Three client-side gates, all driven by IsHunting (FUN_0111621f):
//
//   1) FUN_011154f5 charges the 0-100 XP bar (object +0xaec) ONLY when not
//      hunting - the JNZ at 0x01115514 skips the fill while hunting.
//      Patch 75 49 -> 90 90 so the bar charges during auto-hunt (the
//      function's own status-flag gates 0x96/0xc0/0xeb stay intact).
//
//   2) FUN_011b1ec9 (use skill on target): if hunting AND the current skill
//      is an XP-type skill ([FUN_00d9612c(client)+0x30] == 1, where the
//      accessor returns client+0x70), it shows the string and bails. The JZ
//      at 0x011B21D8 skips that block when not hunting.
//      Patch 74 59 -> EB 59 so the block never runs.
//
//   3) FUN_011b3503 (use skill at position): identical block.
//      Patch 74 4A -> EB 4A.
//
// The server is unaffected: the overlay never sends the 0x855 notify packet,
// so the XP pop is treated as normal gameplay.
// ============================================================================

namespace XpSkill
{
	const uintptr_t XP_FILL_GATE_ADDRESS      = 0x01115514;  // FUN_011154f5 - JNZ skip-fill
	const uintptr_t USE_TARGET_GATE_ADDRESS   = 0x011B21D8;  // FUN_011b1ec9 - JZ skip-block
	const uintptr_t USE_POSITION_GATE_ADDRESS = 0x011B3B21;  // FUN_011b3503 - JZ skip-block

	struct BytePatch
	{
		uintptr_t address;
		unsigned char original[2];
		unsigned char patched[2];
	};

	BytePatch g_patches[] =
	{
		{ XP_FILL_GATE_ADDRESS,       { 0x75, 0x49 }, { 0x90, 0x90 } },  // JNZ -> NOP NOP
		{ USE_TARGET_GATE_ADDRESS,    { 0x74, 0x59 }, { 0xEB, 0x59 } },  // JZ  -> JMP
		{ USE_POSITION_GATE_ADDRESS,  { 0x74, 0x4A }, { 0xEB, 0x4A } },  // JZ  -> JMP
	};

	// User intent - whether XP skills should work while hunting.
	bool g_allowXpSkills = false;
	bool g_patchesApplied = false;

	// Same idea as AutoHunt::IsClientSupported - never write into an unknown
	// build: every site must still hold its original bytes.
	bool IsClientSupported()
	{
		for (int i = 0; i < _countof(g_patches); i++)
		{
			const BytePatch& patch = g_patches[i];
			if (IsBadReadPtr((const void*)patch.address, sizeof(patch.original)))
				return false;
			const unsigned char* code = (const unsigned char*)patch.address;
			if (code[0] != patch.original[0] || code[1] != patch.original[1])
				return false;
		}
		return true;
	}

	void WritePatches(bool apply)
	{
		for (int i = 0; i < _countof(g_patches); i++)
		{
			const BytePatch& patch = g_patches[i];
			DWORD oldProtect = 0;
			if (!VirtualProtect((void*)patch.address, 2, PAGE_EXECUTE_READWRITE, &oldProtect))
				continue;

			const unsigned char* source = apply ? patch.patched : patch.original;
			*(unsigned char*)patch.address = source[0];
			*(unsigned char*)(patch.address + 1) = source[1];

			VirtualProtect((void*)patch.address, 2, oldProtect, &oldProtect);
		}
		g_patchesApplied = apply;
	}

	// Runs when the overlay checkbox changes. Applies or restores the patches.
	void ApplyXpSkillState()
	{
		if (g_allowXpSkills && !g_patchesApplied)
		{
			if (IsClientSupported())
				WritePatches(true);
			else
				g_allowXpSkills = false;  // unknown build - stay off
		}
		else if (!g_allowXpSkills && g_patchesApplied)
		{
			WritePatches(false);
		}
	}
}

void RenderXpSkillInterface()
{
	ImGui::Text("XP Skills");
	ImGui::Separator();

	if (!XpSkill::IsClientSupported() && !XpSkill::g_patchesApplied)
	{
		ImGui::TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), "Unsupported client build - XP unlock unavailable");
		return;
	}

	if (ImGui::Checkbox("Allow XP skills while hunting", &XpSkill::g_allowXpSkills))
		XpSkill::ApplyXpSkillState();

	ImGui::TextDisabled("Removes the \"no XP skills when auto-fighting\" block");
	ImGui::TextDisabled("Bar also charges while hunting. Client-side only.");
}
