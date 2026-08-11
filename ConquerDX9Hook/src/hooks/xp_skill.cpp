#include <windows.h>
#include <stdint.h>
#include "imgui.h"

// ============================================================================
// XP Skills - Conquer.exe client 7937 (image base 0x400000)
// ----------------------------------------------------------------------------
// 1) "Allow XP skills while hunting" - removes the client block
//    "[System] Unable to use XP skills when auto-fighting"
//    (string key STR_CANNOT_USE_XP_WHEN_HANGUP @ 0x01741FA4).
//    Three gates, all driven by IsHunting (FUN_0111621f):
//      - FUN_011154f5 charges the 0-100 XP bar (client+0xaec) only when not
//        hunting - JNZ @ 0x01115514: 75 49 -> 90 90.
//      - FUN_011b1ec9 (use skill on target): if hunting AND the current skill
//        is XP-type ([FUN_00d9612c(client)+0x30] == 1) it shows the string and
//        bails - JZ @ 0x011B21D8: 74 59 -> EB 59.
//      - FUN_011b3503 (use skill at position): identical block -
//        JZ @ 0x011B3B21: 74 4A -> EB 4A.
//
// 2) "Auto XP skill when bar is full" - pops the character's XP skill
//    (Superman / Fatal Strike / any class) automatically.
//
//    The activation mirrors EXACTLY what clicking the lit XP icon does
//    (FUN_00b811a4 = the XP icon click handler; it plays the "yuanshen_jdt1"
//    effect - yuanshen = the XP skill system - then fires):
//
//        FUN_011b1ec9  __thiscall(ECX = client, 0x5FDC, selfUid, 0, 1)
//
//    0x5FDC is a generic XP-skill PSEUDO magic id: the client sends it as-is
//    and the SERVER maps it to the character's actual XP skill - which is why
//    the icon is only enabled when the server says the bar is full. No
//    per-class id table or learned-magic probing is needed (the v1 probing
//    approach never matched - those dispatcher ids are not in the
//    learned-list key space). The same pseudo id appears in the hotkey flow:
//    hotkey command 0x76D -> FUN_00a1d6bc((0x5FDC << 8), 0x72), and the
//    dispatcher special-cases 0x4A6/0x4AB/0x5FDC to fire at self directly.
//
//    - XP bar value: *(uint*)(client + 0xaec); full at 100 (FUN_011154f5
//      clamps to 100 and treats 99 < bar as full).
//    - selfUid = *(uint*)(client + 0x268) (confirmed at FUN_00d3fb0f).
//    - The use-skill gates above are already patched by (1), and note the
//      FUN_011b1ec9 gate reads the CURRENT skill's +0x30 (the attack skill
//      while hunting), so the pop works during auto-hunt either way.
//    - Server unaffected: the 0x855 packet stays withheld, so the XP pop is
//      treated as normal gameplay.
// ============================================================================

namespace XpSkill
{
	// --- Gate patch sites (feature 1) ---
	const uintptr_t XP_FILL_GATE_ADDRESS      = 0x01115514;  // FUN_011154f5 - JNZ skip-fill
	const uintptr_t USE_TARGET_GATE_ADDRESS   = 0x011B21D8;  // FUN_011b1ec9 - JZ skip-block
	const uintptr_t USE_POSITION_GATE_ADDRESS = 0x011B3B21;  // FUN_011b3503 - JZ skip-block

	// --- Auto-activation addresses (feature 2) ---
	const uintptr_t CLIENT_GLOBAL_ADDRESS    = 0x01A52960;  // DAT_01a52960 - client object*
	const uintptr_t MANAGER_GLOBAL_ADDRESS   = 0x01A531E0;  // DAT_01a531e0 - CAutoHangUpMgr*
	const uintptr_t USE_SKILL_ON_TARGET_FUNC = 0x011B1EC9;  // FUN_011b1ec9

	const size_t CLIENT_XP_BAR_OFFSET          = 0xaec;   // 0-100, full at 100
	const size_t CLIENT_SELF_UID_OFFSET        = 0x268;   // own role/UID
	const size_t CLIENT_AUTO_BATTLE_BYTE_OFFSET = 0x5385; // auto-battle flag
	const size_t MANAGER_HUNTING_BYTE_OFFSET   = 0x11;    // hunting-active flag

	// The generic XP-skill pseudo magic id the XP icon click handler
	// (FUN_00b811a4) fires. The server maps it to Superman / Fatal Strike /
	// whatever the character's class XP skill is.
	const unsigned int XP_PSEUDO_MAGIC_ID = 0x5FDC;

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

	// Auto-activation state.
	bool g_autoXpSkill = false;
	bool g_autoXpOnlyWhileHunting = true;   // default: pop during auto-hunt only
	DWORD g_lastFireAttempt = 0;
	unsigned long g_fireCount = 0;          // how many times we sent the pop
	const DWORD FIRE_INTERVAL_MS = 1000;    // same cadence as the hunt brain tick

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

	// ----------------------------------------------------------------------
	// Auto-activation helpers
	// ----------------------------------------------------------------------

	int GetClientObject()
	{
		if (IsBadReadPtr((const void*)CLIENT_GLOBAL_ADDRESS, sizeof(int)))
			return 0;
		return *(int*)CLIENT_GLOBAL_ADDRESS;
	}

	bool IsClientValid(int client)
	{
		return client != 0 && !IsBadReadPtr((const void*)(client + CLIENT_XP_BAR_OFFSET), 4);
	}

	// Mirrors the game's is-hunting check (FUN_0111621f) with plain reads.
	bool IsHunting()
	{
		int client = GetClientObject();
		if (!IsClientValid(client))
			return false;
		if (IsBadReadPtr((const void*)(client + CLIENT_AUTO_BATTLE_BYTE_OFFSET), 1))
			return false;
		if (*(unsigned char*)(client + CLIENT_AUTO_BATTLE_BYTE_OFFSET) == 0)
			return false;

		if (IsBadReadPtr((const void*)MANAGER_GLOBAL_ADDRESS, sizeof(int)))
			return false;
		int manager = *(int*)MANAGER_GLOBAL_ADDRESS;
		if (manager == 0 || IsBadReadPtr((const void*)(manager + MANAGER_HUNTING_BYTE_OFFSET), 1))
			return false;
		return *(unsigned char*)(manager + MANAGER_HUNTING_BYTE_OFFSET) != 0;
	}

	unsigned int GetXpBarValue(int client)
	{
		return *(unsigned int*)(client + CLIENT_XP_BAR_OFFSET);
	}

	unsigned int GetSelfUid(int client)
	{
		if (IsBadReadPtr((const void*)(client + CLIENT_SELF_UID_OFFSET), 4))
			return 0;
		return *(unsigned int*)(client + CLIENT_SELF_UID_OFFSET);
	}

	// Exactly what clicking the lit XP icon runs (FUN_00b811a4):
	//   FUN_011b1ec9 __thiscall(ECX = client, 0x5FDC, selfUid, 0, 1)
	void FireXpSkill(int client)
	{
		unsigned int selfUid = GetSelfUid(client);
		if (selfUid == 0)
			return;
		if (IsBadReadPtr((const void*)USE_SKILL_ON_TARGET_FUNC, 1))
			return;

		uintptr_t useSkillFunc = USE_SKILL_ON_TARGET_FUNC;
		__asm
		{
			push 1            // show-error flag (the icon handler passes 1)
			push 0
			push selfUid
			push 0x5FDC       // XP_PSEUDO_MAGIC_ID
			mov  ecx, client
			call useSkillFunc
		}
	}

	// Per-frame driver (runs from HookedEndScene = the game's own thread, like
	// the auto-hunt state assertion). Pops the XP skill the moment the bar
	// reads full; the server then resets the bar, which throttles the next
	// pop naturally.
	void AutoXpTick()
	{
		if (!g_autoXpSkill)
			return;

		// Same-build proof: the function address only gets called when the
		// gate-patch bytes match this build (or are already applied).
		if (!g_patchesApplied && !IsClientSupported())
		{
			g_autoXpSkill = false;  // unknown build - stay off
			return;
		}

		int client = GetClientObject();
		if (!IsClientValid(client))
			return;

		if (g_autoXpOnlyWhileHunting && !IsHunting())
			return;

		if (GetXpBarValue(client) < 100)
			return;

		DWORD now = GetTickCount();
		if (now - g_lastFireAttempt < FIRE_INTERVAL_MS)
			return;
		g_lastFireAttempt = now;

		FireXpSkill(client);
		g_fireCount++;
	}
}

// Free wrapper so imgui_interface.cpp can run the per-frame auto-pop tick
// (like ApplyAutoHuntClientState for the hunt flags).
void ApplyXpSkillClientState()
{
	XpSkill::AutoXpTick();
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

	ImGui::Spacing();

	// Auto-pop. Enabling it also turns the unlock on: without the fill patch
	// the bar never charges while hunting, so auto-pop could never trigger.
	if (ImGui::Checkbox("Auto XP skill when bar is full", &XpSkill::g_autoXpSkill))
	{
		if (XpSkill::g_autoXpSkill)
		{
			if (!XpSkill::g_allowXpSkills)
			{
				XpSkill::g_allowXpSkills = true;
				XpSkill::ApplyXpSkillState();
			}
		}
		else
		{
			XpSkill::g_fireCount = 0;
		}
	}

	if (XpSkill::g_autoXpSkill)
	{
		ImGui::Checkbox("Only while auto-hunting", &XpSkill::g_autoXpOnlyWhileHunting);

		int client = XpSkill::GetClientObject();
		if (XpSkill::IsClientValid(client))
		{
			ImGui::Text("XP bar: %u / 100", XpSkill::GetXpBarValue(client));
			ImGui::Text("XP pops sent: %lu", XpSkill::g_fireCount);
		}
	}

	ImGui::TextDisabled("Auto-casts your class XP skill (Superman / Fatal Strike / ...)");
}
