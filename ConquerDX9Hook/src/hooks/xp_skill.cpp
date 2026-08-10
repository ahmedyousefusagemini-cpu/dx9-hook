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
//    (Superman / Fatal Strike / any class XP skill) automatically:
//      - XP bar value: *(uint*)(client + 0xaec); full at 100 (FUN_011154f5
//        clamps to 100 and treats 99 < bar as full).
//      - Which skill: FUN_011a92b4(client, &out, magicId) is the client's own
//        learned-magic lookup (scans the vector at client+0x1d88..+0x1d8c).
//        out[0] != 0 = learned; out[1] is an intrusive refcount block released
//        with FUN_00420f03 (__fastcall, ECX = block).
//      - The XP-skill hotkey dispatcher (FUN_00a1d6bc) knows exactly seven
//        self-cast XP skill ids - it compares the current skill's +0x5c field
//        against each and fires the match at the self UID:
//          0x2845, 0x2B34, 0x2B2A, 0x2D5A, 0x3002, 0x323C, 0x3DA4
//        We probe them with the lookup and use the first the character knows,
//        so every class (warrior Superman, trojan Fatal Strike, ...) works
//        with no hardcoded per-class table.
//      - Activation mirrors the dispatcher / hunt brain (FUN_00f54058) call:
//          FUN_011b1ec9  __thiscall(ECX = client, magicId, selfUid, 0, 1)
//        with selfUid = *(uint*)(client + 0x268).
//
//    The use-skill gates above are already patched by (1), so the pop works
//    while hunting. Server unaffected: the 0x855 packet stays withheld, so
//    the XP pop is treated as normal gameplay.
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
	const uintptr_t MAGIC_LOOKUP_FUNC        = 0x011A92B4;  // FUN_011a92b4
	const uintptr_t REF_RELEASE_FUNC         = 0x00420F03;  // FUN_00420f03

	const size_t CLIENT_XP_BAR_OFFSET          = 0xaec;   // 0-100, full at 100
	const size_t CLIENT_SELF_UID_OFFSET        = 0x268;   // own role/UID
	const size_t CLIENT_AUTO_BATTLE_BYTE_OFFSET = 0x5385; // auto-battle flag
	const size_t MANAGER_HUNTING_BYTE_OFFSET   = 0x11;    // hunting-active flag

	// The seven self-cast XP skill ids from the hotkey dispatcher FUN_00a1d6bc.
	const unsigned int XP_SKILL_IDS[] =
		{ 0x2845, 0x2B34, 0x2B2A, 0x2D5A, 0x3002, 0x323C, 0x3DA4 };

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
	unsigned int g_detectedXpSkillId = 0;   // cached result of the learned-magic scan
	DWORD g_lastDetectScan = 0;
	DWORD g_lastFireAttempt = 0;
	const DWORD DETECT_INTERVAL_MS = 3000;  // re-scan learned magics slowly
	const DWORD FIRE_INTERVAL_MS   = 1000;  // same cadence as the hunt brain tick

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

	// The client's own learned-magic lookup:
	//   void __thiscall FUN_011a92b4(client, CSmartPtr out[2], int magicId)
	// out[0] != 0 means the character knows the magic; out[1] is a refcount
	// block that must be released with FUN_00420f03 (__fastcall, ECX = block).
	bool HasMagic(int client, unsigned int magicId)
	{
		if (IsBadReadPtr((const void*)MAGIC_LOOKUP_FUNC, 1))
			return false;

		void* result[2] = { 0, 0 };
		uintptr_t lookupFunc = MAGIC_LOOKUP_FUNC;
		__asm
		{
			push magicId
			lea  eax, result
			push eax
			mov  ecx, client
			call lookupFunc
		}

		bool known = (result[0] != 0);
		if (result[1] != 0)
		{
			void* refBlock = result[1];
			uintptr_t releaseFunc = REF_RELEASE_FUNC;
			__asm
			{
				mov  ecx, refBlock
				call releaseFunc
			}
		}
		return known;
	}

	// First XP skill the character has learned, or 0.
	unsigned int DetectXpSkill(int client)
	{
		for (int i = 0; i < _countof(XP_SKILL_IDS); i++)
		{
			if (HasMagic(client, XP_SKILL_IDS[i]))
				return XP_SKILL_IDS[i];
		}
		return 0;
	}

	// Exactly what the dispatcher and the hunt brain run:
	//   FUN_011b1ec9 __thiscall(ECX = client, magicId, targetUid, 0, 1)
	void FireXpSkill(int client, unsigned int magicId)
	{
		unsigned int selfUid = GetSelfUid(client);
		if (selfUid == 0)
			return;
		if (IsBadReadPtr((const void*)USE_SKILL_ON_TARGET_FUNC, 1))
			return;

		uintptr_t useSkillFunc = USE_SKILL_ON_TARGET_FUNC;
		__asm
		{
			push 1            // show-error flag (client's own XP call passes 1)
			push 0
			push selfUid
			push magicId
			mov  ecx, client
			call useSkillFunc
		}
	}

	// Per-frame driver (runs from HookedEndScene = the game's own thread, like
	// the auto-hunt state assertion). Fires the detected XP skill the moment
	// the bar reads full; the server then resets the bar, which throttles the
	// next pop naturally.
	void AutoXpTick()
	{
		if (!g_autoXpSkill)
			return;

		// Same-build proof: the function addresses only get called when the
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

		DWORD now = GetTickCount();

		// Re-scan slowly: cheap, and picks up relogs / class changes.
		if (now - g_lastDetectScan >= DETECT_INTERVAL_MS)
		{
			g_lastDetectScan = now;
			g_detectedXpSkillId = DetectXpSkill(client);
		}
		if (g_detectedXpSkillId == 0)
			return;

		if (GetXpBarValue(client) < 100)
			return;

		if (now - g_lastFireAttempt < FIRE_INTERVAL_MS)
			return;
		g_lastFireAttempt = now;

		FireXpSkill(client, g_detectedXpSkillId);
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
			XpSkill::g_detectedXpSkillId = 0;
		}
	}

	if (XpSkill::g_autoXpSkill)
	{
		ImGui::Checkbox("Only while auto-hunting", &XpSkill::g_autoXpOnlyWhileHunting);

		int client = XpSkill::GetClientObject();
		if (XpSkill::IsClientValid(client))
		{
			ImGui::Text("XP bar: %u / 100", XpSkill::GetXpBarValue(client));
			if (XpSkill::g_detectedXpSkillId != 0)
				ImGui::Text("XP skill: 0x%04X (auto-detected)", XpSkill::g_detectedXpSkillId);
			else
				ImGui::TextDisabled("XP skill: scanning...");
		}
	}

	ImGui::TextDisabled("Auto-casts your class XP skill (Superman / Fatal Strike / ...)");
}
