#include <windows.h>
#include <stdint.h>
#include "imgui.h"

// Shared status lookups from buffs.cpp (names from ini/Cn_Res.ini, live
// buff timers from the active-icon vectors).
extern const char* GetStatusName(int statusId);
extern unsigned long GetStatusEndMs(int statusId);

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
// 2) "Auto XP skill when bar is full" (v3) - pops the character's XP skill(s)
//    (Superman / Fatal Strike / any class, MULTIPLE per character) as the bar
//    fills.
//
//    Detection = enumerate the learned-magic list directly (no id guessing):
//      - vector at client+0x1D88 (begin) / client+0x1D8C (end), 8-byte
//        entries, entry[0] = learned-magic record ptr (from the disassembly of
//        the client's own lookup FUN_011a92b4).
//      - record + 0x70 = its magic-info struct (FUN_00d9612c = this + 0x70;
//        the lookup compares info+0x5C against the id - CMP at 0x011A930F).
//      - info+0x5C = magic type id, info+0x30 = 1 for XP-type skills (same
//        layout as the current-skill struct the use-skill gates check).
//      - 0x5FDC = the generic XP-skill pseudo id the XP icon click handler
//        (FUN_00b811a4) fires; when present in the list it goes first.
//
//    Activation mirrors the icon handler / dispatcher exactly:
//        FUN_011b1ec9  __thiscall(ECX = client, magicId, selfUid, 0, 1)
//      selfUid = *(uint*)(client + 0x268).
//
//    Fire control: one pop per bar fill - after firing we wait for the bar to
//    drop below 100 (the server resets it on a pop) before re-arming, with a
//    5s retry in case a pop was rejected. Multiple XP skills are rotated
//    round-robin, one per fill. Max one attempt per second.
//
//    The use-skill gates above are already patched by (1), and the
//    FUN_011b1ec9 gate reads the CURRENT skill's +0x30 (the attack skill
//    while hunting), so the pop works during auto-hunt either way. Server
//    unaffected: the 0x855 packet stays withheld.
// ============================================================================

namespace XpSkill
{
	// --- Gate patch sites (feature 1) ---
	const uintptr_t XP_FILL_GATE_ADDRESS      = 0x01115514;  // FUN_011154f5 - JNZ skip-fill
	const uintptr_t USE_TARGET_GATE_ADDRESS   = 0x011B21D8;  // FUN_011b1ec9 - JZ skip-block
	const uintptr_t USE_POSITION_GATE_ADDRESS = 0x011B3B21;  // FUN_011b3503 - JZ skip-block

	// --- Addresses (feature 2) ---
	const uintptr_t CLIENT_GLOBAL_ADDRESS    = 0x01A52960;  // DAT_01a52960 - client object*
	const uintptr_t MANAGER_GLOBAL_ADDRESS   = 0x01A531E0;  // DAT_01a531e0 - CAutoHangUpMgr*
	const uintptr_t USE_SKILL_ON_TARGET_FUNC = 0x011B1EC9;  // FUN_011b1ec9

	const size_t CLIENT_XP_BAR_OFFSET          = 0xaec;   // 0-100, full at 100
	const size_t CLIENT_SELF_UID_OFFSET        = 0x268;   // own role/UID
	const size_t CLIENT_AUTO_BATTLE_BYTE_OFFSET = 0x5385; // auto-battle flag
	const size_t MANAGER_HUNTING_BYTE_OFFSET   = 0x11;    // hunting-active flag

	// Learned-magic list (from the FUN_011a92b4 disassembly).
	const size_t CLIENT_MAGIC_VEC_BEGIN_OFFSET = 0x1d88;  // vector begin
	const size_t CLIENT_MAGIC_VEC_END_OFFSET   = 0x1d8c;  // vector end
	const size_t MAGIC_RECORD_INFO_OFFSET      = 0x70;    // FUN_00d9612c = this + 0x70
	const size_t MAGIC_INFO_ID_OFFSET          = 0x5c;    // magic type id
	const size_t MAGIC_INFO_IS_XP_OFFSET       = 0x30;    // 1 = XP-type skill

	// The generic XP-skill pseudo magic id the XP icon click handler
	// (FUN_00b811a4) fires; the server maps it to the class XP skill.
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

	const DWORD FIRE_INTERVAL_MS      = 1000;  // same cadence as the hunt brain tick
	const DWORD RETRY_INTERVAL_MS     = 5000;  // re-fire if the bar never dropped
	const DWORD LIST_SCAN_INTERVAL_MS = 5000;  // re-enumerate learned magics slowly

	const unsigned int MAX_XP_IDS = 32;
	unsigned int  g_xpIds[32];           // detected XP skills (fire list)
	unsigned int  g_xpIdCount = 0;
	unsigned int  g_rotateIdx = 0;       // round-robin over g_xpIds
	unsigned int  g_learnedCount = 0;    // total learned magics (debug display)
	DWORD         g_lastListScan = 0;
	DWORD         g_lastFireAttempt = 0;
	bool          g_waitingReset = false; // fired; waiting for the bar to drop
	unsigned int  g_lastFiredId = 0;
	unsigned long g_fireCount = 0;

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

	// Enumerate the learned-magic vector and rebuild the XP fire list.
	// Pure memory reads - no game calls, no smart-pointer dance.
	void ScanMagics(int client)
	{
		g_xpIdCount = 0;
		g_learnedCount = 0;
		bool pseudoKnown = false;

		if (IsBadReadPtr((const void*)(client + CLIENT_MAGIC_VEC_BEGIN_OFFSET), 8))
			return;

		uintptr_t begin = *(uintptr_t*)(client + CLIENT_MAGIC_VEC_BEGIN_OFFSET);
		uintptr_t end   = *(uintptr_t*)(client + CLIENT_MAGIC_VEC_END_OFFSET);
		if (begin == 0 || end < begin)
			return;
		uintptr_t bytes = end - begin;
		if ((bytes & 7) != 0 || bytes > 0x8000)   // sanity: 8-byte entries, sane size
			return;

		for (uintptr_t entry = begin; entry < end; entry += 8)
		{
			if (IsBadReadPtr((const void*)entry, 8))
				break;
			uintptr_t record = *(uintptr_t*)entry;   // entry[0] = record ptr
			if (record == 0)
				continue;
			g_learnedCount++;

			uintptr_t info = record + MAGIC_RECORD_INFO_OFFSET;
			if (IsBadReadPtr((const void*)(info + MAGIC_INFO_ID_OFFSET), 4))
				continue;
			unsigned int id = *(unsigned int*)(info + MAGIC_INFO_ID_OFFSET);
			if (id == XP_PSEUDO_MAGIC_ID)
				pseudoKnown = true;

			if (IsBadReadPtr((const void*)(info + MAGIC_INFO_IS_XP_OFFSET), 4))
				continue;
			if (*(unsigned int*)(info + MAGIC_INFO_IS_XP_OFFSET) != 1)
				continue;

			bool exists = false;
			for (unsigned int i = 0; i < g_xpIdCount; i++)
				if (g_xpIds[i] == id) { exists = true; break; }
			if (!exists && g_xpIdCount < MAX_XP_IDS)
				g_xpIds[g_xpIdCount++] = id;
		}

		// The icon's pseudo id always works when the character has it - keep it
		// at the front of the rotation.
		if (pseudoKnown && g_xpIdCount < MAX_XP_IDS)
		{
			bool exists = false;
			for (unsigned int i = 0; i < g_xpIdCount; i++)
				if (g_xpIds[i] == XP_PSEUDO_MAGIC_ID) { exists = true; break; }
			if (!exists)
			{
				for (unsigned int i = g_xpIdCount; i > 0; i--)
					g_xpIds[i] = g_xpIds[i - 1];
				g_xpIds[0] = XP_PSEUDO_MAGIC_ID;
				g_xpIdCount++;
			}
		}

		if (g_rotateIdx >= g_xpIdCount)
			g_rotateIdx = 0;
	}

	// Exactly what the XP icon handler / dispatcher run:
	//   FUN_011b1ec9 __thiscall(ECX = client, magicId, targetUid, 0, 1)
	void FireMagic(int client, unsigned int magicId)
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
			push magicId
			mov  ecx, client
			call useSkillFunc
		}
	}

	// Per-frame driver (runs from HookedEndScene = the game's own thread, like
	// the auto-hunt state assertion).
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

		DWORD now = GetTickCount();

		// Re-enumerate the learned magics slowly (picks up relogs/class changes).
		if (now - g_lastListScan >= LIST_SCAN_INTERVAL_MS)
		{
			g_lastListScan = now;
			ScanMagics(client);
		}

		unsigned int bar = GetXpBarValue(client);

		// One pop per fill: after firing, wait for the server to consume the bar
		// (value drops below 100) before re-arming. If it never drops, the pop
		// was likely rejected - re-arm after a timeout and try again.
		if (g_waitingReset)
		{
			if (bar < 100)
				g_waitingReset = false;
			else if (now - g_lastFireAttempt >= RETRY_INTERVAL_MS)
				g_waitingReset = false;
			else
				return;
		}

		if (bar < 100)
			return;
		if (g_xpIdCount == 0)
			return;
		if (now - g_lastFireAttempt < FIRE_INTERVAL_MS)
			return;

		unsigned int id = g_xpIds[g_rotateIdx % g_xpIdCount];
		g_lastFireAttempt = now;

		FireMagic(client, id);

		g_lastFiredId = id;
		g_fireCount++;
		g_rotateIdx++;
		g_waitingReset = true;
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
			XpSkill::g_lastFiredId = 0;
			XpSkill::g_waitingReset = false;
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
			if (XpSkill::g_lastFiredId != 0)
				ImGui::Text("Last pop id: 0x%04X", XpSkill::g_lastFiredId);

			if (ImGui::TreeNode("XP Debug"))
			{
				ImGui::Text("Learned magics: %u", XpSkill::g_learnedCount);
				ImGui::Text("XP skills found: %u", XpSkill::g_xpIdCount);
				// XP skills apply statuses with the same id, so the STATUSTIPS
				// name (ini/Cn_Res.ini) and the live buff timer apply to them.
				for (unsigned int i = 0; i < XpSkill::g_xpIdCount; i++)
				{
					unsigned int id = XpSkill::g_xpIds[i];
					const char* name = GetStatusName((int)id);
					unsigned long endMs = GetStatusEndMs((int)id);
					unsigned long now = GetTickCount();
					if (name && endMs != 0 && now < endMs)
					{
						unsigned long secs = (endMs - now + 500) / 1000;
						ImGui::BulletText("%s (0x%04X) - buff active, %lu s", name, id, secs);
					}
					else if (name)
					{
						ImGui::BulletText("%s (0x%04X)", name, id);
					}
					else
					{
						ImGui::BulletText("0x%04X", id);
					}
				}
				if (XpSkill::g_xpIdCount == 0)
					ImGui::TextDisabled("(none detected - list rescans every 5s)");
				ImGui::TreePop();
			}
		}
	}

	ImGui::TextDisabled("Auto-casts your XP skills (Superman / Fatal Strike / ...)");
	ImGui::TextDisabled("Characters with several XP skills rotate through them all.");
}
