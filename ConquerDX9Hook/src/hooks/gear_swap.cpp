#include <windows.h>
#include <stdint.h>
#include <cstdio>
#include <string.h>
#include "imgui.h"

// Shared lookups from buffs.cpp - the auto-swap trigger is an XP-style buff:
// a status whose bit is set AND that has a magic-derived duration registered
// (XP skills apply statuses without creating icons).
extern bool IsXpStyleBuffActive();

// ============================================================================
// Auto Gear Swap - Conquer.exe client 7937 (image base 0x400000)
// ----------------------------------------------------------------------------
// The client has a native "switch to alternate equipment" feature (the fgui
// swap button, STR_SWAP_SUB_WEAPONBTNTIP). Reverse-engineered chain:
//
//   Swapuse_SwapmainbBtn click
//     -> 0x00A58AA8  (button dispatcher: MOV ECX,EAX after FUN_0043e581)
//     -> FUN_00FF219D  CMyHero::SwapEquipMode  (heroitem.cpp)
//          this = FUN_0043e581() -> DAT_01a53980 (CMyHero singleton)
//          equip mode flag at hero+0x193C: 0 = main, 1 = alternate
//          if (mode == 0) send CMsgItem{action=0x2D}  (0x97B)  // swap to ALT
//                         + CMsgAction{action=0x198} (0x833)  // equip refresh
//          if (mode == 1) send CMsgItem{action=0x2C}  (0x97B)  // swap to MAIN
//                         + CMsgAction{action=0x198} (0x833)
//     -> server replies; inbound CMsgItem::Process (FUN_00F0959C) re-renders
//        all 8 equipment slots (FUN_00ff1eff clear + FUN_00ff49c4 set pairs).
//
// So the complete native swap = FUN_00FF219D(hero) - exactly what the button
// runs. This module just calls it when an XP-style buff becomes active
// (gear -> ALT) and again when it clears (gear -> MAIN), waiting for the
// +0x193C flag to flip before re-arming.
// ============================================================================

namespace GearSwap
{
	// --- game constants (client 7937) --------------------------------------
	const uintptr_t HERO_GLOBAL_ADDRESS = 0x01A53980;  // DAT_01a53980 - CMyHero*
	const uintptr_t SWAP_FUNC           = 0x00FF219D;  // FUN_00ff219d - CMyHero::SwapEquipMode
	const size_t    EQUIP_MODE_OFFSET   = 0x193C;      // 0 = main, 1 = alternate

	// --- configuration -----------------------------------------------------
	bool g_autoSwap = false;
	bool g_wearAltOnXp = true;   // true: XP buff -> ALT gear, cleared -> MAIN

	// --- runtime state -----------------------------------------------------
	int  g_mode = -1;            // last read equip mode (-1 = unknown)
	bool g_xpActive = false;     // last poll: XP-style buff active?
	int  g_pendingTarget = -1;   // swap in flight: 0 (main) / 1 (alt), -1 none
	DWORD g_lastSwapSent = 0;
	DWORD g_cooldownUntil = 0;
	unsigned long g_swapCount = 0;     // native swap calls issued
	unsigned long g_confirmCount = 0;  // flag flips observed
	unsigned long g_confirmFail = 0;   // timeouts waiting for the flip
	unsigned long g_skippedWhileBusy = 0;

	char g_lastResult[48] = "idle";
	DWORD g_lastResultTick = 0;

	// --- sanity / support --------------------------------------------------

	bool IsHeroSupported()
	{
		// Prologue of FUN_00ff219d (verified byte-for-byte):
		//   68 4C 09 00 00          push 0x94C                       @ 0x00
		//   B8 F6 E7 4A 01          mov  eax, 0x14AE7F6             @ 0x05
		//   E8 DD ED 26 00          call __EH_prolog3_GS            @ 0x0A
		//   8B F1                   mov  esi, ecx                   @ 0x0F
		//   8B 86 3C 19 00 00       mov  eax, [esi+0x193C]          @ 0x11  <- the mode read
		const unsigned char* p = (const unsigned char*)SWAP_FUNC;
		if (IsBadReadPtr(p, 0x18))
			return false;
		if (p[0] != 0x68 || p[1] != 0x4C)
			return false;
		if (p[0x0F] != 0x8B || p[0x10] != 0xF1)
			return false;
		if (p[0x11] != 0x8B || p[0x12] != 0x86 || p[0x14] != 0x19)
			return false;
		return true;
	}

	int GetHero()
	{
		if (IsBadReadPtr((const void*)HERO_GLOBAL_ADDRESS, sizeof(int)))
			return 0;
		int hero = *(int*)HERO_GLOBAL_ADDRESS;
		if (hero == 0 || IsBadReadPtr((const void*)(hero + EQUIP_MODE_OFFSET), 4))
			return 0;
		return hero;
	}

	int GetEquipMode(int hero)
	{
		return *(int*)(hero + EQUIP_MODE_OFFSET);
	}

	void SetResult(const char* text)
	{
		strncpy_s(g_lastResult, text, sizeof(g_lastResult) - 1);
		g_lastResultTick = GetTickCount();
	}

	// The native swap: FUN_00FF219D(ECX = hero), no stack args. Sends the
	// right CMsgItem action (0x2D to ALT / 0x2C to MAIN) + equip refresh.
	void SendNativeSwap(int hero)
	{
		typedef void (__fastcall* SwapEquipModeFn)(void* hero);
		SwapEquipModeFn swap = (SwapEquipModeFn)SWAP_FUNC;
		swap((void*)hero);
	}

	// Requests a swap toward `target` (0 = main, 1 = alt). Respects the
	// cooldown so a fast XP on/off flicker cannot spam the server.
	void RequestSwap(int hero, int target)
	{
		DWORD now = GetTickCount();
		if (now < g_cooldownUntil)
		{
			g_skippedWhileBusy++;
			return;
		}
		SendNativeSwap(hero);
		g_pendingTarget = target;
		g_lastSwapSent = now;
		g_cooldownUntil = now + 1500;
		g_swapCount++;
		SetResult("swap sent");
	}

	// Per-frame driver (runs from HookedEndScene = the game's own thread).
	void AutoSwapTick()
	{
		if (!g_autoSwap)
			return;

		if (!IsHeroSupported())
		{
			g_autoSwap = false;   // unknown build - stay off
			SetResult("unsupported client build");
			return;
		}

		int hero = GetHero();
		if (!hero)
			return;
		g_mode = GetEquipMode(hero);
		g_xpActive = IsXpStyleBuffActive();

		int desired = g_wearAltOnXp ? (g_xpActive ? 1 : 0) : (g_xpActive ? 0 : 1);
		DWORD now = GetTickCount();

		// A swap is in flight - wait for the server round-trip. The client
		// flips hero+0x193C when the reply lands (the same flag the button's
		// swap reads to pick the direction), so a flip confirms the swap.
		if (g_pendingTarget >= 0)
		{
			if (g_mode == g_pendingTarget)
			{
				g_pendingTarget = -1;
				g_confirmCount++;
				g_confirmFail = 0;   // a real flip resets the timeout streak
				SetResult("swap confirmed");
			}
			else if (now - g_lastSwapSent >= 5000)
			{
				g_pendingTarget = -1;
				g_confirmFail++;
				if (g_confirmFail >= 2)
				{
					// Two timeouts in a row: the server never flips the mode
					// flag (private servers may not reply). Stop spamming it.
					g_autoSwap = false;
					SetResult("no server reply - auto-swap stopped");
					return;
				}
				SetResult("no server reply - will retry");
			}
			else
			{
				return;   // still waiting
			}
		}

		if (g_mode == desired)
			return;
		if (g_mode != 0 && g_mode != 1)
		{
			g_autoSwap = false;   // unexpected value - refuse to act
			SetResult("unexpected equip mode - stopped");
			return;
		}

		RequestSwap(hero, desired);
	}
}

// Free wrapper so imgui_interface.cpp can run the per-frame auto-swap tick
// (like ApplyXpSkillClientState for the XP pop).
void ApplyGearSwapClientState()
{
	GearSwap::AutoSwapTick();
}

void RenderGearSwapInterface()
{
	ImGui::Text("Auto Gear Swap");
	ImGui::Separator();

	if (!GearSwap::IsHeroSupported())
	{
		ImGui::TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), "Unsupported client build - swap unavailable");
		return;
	}

	if (ImGui::Checkbox("Auto swap on XP buff", &GearSwap::g_autoSwap))
	{
		if (!GearSwap::g_autoSwap)
			GearSwap::g_pendingTarget = -1;
	}

	if (GearSwap::g_autoSwap)
	{
		ImGui::Checkbox("XP buff active -> wear alternate gear", &GearSwap::g_wearAltOnXp);

		ImGui::TextDisabled("Swaps to alternate equipment when an XP-style buff");
		ImGui::TextDisabled("starts, back to main equipment when it ends.");
	}

	ImGui::Spacing();

	int hero = GearSwap::GetHero();
	if (hero)
	{
		const char* modeName = GearSwap::g_mode == 0 ? "MAIN" :
			(GearSwap::g_mode == 1 ? "ALT" : "?");
		ImGui::Text("Equip mode: %s", modeName);
		ImGui::SameLine();
		ImGui::TextDisabled("(0x%08X)", (unsigned int)hero);
		ImGui::Text("XP buff active: %s", GearSwap::g_xpActive ? "YES" : "no");
		if (GearSwap::g_pendingTarget >= 0)
		{
			ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.3f, 1.0f), "Swap in flight -> %s...",
				GearSwap::g_pendingTarget == 1 ? "ALT" : "MAIN");
		}
		ImGui::Text("Last: %s", GearSwap::g_lastResult);
		ImGui::Text("Swaps sent: %lu | confirmed: %lu | timeouts: %lu | busy-skips: %lu",
			GearSwap::g_swapCount, GearSwap::g_confirmCount,
			GearSwap::g_confirmFail, GearSwap::g_skippedWhileBusy);

		ImGui::Spacing();
		ImGui::TextDisabled("Manual test:");
		if (ImGui::Button("Wear Main"))
			GearSwap::RequestSwap(hero, 0);
		ImGui::SameLine();
		if (ImGui::Button("Wear Alt"))
			GearSwap::RequestSwap(hero, 1);
		ImGui::SameLine();
		if (ImGui::Button("Force toggle"))
			GearSwap::RequestSwap(hero, GearSwap::g_mode == 1 ? 0 : 1);

		if (ImGui::TreeNode("Debug"))
		{
			ImGui::Text("hero+0x193C raw: %d", GearSwap::g_mode);
			ImGui::Text("pending target: %d", GearSwap::g_pendingTarget);
			ImGui::Text("last result at +%lums",
				GearSwap::g_lastResultTick ? GetTickCount() - GearSwap::g_lastResultTick : 0);
			ImGui::TreePop();
		}
	}
	else
	{
		ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f),
			"(enter the game - no character object yet)");
	}
}