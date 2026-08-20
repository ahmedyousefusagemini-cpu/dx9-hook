#include <windows.h>
#include <stdint.h>
#include <cstdio>
#include <string.h>
#include "imgui.h"
#include "MinHook.h"

// Shared lookups from buffs.cpp and xp_skill.cpp - the auto-swap trigger:
//   XP icon on screen -> wear alternate gear
//   XP buff status active -> back to main gear.
extern bool IsStatusActive(int statusId);
extern unsigned int GetXpBarValue();

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
// runs. This module wears ALT while the XP icon is on screen and switches back
// to MAIN the moment the XP skill activates:
//
//   - icon on screen (hooked directly, see below) -> wear ALT
//   - the XP buff status (configurable, default 47) sets = the skill
//     activated -> wear MAIN, held until the icon clears and re-appears
//
// Icon detection: the game's per-frame XP icon driver (FUN_0060AE62) feeds
// CDlgXp::update (FUN_00AE5FC7) whenever the icon logic is live. We MinHook
// that dispatcher, remember the CDlgXp instance, and each frame read its
// +0xAB0/+0xAB4 flags - the exact fields the game renders the icon from
// (set by every show path, cleared by every hide path). This is ground
// truth for "icon on screen" - no status-id guessing, so it is immune to
// the server's random timing between bar fill and icon pop, and to
// status-id differences between private servers.
// ============================================================================

namespace GearSwap
{
	// --- game constants (client 7937) --------------------------------------
	const uintptr_t HERO_GLOBAL_ADDRESS = 0x01A53980;  // DAT_01a53980 - CMyHero*
	const uintptr_t SWAP_FUNC           = 0x00FF219D;  // FUN_00ff219d - CMyHero::SwapEquipMode
	const size_t    EQUIP_MODE_OFFSET   = 0x193C;      // 0 = main, 1 = alternate

	// CDlgXp::update - the per-frame dispatcher the game's icon driver
	// (FUN_0060AE62, table-dispatched) calls while the XP icon is live. The
	// alternate show path in it bypasses FUN_00AE5B7B entirely (it moves the
	// window and draws directly), so hooking the dispatcher is the reliable
	// way to capture the CDlgXp instance. Prologue sanity bytes:
	//   6A 60                push 0x60
	//   B8 79 D6 32 01       mov  eax, 0x132D679
	const uintptr_t XP_ICON_UPDATE_FUNC = 0x00AE5FC7;
	const size_t    ICON_MODE_FLAG_OFFSET  = 0xAB0;  // show-mode flag (1 = icon up in any show path)
	const size_t    ICON_SHOWN_FLAG_OFFSET = 0xAB4;  // CDlgXp::show set it (1 = shown via the main path)
	const size_t    HWND_OFFSET            = 0x20;   // CWnd::m_hWnd (debug display only)

	// --- configuration -----------------------------------------------------
	bool g_autoSwap = false;
	int  g_xpBuffStatusId = 47;   // XP buff status id (server applies it as an icon status)

	// --- runtime state -----------------------------------------------------
	int  g_mode = -1;            // last read equip mode (-1 = unknown)
	unsigned int g_xpBar = 0;    // last poll: XP bar value (0-100)
	bool g_iconActive = false;   // last poll: XP icon window on screen?
	bool g_buffActive = false;   // last poll: XP buff status bit set?
	bool g_buffSeenThisFill = false; // the XP skill activated since the icon went up - hold MAIN
	int  g_pendingTarget = -1;   // swap in flight: 0 (main) / 1 (alt), -1 none
	DWORD g_lastSwapSent = 0;
	DWORD g_cooldownUntil = 0;
	unsigned long g_swapCount = 0;     // native swap calls issued
	unsigned long g_confirmCount = 0;  // flag flips observed
	unsigned long g_confirmFail = 0;   // timeouts waiting for the flip
	unsigned long g_skippedWhileBusy = 0;

	int  g_cdlgxp = 0;           // captured CDlgXp instance (from the show hook)
	bool g_iconHookInstalled = false;
	int  g_iconHookStatus = 0;

	char g_lastResult[48] = "idle";
	DWORD g_lastResultTick = 0;

	// --- XP icon visibility hook -------------------------------------------
	// FUN_00AE5FC7 is CDlgXp::update (this in ECX, param_2 = mode, param_3 =
	// feature flag). The game's per-frame icon driver (FUN_0060AE62) calls it
	// whenever the XP icon logic is live (status 27 active OR the client's own
	// +0x4096A8 flag set), so this hook captures the CDlgXp instance and runs
	// every frame the icon is being managed - including the alternate show
	// path that never touches FUN_00AE5B7B.
	typedef void (__thiscall* XpIconUpdateFn)(void* self, int mode, int feature);
	static XpIconUpdateFn s_originalXpIconUpdate = nullptr;
	unsigned long g_iconHookFired = 0;   // detour call counter (diagnostic)

	void __fastcall HkXpIconUpdate(void* self, void* /*edx*/, int mode, int feature)
	{
		GearSwap::g_cdlgxp = (int)self;
		GearSwap::g_iconHookFired++;
		if (s_originalXpIconUpdate)
			s_originalXpIconUpdate(self, mode, feature);
	}

	void EnsureIconHookInstalled()
	{
		if (g_iconHookInstalled)
			return;
		const unsigned char* p = (const unsigned char*)XP_ICON_UPDATE_FUNC;
		if (IsBadReadPtr(p, 8))
			return;
		// Prologue must match the static binary or the hook would land on the
		// wrong code (client builds / packer variants shift addresses).
		if (p[0] != 0x6A || p[1] != 0x60 || p[2] != 0xB8 ||
			p[3] != 0x79 || p[4] != 0xD6 || p[5] != 0x32 || p[6] != 0x01)
			return;
		g_iconHookStatus = MH_Initialize();
		if (g_iconHookStatus != MH_OK && g_iconHookStatus != MH_ERROR_ALREADY_INITIALIZED)
			return;
		g_iconHookStatus = MH_CreateHook((LPVOID)XP_ICON_UPDATE_FUNC, &HkXpIconUpdate, (LPVOID*)&s_originalXpIconUpdate);
		if (g_iconHookStatus != MH_OK)
			return;
		g_iconHookStatus = MH_EnableHook((LPVOID)XP_ICON_UPDATE_FUNC);
		if (g_iconHookStatus != MH_OK)
			return;
		g_iconHookInstalled = true;
	}

	// Ground-truth check: the icon window's own flags on the captured CDlgXp
	// instance. Every show path leaves a marker behind: the main path
	// (FUN_00AE5B7B) sets +0xAB4 = 1, the alternate path sets +0xAB0 = 1; all
	// hide paths clear both. So "icon on screen" = either flag non-zero.
	bool IsXpIconVisible()
	{
		if (!g_cdlgxp || IsBadReadPtr((const void*)g_cdlgxp, ICON_SHOWN_FLAG_OFFSET + sizeof(int)))
			return false;
		int mode = *(int*)(g_cdlgxp + ICON_MODE_FLAG_OFFSET);
		int shown = *(int*)(g_cdlgxp + ICON_SHOWN_FLAG_OFFSET);
		return mode != 0 || shown != 0;
	}

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

		EnsureIconHookInstalled();
		if (!g_iconHookInstalled)
		{
			g_autoSwap = false;   // icon detection unavailable - stay off
			SetResult("XP icon hook failed");
			return;
		}

		g_mode = GetEquipMode(hero);
		g_xpBar = GetXpBarValue();
		g_iconActive = IsXpIconVisible();
		g_buffActive = IsStatusActive(g_xpBuffStatusId);
		DWORD now = GetTickCount();

		// The XP icon window's real on-screen state (IsWindowVisible on the
		// CDlgXp HWND, captured by the show hook). The server pops the icon at
		// its own timing after the bar fills; wear ALT from the moment the
		// icon is actually visible, and once the XP skill activates (buff
		// status) go back to MAIN, held until the icon clears and re-appears.
		if (!g_iconActive)
			g_buffSeenThisFill = false;   // icon gone - re-arm for the next pop
		if (g_buffActive)
			g_buffSeenThisFill = true;    // activated - back to MAIN

		bool altWanted = g_iconActive && !g_buffSeenThisFill;
		int desired = altWanted ? 1 : 0;

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

	if (ImGui::Checkbox("Auto swap on XP icon", &GearSwap::g_autoSwap))
	{
		if (!GearSwap::g_autoSwap)
			GearSwap::g_pendingTarget = -1;
	}

	if (GearSwap::g_autoSwap)
	{
		ImGui::TextDisabled("XP icon on screen -> wear ALT;");
		ImGui::TextDisabled("skill activated (buff) -> MAIN, held until the icon clears.");

		int statusId = GearSwap::g_xpBuffStatusId;
		if (ImGui::InputInt("XP buff status id", &statusId))
		{
			if (statusId < 0)
				statusId = 0;
			if (statusId > 575)
				statusId = 575;
			GearSwap::g_xpBuffStatusId = statusId;
		}
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
		ImGui::Text("XP bar: %u / 100", GearSwap::g_xpBar);
		ImGui::Text("XP icon: %s", GearSwap::g_iconActive ? "ON SCREEN" : "off");
		ImGui::Text("Status %d (XP buff): %s", GearSwap::g_xpBuffStatusId,
			GearSwap::g_buffActive ? "ACTIVE" : "off");
		if (GearSwap::g_autoSwap && GearSwap::g_iconActive && !GearSwap::g_buffSeenThisFill)
		{
			ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.3f, 1.0f),
				"XP icon up - wearing ALT until the skill activates");
		}
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
			ImGui::Text("XP icon hook: %s (status %d, fired %lu)",
				GearSwap::g_iconHookInstalled ? "installed" : "not installed",
				GearSwap::g_iconHookStatus, GearSwap::g_iconHookFired);
			ImGui::Text("CDlgXp: 0x%08X", (unsigned int)GearSwap::g_cdlgxp);
			if (GearSwap::g_cdlgxp)
			{
				ImGui::Text("icon flags: mode(+0xAB0)=%d shown(+0xAB4)=%d",
					*(int*)(GearSwap::g_cdlgxp + GearSwap::ICON_MODE_FLAG_OFFSET),
					*(int*)(GearSwap::g_cdlgxp + GearSwap::ICON_SHOWN_FLAG_OFFSET));
				HWND hwnd = *(HWND*)(GearSwap::g_cdlgxp + GearSwap::HWND_OFFSET);
				ImGui::Text("icon HWND: 0x%08X visible=%d", (unsigned int)hwnd,
					hwnd ? (IsWindowVisible(hwnd) != FALSE) : 0);
			}
			ImGui::TreePop();
		}
	}
	else
	{
		ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f),
			"(enter the game - no character object yet)");
	}
}