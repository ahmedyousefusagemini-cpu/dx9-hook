#include <windows.h>
#include <stdint.h>
#include <cstdio>
#include <string.h>
#include "imgui.h"
#include "MinHook.h"

// Shared lookup from xp_skill.cpp - the XP bar value (same field the game's
// WndProc gates the icon show on: hero+0xAEC, 0-100).
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
// to MAIN the moment the icon goes away (the skill activation consumes it):
//
//   - icon on screen -> wear ALT
//   - icon gone (pop consumed) -> wear MAIN
//
// Icon detection: the modded client's main-window WndProc shows the XP icon
// when the hero has status 10 OR status 5 active - 0x00A653E4:
//   ChkStatus(hero, 0xA) || ChkStatus(hero, 0x5)
//     -> FUN_005F254F -> CDlgXp::SetBar(1) (+0xAA8 = 1, render XpSkillType0)
// and the hide handler FUN_005F25BA -> SetBar(0) clears it when the pop is
// consumed. ChkStatus (FUN_00F1AF78: ADD ECX,0x138) reads the 576-bit status
// bitfield at DAT_01a53980+0x138 - the exact object and field the game's own
// check uses. We mirror that read directly per frame: no hooks, no instance,
// immune to status-id differences between private servers (the ids are
// configurable in the UI).
// ============================================================================

namespace GearSwap
{
	// --- game constants (client 7937) --------------------------------------
	const uintptr_t HERO_GLOBAL_ADDRESS = 0x01A53980;  // DAT_01a53980 - CMyHero*
	const uintptr_t SWAP_FUNC           = 0x00FF219D;  // FUN_00ff219d - CMyHero::SwapEquipMode
	const size_t    EQUIP_MODE_OFFSET   = 0x193C;      // 0 = main, 1 = alternate

	// The hero's 576-bit status bitfield. The game's own ChkStatus
	// (FUN_00F1AF78: ADD ECX,0x138) reads it from DAT_01a53980+0x138, and the
	// bit layout (from FUN_00D4ED8E) is: bit (id & 63) of 64-bit word (id >> 6),
	// i.e. ((unsigned long long*)(hero+0x138))[id >> 6] >> (id & 63).
	const size_t STATUS_BITFIELD_OFFSET = 0x138;

	// The modded client's main-window WndProc shows the XP icon when either
	// of these hero statuses is active (0x00A653E4: ChkStatus(hero, 0xA) ||
	// ChkStatus(hero, 0x5) -> FUN_005F254F -> SetBar(1)). Configurable - some
	// private servers use different ids for the XP pop.
	const int XP_ICON_GATE_STATUS_A = 10;
	const int XP_ICON_GATE_STATUS_B = 5;

	// CDlgXp::SetBar (dlgxp.cpp) - the modded client's real icon show/hide
	// setter. The whole icon lifecycle funnels through it:
	//   show: FUN_005F254F -> FUN_00AE622B(1) -> +0xAA8 = 1, render icon
	//   hide: FUN_005F25BA -> FUN_00AE622B(0) -> +0xAA8 = 0, hide window
	// The old FUN_00AE5B7B/FUN_00AE5FC7 paths are dead in this build (the
	// modded renderer FUN_00AE6708 draws the icon directly), so this is the
	// one function called on every icon state change. Prologue sanity bytes:
	//   55                push ebp
	//   8B EC             mov  ebp, esp
	//   56                push esi
	//   6A 05             push 5
	const uintptr_t XP_ICON_SET_FUNC = 0x00AE622B;
	const size_t    ICON_BAR_FLAG_OFFSET  = 0xAA8;  // 1 = icon bar active/visible, 0 = hidden
	const size_t    ICON_MODE_FLAG_OFFSET  = 0xAB0;  // old-path show-mode flag (debug display)
	const size_t    ICON_SHOWN_FLAG_OFFSET = 0xAB4;  // old-path shown flag (debug display)
	const size_t    HWND_OFFSET            = 0x20;   // CWnd::m_hWnd (debug display only)

	// --- configuration -----------------------------------------------------
	bool g_autoSwap = false;
	int  g_iconStatusIdA = XP_ICON_GATE_STATUS_A;  // icon gate status A (WndProc 0x00A653E4)
	int  g_iconStatusIdB = XP_ICON_GATE_STATUS_B;  // icon gate status B (WndProc 0x00A653F6, EDI=5)

	// --- runtime state -----------------------------------------------------
	int  g_mode = -1;            // last read equip mode (-1 = unknown)
	unsigned int g_xpBar = 0;    // last poll: XP bar value (0-100)
	bool g_iconActive = false;   // last poll: XP icon on screen (gate status A or B)?
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

	int GetHero();   // defined below - the CMyHero singleton (DAT_01a53980)

	// --- XP icon visibility hook -------------------------------------------
	// FUN_00AE622B is CDlgXp::SetBar (this in ECX, param_2 = show != 0). It is
	// the single choke point the modded client uses for both directions: the
	// show handler (FUN_005F254F) and the hide handler (FUN_005F25BA) both
	// call it, it sets CDlgXp+0xAA8 = 1/0, and on show it renders the icon
	// bar through FUN_00AE4949 -> FUN_00AE6708. The old FUN_00AE5B7B /
	// FUN_00AE5FC7 functions never run in this build.
	typedef void (__thiscall* XpIconSetFn)(void* self, int show);
	static XpIconSetFn s_originalXpIconSet = nullptr;
	unsigned long g_iconHookFired = 0;   // detour call counter (diagnostic)

	void __fastcall HkXpIconSet(void* self, void* /*edx*/, int show)
	{
		GearSwap::g_cdlgxp = (int)self;
		GearSwap::g_iconHookFired++;
		if (s_originalXpIconSet)
			s_originalXpIconSet(self, show);
	}

	void EnsureIconHookInstalled()
	{
		if (g_iconHookInstalled)
			return;
		const unsigned char* p = (const unsigned char*)XP_ICON_SET_FUNC;
		if (IsBadReadPtr(p, 8))
			return;
		// Prologue must match the static binary or the hook would land on the
		// wrong code (client builds / packer variants shift addresses).
		if (p[0] != 0x55 || p[1] != 0x8B || p[2] != 0xEC ||
			p[3] != 0x56 || p[4] != 0x6A || p[5] != 0x05)
			return;
		g_iconHookStatus = MH_Initialize();
		if (g_iconHookStatus != MH_OK && g_iconHookStatus != MH_ERROR_ALREADY_INITIALIZED)
			return;
		g_iconHookStatus = MH_CreateHook((LPVOID)XP_ICON_SET_FUNC, &HkXpIconSet, (LPVOID*)&s_originalXpIconSet);
		if (g_iconHookStatus != MH_OK)
			return;
		g_iconHookStatus = MH_EnableHook((LPVOID)XP_ICON_SET_FUNC);
		if (g_iconHookStatus != MH_OK)
			return;
		g_iconHookInstalled = true;
	}

	// Ground-truth check: the game's own ChkStatus mirror. Statuses live in
	// the 576-bit bitfield at hero+0x138 (FUN_00F1AF78 = C3DUser::ChkStatus:
	// ADD ECX,0x138; bit layout per FUN_00D4ED8E: bit (id&63) of word (id>>6)).
	// The modded WndProc shows the XP icon when status A or status B is set,
	// so this is exactly what "icon on screen" means to the client - no hooks
	// needed, and it also catches the hide the moment the pop is consumed.
	bool IsHeroStatusActive(int statusId)
	{
		int hero = GetHero();
		if (!hero || statusId < 0 || statusId >= 576)
			return false;
		if (IsBadReadPtr((const void*)(hero + STATUS_BITFIELD_OFFSET), 72))
			return false;
		const unsigned long long* words =
			(const unsigned long long*)(hero + STATUS_BITFIELD_OFFSET);
		return ((words[statusId >> 6] >> (statusId & 63)) & 1ULL) != 0;
	}

	bool IsXpIconVisible()
	{
		return IsHeroStatusActive(g_iconStatusIdA) || IsHeroStatusActive(g_iconStatusIdB);
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

		// The SetBar hook is purely diagnostic now (captures the CDlgXp
		// instance + fired counter for the debug tree) - the status-bit read
		// is the real signal and cannot fail on a valid build.
		EnsureIconHookInstalled();

		g_mode = GetEquipMode(hero);
		g_xpBar = GetXpBarValue();
		g_iconActive = IsXpIconVisible();
		DWORD now = GetTickCount();

		// The client shows the icon while the hero carries the XP pop status
		// (10 or 5) and hides it when the skill activation consumes the pop -
		// so "icon on screen" alone drives both directions:
		//   icon up   -> wear ALT
		//   icon gone -> wear MAIN
		bool altWanted = g_iconActive;
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
		ImGui::TextDisabled("icon gone (pop consumed) -> MAIN.");

		int statusA = GearSwap::g_iconStatusIdA;
		int statusB = GearSwap::g_iconStatusIdB;
		if (ImGui::InputInt("XP icon status id A", &statusA))
		{
			if (statusA < 0)
				statusA = 0;
			if (statusA > 575)
				statusA = 575;
			GearSwap::g_iconStatusIdA = statusA;
		}
		if (ImGui::InputInt("XP icon status id B", &statusB))
		{
			if (statusB < 0)
				statusB = 0;
			if (statusB > 575)
				statusB = 575;
			GearSwap::g_iconStatusIdB = statusB;
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
		ImGui::Text("Status %d: %s   Status %d: %s",
			GearSwap::g_iconStatusIdA,
			GearSwap::IsHeroStatusActive(GearSwap::g_iconStatusIdA) ? "ACTIVE" : "off",
			GearSwap::g_iconStatusIdB,
			GearSwap::IsHeroStatusActive(GearSwap::g_iconStatusIdB) ? "ACTIVE" : "off");
		if (GearSwap::g_autoSwap && GearSwap::g_iconActive)
		{
			ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.3f, 1.0f),
				"XP icon up - wearing ALT until it clears");
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
				ImGui::Text("icon flags: bar(+0xAA8)=%d mode(+0xAB0)=%d shown(+0xAB4)=%d",
					*(int*)(GearSwap::g_cdlgxp + GearSwap::ICON_BAR_FLAG_OFFSET),
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