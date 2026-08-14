#include <windows.h>
#include <stdint.h>
#include <vector>
#include <string>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include "imgui.h"
#include "MinHook.h"

// ============================================================================
// Character Buffs / Status overlay - Conquer.exe client 7937 (base 0x400000)
// ----------------------------------------------------------------------------
// The client calls character buffs "StatusIcons" and tracks them in a
// 576-bit bitfield on the C3DUser (my character). All verified in Ghidra:
//
//   FUN_00eecff1 (C3DUser::AddStatus)  : ADD ECX,0x138; call bitfield setter
//   FUN_00ef1835 (C3DUser::ClearStatus): ADD ECX,0x138; call bitfield clear
//   FUN_00f1a1d8 (C3DUser::ChkStatus)  : ADD ECX,0x138; call bitfield tester
//   FUN_00eed011 / FUN_00ef1855        : same pair on a second bitfield +0x1c8
//   FUN_00a72eab (core setter/tester)  : bit = (id%64) of 64-bit word
//                                        bitfield + (id/64)*8
//
//   => active statuses = 72 bytes of bit flags at C3DUser+0x138 (576 bits).
//
// Remaining time: the server-driven apply chokepoint is FUN_00e48d33
//   (called by the MsgUserAttrib processor FUN_01040c2e as
//    e48d33(mgr, statusId, displayType, seconds, flag, extra)).
//   It refreshes the icon timer via FUN_00e4c9d8(icon, seconds, type) which
//   stores icon+0x2c = total seconds. We MinHook e48d33 and capture
//   endMs = now + seconds*1000 per status id.
//
// Buff names: the client's language table ini/Cn_Res.ini (GBK) holds the
// display names under STR_INI_STATUSTIPS_<id>_NAME (e.g.
// STR_INI_STATUSTIPS_250_NAME=Celestial Dance). StatusTips.ini Name= values
// are only STR_ keys, and the CUserAttrib def's +0x178 string is the effect
// animation name (e.g. "trojanblkt") - neither is displayable.
//
// My C3DUser is the tail of the client's +0x98 chain (same walk the auto-hunt
// brain uses, FUN_00deb082), validated by id match: user+0x54 == client+0x268.
// ============================================================================

namespace Buffs
{
	// ---- configuration -----------------------------------------------------
	bool g_buffsEnabled = true;

	// ---- game constants (client 7937) --------------------------------------
	const uintptr_t CLIENT_GLOBAL_ADDRESS = 0x01A52960;  // DAT_01a52960 - client object*
	const size_t    CLIENT_MY_ID_OFFSET   = 0x268;       // my entity id (variant A match)
	const size_t    USER_ID_OFFSET        = 0x54;        // role id (variant A)
	const size_t    USER_CHAIN_OFFSET     = 0x98;        // client->...->my C3DUser chain
	const size_t    STATUS_BITFIELD_OFFSET  = 0x138;     // 576-bit status bitfield
	const size_t    STATUS_BITFIELD_WORDS   = 9;         // 9 * 8 bytes = 72 bytes
	const size_t    STATUS_MAX_ID            = 576;

	// CUserAttribMgr: singleton global (DAT_01a56f20). Holds the definition
	// map and the active-icon vectors.
	const uintptr_t MGR_GLOBAL_ADDRESS = 0x01A56F20;   // DAT_01a56f20

	// Active status icons: std::vector<icon*> at mgr+0xe0 (and mgr+0xec for
	// the second display group). Each 0xac-byte icon:
	//   +0x28 = timeGetTime() at apply, +0x2c = total seconds,
	//   +0xa8 = CUserAttrib* def (def+0 = statusId)  [FUN_00e4c3d2]
	const size_t    MGR_ICON_VEC_A  = 0xe0;
	const size_t    MGR_ICON_VEC_B  = 0xec;
	const size_t    ICON_START_MS   = 0x28;
	const size_t    ICON_TOTAL_SEC  = 0x2c;
	const size_t    ICON_DEF_PTR    = 0xa8;
	const size_t    ICON_STRUCT_SIZE = 0xac;

	// FUN_00e48d33 - the server-driven status apply chokepoint:
	//   void __thiscall(mgr, statusId, displayType, seconds, flag, extra)
	// Prologue sanity bytes: 6A 1C B8 ?? ?? ?? ?? E8 (EH prolog).
	const uintptr_t STATUS_APPLY_FUNC = 0x00E48D33;

	// FUN_00a72eab - the core 64-bit bitfield set/clear that every status
	// funnels through (AddStatus/ClearStatus AND the XP-skill bit-only path).
	// XP skills set their bit WITHOUT creating a status icon, so this hook is
	// the only way the overlay sees their activation (the icon vectors + the
	// FUN_00e48d33 hook never fire for them).
	const uintptr_t STATUS_BITSET_FUNC = 0x00A72EAB;

	// ---- runtime state -----------------------------------------------------
	struct BuffEntry
	{
		int  statusId;
		char name[64];
	};

	std::vector<BuffEntry> g_knownStatuses;   // id->name map from ini/Cn_Res.ini
	unsigned char g_statusBits[STATUS_BITFIELD_WORDS * 8] = {};
	bool g_statusReadOk = false;

	// Per-status end timestamps (GetTickCount ms) from the active-icon
	// vectors (and the apply hook). 0 = unknown / permanent (no countdown).
	unsigned long g_statusEndMs[STATUS_MAX_ID] = {};
	bool g_timerHookInstalled = false;

	// Per-status buff duration (seconds) registered from XP/magic data
	// (magic-info +0x60). The core bit-set hook uses it to synthesize a
	// countdown for icon-less statuses (XP skills) that the icon vectors and
	// FUN_00e48d33 never report.
	unsigned int g_statusDurationSec[STATUS_MAX_ID] = {};
	bool g_bitHookInstalled = false;
	unsigned int g_bitSetCount = 0;
	unsigned int g_lastBitSetId = 0xFFFFFFFF;
	unsigned long g_lastBitSetTick = 0;

	// Ring buffer of the most recent status-bit transitions - a live trace of
	// which status id the game toggles (confirms the XP skill's real status id
	// so the countdown registration can be matched to it).
	struct BitEvent { unsigned int id; unsigned char set; unsigned long tick; };
	const int BIT_EVENT_RING = 64;
	BitEvent g_bitEvents[BIT_EVENT_RING] = {};
	int g_bitEventIndex = 0;
	unsigned int g_bitEventTotal = 0;

	// Diagnostics.
	int g_captureCount = 0;          // how many timer captures the hooks/reads saw
	int g_lastCaptureId = -1;
	unsigned long g_lastCaptureEndMs = 0;
	int g_namesLoaded = 0;
	int g_iconVectorCount = 0;       // active icons found in the mgr vectors

	// Diagnostics for object resolution (shown in the debug tree).
	int g_clientAddr = 0;
	int g_userAddr = 0;
	int g_userId54 = 0;
	int g_userId268 = 0;
	int g_clientId268 = 0;
	int g_clientId26c = 0;
	bool g_idMatched = false;

	// ---- tiny helpers ------------------------------------------------------

	bool IsReadable(const void* ptr, size_t len)
	{
		return ptr != nullptr && !IsBadReadPtr(ptr, len);
	}

	int GetClientObject()
	{
		if (!IsReadable((const void*)CLIENT_GLOBAL_ADDRESS, sizeof(int)))
			return 0;
		return *(int*)CLIENT_GLOBAL_ADDRESS;
	}

	// Walks client+0x98 to the tail node - my C3DUser (FUN_00deb082 pattern,
	// same walk the auto-hunt brain uses for the player position). The id
	// checks are soft: private servers can zero one pair or the other, so any
	// match confirms, but no match still returns the tail (GetPlayerPos proves
	// it is the local player).
	int GetMyUserObject()
	{
		int client = GetClientObject();
		if (!IsReadable((const void*)client, 0x100))
			return 0;

		g_clientAddr = client;
		g_clientId268 = *(int*)(client + CLIENT_MY_ID_OFFSET);
		g_clientId26c = *(int*)(client + 0x26c);

		int user = client;
		for (int i = 0; i < 64; i++)
		{
			if (!IsReadable((const void*)(user + USER_CHAIN_OFFSET), 4))
				return 0;
			int next = *(int*)(user + USER_CHAIN_OFFSET);
			if (next == 0)
				break;
			user = next;
		}

		if (!IsReadable((const void*)(user + 0x268), 4))
			return 0;

		g_userAddr = user;
		g_userId54 = *(int*)(user + USER_ID_OFFSET);
		g_userId268 = *(int*)(user + 0x268);

		// Any known id pair confirms this is my role:
		//   variant A : user+0x54  == client+0x268 (role-list match, FUN_00d3203a)
		//   variant B : user+0x268 == client+0x26c (msg filter, FUN_0098c58d)
		//   net path : user+0x268 == client+0x268 (CMsgUserAttrib handler check)
		g_idMatched =
			g_userId54 == g_clientId268 ||
			g_userId268 == g_clientId26c ||
			g_userId268 == g_clientId268;

		// If the chain never advanced, the tail is just the client object
		// itself - only trust it when an id pair actually matched.
		if (user == client && !g_idMatched)
			return 0;
		return user;
	}

	// ---- name map ----------------------------------------------------------

	// GBK (codepage 936) -> UTF-8 for ImGui.
	static void GbkToUtf8(const char* gbk, char* out, size_t outSize)
	{
		out[0] = '\0';
		int wlen = MultiByteToWideChar(936, 0, gbk, -1, NULL, 0);
		if (wlen <= 0)
			return;
		std::wstring w(wlen, L'\0');
		MultiByteToWideChar(936, 0, gbk, -1, &w[0], wlen);
		int ulen = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, NULL, 0, NULL, NULL);
		if (ulen <= 0)
			return;
		if ((size_t)ulen > outSize)
			ulen = (int)outSize;
		WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, out, ulen, NULL, NULL);
		out[outSize - 1] = '\0';
	}

	// Display names come from the game's language table ini/Cn_Res.ini (GBK):
	//   STR_INI_STATUSTIPS_250_NAME=Celestial Dance
	// (StatusTips.ini Name= values are only STR_ keys; the CUserAttrib def's
	// +0x178 string is the effect animation name - neither is displayable.)
	// The client resolves these paths CWD-relative ("ini\..."), so try the
	// current directory first, then the exe directory.
	static bool ParseCnRes(const char* baseDir)
	{
		char path[MAX_PATH];
		if (baseDir[0])
			_snprintf_s(path, sizeof(path), _TRUNCATE, "%s\\ini\\Cn_Res.ini", baseDir);
		else
			strcpy_s(path, sizeof(path), "ini\\Cn_Res.ini");

		FILE* f = nullptr;
		if (fopen_s(&f, path, "rb") != 0 || !f)
			return false;

		char line[1024];
		bool any = false;
		while (fgets(line, sizeof(line), f))
		{
			const char* key = "STR_INI_STATUSTIPS_";
			if (strncmp(line, key, strlen(key)) != 0)
				continue;

			int id = 0;
			size_t p = strlen(key);
			while (line[p] >= '0' && line[p] <= '9')
			{
				id = id * 10 + (line[p] - '0');
				p++;
			}
			if (strncmp(line + p, "_NAME=", 6) != 0 || id < 0 || id >= (int)STATUS_MAX_ID)
				continue;

			// Value is GBK up to the line end; strip CR/LF.
			char value[512];
			size_t v = p + 6;
			size_t len = 0;
			while (line[v] && line[v] != '\r' && line[v] != '\n' && len < sizeof(value) - 1)
				value[len++] = line[v++];
			value[len] = '\0';
			if (len == 0)
				continue;

			// '~' is the string system's space marker.
			for (size_t i = 0; i < len; i++)
				if (value[i] == '~')
					value[i] = ' ';

			BuffEntry e;
			e.statusId = id;
			GbkToUtf8(value, e.name, sizeof(e.name));
			if (e.name[0] == '\0')
				strncpy_s(e.name, value, sizeof(e.name) - 1);

			// First definition wins (main Cn_Res.ini beats ft/sp subdirs).
			bool exists = false;
			for (size_t i = 0; i < g_knownStatuses.size(); i++)
			{
				if (g_knownStatuses[i].statusId == id)
				{
					exists = true;
					break;
				}
			}
			if (!exists)
			{
				g_knownStatuses.push_back(e);
				g_namesLoaded++;
				any = true;
			}
		}
		fclose(f);
		return any;
	}

	void LoadStatusNames()
	{
		if (!g_knownStatuses.empty())
			return;

		g_namesLoaded = 0;

		// CWD first (the game is launched from the client root).
		char cwd[MAX_PATH];
		if (GetCurrentDirectoryA(sizeof(cwd), cwd) && ParseCnRes(cwd))
			return;
		// Fallback: sub-language copies.
		{
			char sub[MAX_PATH];
			_snprintf_s(sub, sizeof(sub), _TRUNCATE, "%s\\ini\\ft", cwd);
			ParseCnRes(sub);
			_snprintf_s(sub, sizeof(sub), _TRUNCATE, "%s\\ini\\sp", cwd);
			ParseCnRes(sub);
		}
		if (!g_knownStatuses.empty())
			return;
		// Exe dir (in case the game was launched from elsewhere).
		char exe[MAX_PATH];
		if (GetModuleFileNameA(GetModuleHandleA(NULL), exe, sizeof(exe)))
		{
			char* slash = strrchr(exe, '\\');
			if (slash)
				*slash = '\0';  // strip the exe name, keep the folder
			if (ParseCnRes(exe))
				return;
		}
	}

	// ---- timer hook --------------------------------------------------------

	typedef void (__thiscall* StatusApplyFn)(void* mgr, int statusId, int displayType,
		int seconds, int flag, int extra);
	static StatusApplyFn s_originalApply = nullptr;

	// __fastcall detour matches the __thiscall layout (this in ECX, args on
	// the stack). Seconds > 0 refreshes the deadline; seconds == 0 marks the
	// status as permanent/unknown so the UI shows no countdown.
	void __fastcall HkStatusApply(void* mgr, void*, int statusId, int displayType,
		int seconds, int flag, int extra)
	{
		if (statusId >= 0 && statusId < (int)STATUS_MAX_ID)
		{
			if (seconds > 0 && seconds < 86400 * 30)
			{
				g_statusEndMs[statusId] = GetTickCount() + (unsigned long)seconds * 1000UL;
				g_captureCount++;
				g_lastCaptureId = statusId;
				g_lastCaptureEndMs = g_statusEndMs[statusId];
			}
			else
			{
				g_statusEndMs[statusId] = 0;
			}
		}
		s_originalApply(mgr, statusId, displayType, seconds, flag, extra);
	}

	void EnsureTimerHookInstalled()
	{
		if (g_timerHookInstalled)
			return;

		// Sanity-check the target prologue (EH prolog: 6A 1C B8 ...).
		const unsigned char* code = (const unsigned char*)STATUS_APPLY_FUNC;
		if (IsBadReadPtr(code, 8) || code[0] != 0x6A || code[1] != 0x1C || code[2] != 0xB8)
			return;

		if (MH_Initialize() != MH_OK)
			return;
		if (MH_CreateHook((LPVOID)STATUS_APPLY_FUNC, &HkStatusApply,
			(LPVOID*)&s_originalApply) != MH_OK)
			return;
		if (MH_EnableHook((LPVOID)STATUS_APPLY_FUNC) != MH_OK)
			return;
		g_timerHookInstalled = true;
	}

	// ----------------------------------------------------------------------
	// Core bit-field hook (FUN_00a72eab). Catches the XP skill's bit-only
	// activation that never becomes a status icon.
	//   __thiscall(bitfield, id, set)  ->  __fastcall(ecx, unusedEdx, id, set)
	// ----------------------------------------------------------------------
	typedef int (__thiscall* BitSetFn)(void* bitfield, unsigned int id, char set);
	static BitSetFn s_originalBitSet = nullptr;

	void __fastcall HkBitSet(void* bitfield, void*, unsigned int id, char set)
	{
		unsigned long now = GetTickCount();

		if (id < (unsigned int)STATUS_MAX_ID)
		{
			if (set)
			{
				g_lastBitSetId = id;
				g_lastBitSetTick = now;
				g_bitSetCount++;

				// Only synthesize a deadline when a duration has been
				// registered for this status (XP skills). Icon-based statuses
				// keep their icon-derived timers from PollIconTimers.
				if (g_statusDurationSec[id] > 0)
				{
					g_statusEndMs[id] = now + (unsigned long)g_statusDurationSec[id] * 1000UL;
					g_captureCount++;
					g_lastCaptureId = (int)id;
					g_lastCaptureEndMs = g_statusEndMs[id];
				}
			}
			else
			{
				g_statusEndMs[id] = 0;   // status cleared - no more countdown
			}

			g_bitEvents[g_bitEventIndex].id = id;
			g_bitEvents[g_bitEventIndex].set = set;
			g_bitEvents[g_bitEventIndex].tick = now;
			g_bitEventIndex = (g_bitEventIndex + 1) % BIT_EVENT_RING;
			g_bitEventTotal++;
		}

		if (s_originalBitSet)
			s_originalBitSet(bitfield, id, set);
	}

	void EnsureBitHookInstalled()
	{
		if (g_bitHookInstalled)
			return;
		if (IsBadReadPtr((const void*)STATUS_BITSET_FUNC, 8))
			return;
		if (MH_Initialize() != MH_OK)
			return;
		if (MH_CreateHook((LPVOID)STATUS_BITSET_FUNC, &HkBitSet, (LPVOID*)&s_originalBitSet) != MH_OK)
			return;
		if (MH_EnableHook((LPVOID)STATUS_BITSET_FUNC) != MH_OK)
			return;
		g_bitHookInstalled = true;
	}

	// Reads the game's own active-icon list (mgr+0xe0 / +0xec vectors) and
	// derives each status's deadline. This mirrors what the game renders:
	//   remaining = total - (now - startMs)/1000  (FUN_00e4e217)
	// Works for every buff the client shows an icon for, no hook required.
	static void PollIconTimers()
	{
		g_iconVectorCount = 0;

		int mgr = 0;
		if (IsReadable((const void*)MGR_GLOBAL_ADDRESS, sizeof(int)))
			mgr = *(int*)MGR_GLOBAL_ADDRESS;
		if (!IsReadable((const void*)mgr, 0x100))
			return;

		const size_t vecOffsets[2] = { MGR_ICON_VEC_A, MGR_ICON_VEC_B };
		for (int v = 0; v < 2; v++)
		{
			int begin = *(int*)(mgr + vecOffsets[v]);
			int end = *(int*)(mgr + vecOffsets[v] + 4);
			if (!begin || end <= begin)
				continue;

			int count = (end - begin) >> 2;
			if (count > 64)
				count = 64;

			for (int i = 0; i < count; i++)
			{
				int icon = *(int*)(begin + i * 4);
				if (!IsReadable((const void*)icon, ICON_STRUCT_SIZE))
					continue;
				int def = *(int*)(icon + ICON_DEF_PTR);
				if (!IsReadable((const void*)def, 0x190))
					continue;

				int id = *(int*)def;
				if (id < 0 || id >= (int)STATUS_MAX_ID)
					continue;

				int startMs = *(int*)(icon + ICON_START_MS);
				int totalSec = *(int*)(icon + ICON_TOTAL_SEC);
				if (totalSec > 0 && totalSec < 86400 * 30)
				{
					g_statusEndMs[id] = (unsigned long)startMs + (unsigned long)totalSec * 1000UL;
					g_captureCount++;
					g_lastCaptureId = id;
					g_lastCaptureEndMs = g_statusEndMs[id];
				}
				else
				{
					g_statusEndMs[id] = 0;
				}
				g_iconVectorCount++;
			}
		}
	}

	// ---- per-frame poll ----------------------------------------------------

	// Mirrors the game's ChkStatus (FUN_00d4e0ae): bit (id%64) of the 64-bit
	// word at bitfield + (id/64)*8.
	static bool TestStatusBit(const unsigned char* bits, int id)
	{
		if (id < 0 || id >= STATUS_MAX_ID)
			return false;
		const unsigned long long* words = (const unsigned long long*)bits;
		return (words[id >> 6] >> (id & 63)) & 1ULL;
	}

	// "34s" / "1m 12s" / "--" for permanent or unknown-duration buffs.
	static const char* FormatRemaining(int statusId)
	{
		static char buf[32];
		unsigned long end = g_statusEndMs[statusId];
		if (end == 0)
			return "--";
		unsigned long now = GetTickCount();
		if (now >= end)
			return "0s";
		unsigned long secs = (end - now + 500) / 1000;
		if (secs >= 60)
			_snprintf_s(buf, sizeof(buf), _TRUNCATE, "%lum %lus", secs / 60, secs % 60);
		else
			_snprintf_s(buf, sizeof(buf), _TRUNCATE, "%lus", secs);
		return buf;
	}

	void PollBuffs()
	{
		g_statusReadOk = false;

		EnsureTimerHookInstalled();
		EnsureBitHookInstalled();

		int user = GetMyUserObject();
		if (!user)
			return;

		const unsigned char* bits = (const unsigned char*)(user + STATUS_BITFIELD_OFFSET);
		if (!IsReadable(bits, sizeof(g_statusBits)))
			return;

		memcpy(g_statusBits, bits, sizeof(g_statusBits));
		g_statusReadOk = true;
		LoadStatusNames();
		PollIconTimers();
	}
}

// Free wrapper so imgui_interface.cpp can poll every frame.
void ApplyBuffsClientState()
{
	Buffs::PollBuffs();
}

// Shared lookups (used by the XP-skill section: XP skills apply statuses
// with the same id, so the STATUSTIPS name + live timer apply to them too).
const char* GetStatusName(int statusId)
{
	if (statusId >= 0 && statusId < (int)Buffs::STATUS_MAX_ID)
	{
		for (size_t i = 0; i < Buffs::g_knownStatuses.size(); i++)
		{
			if (Buffs::g_knownStatuses[i].statusId == statusId)
				return Buffs::g_knownStatuses[i].name;
		}
	}
	return nullptr;
}

unsigned long GetStatusEndMs(int statusId)
{
	if (statusId < 0 || statusId >= (int)Buffs::STATUS_MAX_ID)
		return 0;
	return Buffs::g_statusEndMs[statusId];
}

// XP / magic data registers a status's buff duration (seconds) so the core
// bit-set hook can synthesize a live countdown even for icon-less statuses
// (XP skills). Called from xp_skill.cpp's learned-magic scan.
void RegisterStatusDuration(int statusId, unsigned int seconds)
{
	if (statusId >= 0 && statusId < (int)Buffs::STATUS_MAX_ID)
		Buffs::g_statusDurationSec[statusId] = seconds;
}

void RenderBuffsInterface()
{
	ImGui::Text("Character Buffs");
	ImGui::Separator();

	ImGui::Checkbox("Enable buff tracking", &Buffs::g_buffsEnabled);
	if (!Buffs::g_buffsEnabled)
		return;

	if (!Buffs::g_statusReadOk)
	{
		ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f),
			"(enter the game - no character object yet)");
		return;
	}

	ImGui::Spacing();

	// Every status defined in StatusTips.ini, shown with its live state.
	// Active = green [ON], inactive = gray [OFF].
	int onCount = 0;
	std::vector<int> activeIds;
	for (int id = 0; id < Buffs::STATUS_MAX_ID; id++)
	{
		if (Buffs::TestStatusBit(Buffs::g_statusBits, id))
		{
			onCount++;
			activeIds.push_back(id);
		}
	}

	ImGui::Text("Active: %d buff(s)", onCount);
	ImGui::Separator();

	// Show the known (named) statuses that are ACTIVE first.
	bool shownAny = false;
	for (size_t i = 0; i < Buffs::g_knownStatuses.size(); i++)
	{
		const Buffs::BuffEntry& b = Buffs::g_knownStatuses[i];
		if (!Buffs::TestStatusBit(Buffs::g_statusBits, b.statusId))
			continue;
		ImGui::PushID((int)i);
		ImGui::TextColored(ImVec4(0.3f, 1.0f, 0.3f, 1.0f), "[ON]  %s", b.name);
		ImGui::SameLine();
		ImGui::TextDisabled("id=%d", b.statusId);
		ImGui::SameLine();
		ImGui::Text("  %s", Buffs::FormatRemaining(b.statusId));
		ImGui::PopID();
		shownAny = true;
	}

	// Active ids that aren't in the ini (unknown name) still show.
	for (size_t i = 0; i < activeIds.size(); i++)
	{
		bool known = false;
		for (size_t j = 0; j < Buffs::g_knownStatuses.size(); j++)
		{
			if (Buffs::g_knownStatuses[j].statusId == activeIds[i])
			{
				known = true;
				break;
			}
		}
		if (known)
			continue;
		ImGui::PushID((int)(i + 50000));
		ImGui::TextColored(ImVec4(0.3f, 1.0f, 0.3f, 1.0f), "[ON]  Status %d", activeIds[i]);
		ImGui::SameLine();
		ImGui::Text("  %s", Buffs::FormatRemaining(activeIds[i]));
		ImGui::PopID();
		shownAny = true;
	}

	if (!shownAny)
		ImGui::TextDisabled("No active buffs");

	// Collapsible list of every known status with its live state.
	if (ImGui::TreeNode("All known statuses"))
	{
		ImGui::TextDisabled("(%d named in Cn_Res.ini)", (int)Buffs::g_knownStatuses.size());
		for (size_t i = 0; i < Buffs::g_knownStatuses.size(); i++)
		{
			const Buffs::BuffEntry& b = Buffs::g_knownStatuses[i];
			bool on = Buffs::TestStatusBit(Buffs::g_statusBits, b.statusId);
			ImGui::PushID((int)(i + 100000));
			if (on)
				ImGui::TextColored(ImVec4(0.3f, 1.0f, 0.3f, 1.0f), "[ON]  %s", b.name);
			else
				ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "[OFF] %s", b.name);
			ImGui::SameLine();
			ImGui::TextDisabled("id=%d", b.statusId);
			if (on)
			{
				ImGui::SameLine();
				ImGui::Text("  %s", Buffs::FormatRemaining(b.statusId));
			}
			ImGui::PopID();
		}
		ImGui::TreePop();
	}

	// Raw bitfield debug - confirms the offsets on a new client build.
	if (ImGui::TreeNode("Raw status bits"))
	{
		for (size_t w = 0; w < Buffs::STATUS_BITFIELD_WORDS; w++)
		{
			ImGui::Text("+0x%03X: %08X %08X",
				(unsigned int)(Buffs::STATUS_BITFIELD_OFFSET + w * 8),
				(unsigned int)((const unsigned int*)Buffs::g_statusBits)[w * 2],
				(unsigned int)((const unsigned int*)Buffs::g_statusBits)[w * 2 + 1]);
		}
		ImGui::TreePop();
	}

	// Object resolution diagnostics - helps when a new server build moves ids.
	if (ImGui::TreeNode("Object resolution"))
	{
		ImGui::Text("client: 0x%08X", (unsigned int)Buffs::g_clientAddr);
		ImGui::Text("user  : 0x%08X", (unsigned int)Buffs::g_userAddr);
		ImGui::Text("user+0x54  = %d (variant A role id)", Buffs::g_userId54);
		ImGui::Text("user+0x268 = %d (variant B role id)", Buffs::g_userId268);
		ImGui::Text("client+0x268 = %d (my id A)", Buffs::g_clientId268);
		ImGui::Text("client+0x26c = %d (my id B)", Buffs::g_clientId26c);
		ImGui::TextColored(Buffs::g_idMatched ? ImVec4(0.3f, 1.0f, 0.3f, 1.0f) : ImVec4(1.0f, 0.7f, 0.2f, 1.0f),
			Buffs::g_idMatched ? "id matched: this is my character" : "no id pair matched - check server id layout");
		ImGui::TreePop();
	}

	// Timer hook + name source diagnostics.
	if (ImGui::TreeNode("Timer hook"))
	{
		int mgr = 0;
		if (!IsBadReadPtr((const void*)Buffs::MGR_GLOBAL_ADDRESS, sizeof(int)))
			mgr = *(int*)Buffs::MGR_GLOBAL_ADDRESS;
		ImGui::Text("mgr: 0x%08X", (unsigned int)mgr);
		ImGui::TextColored(Buffs::g_timerHookInstalled ? ImVec4(0.3f, 1.0f, 0.3f, 1.0f) : ImVec4(1.0f, 0.3f, 0.3f, 1.0f),
			Buffs::g_timerHookInstalled ? "apply hook: INSTALLED" : "apply hook: NOT installed (build mismatch?)");
		ImGui::Text("captures: %d", Buffs::g_captureCount);
		ImGui::Text("active icons in mgr vectors: %d", Buffs::g_iconVectorCount);
		if (Buffs::g_lastCaptureId >= 0)
			ImGui::Text("last capture: id=%d endMs=%lu (now=%lu)",
				Buffs::g_lastCaptureId, Buffs::g_lastCaptureEndMs, GetTickCount());
		ImGui::Text("names loaded: %d", Buffs::g_namesLoaded);
		ImGui::TreePop();
	}

	// Core bit-set hook diagnostics. This is how the XP skill's real status id
	// is discovered: cast the XP skill once and the latest SET events show it.
	if (ImGui::TreeNode("Status bit monitor"))
	{
		ImGui::TextColored(Buffs::g_bitHookInstalled ? ImVec4(0.3f, 1.0f, 0.3f, 1.0f) : ImVec4(1.0f, 0.3f, 0.3f, 1.0f),
			Buffs::g_bitHookInstalled ? "bitset hook: INSTALLED" : "bitset hook: NOT installed (build mismatch?)");
		ImGui::Text("transitions: %u   sets: %u", Buffs::g_bitEventTotal, Buffs::g_bitSetCount);
		if (Buffs::g_lastBitSetId != 0xFFFFFFFF)
			ImGui::Text("last SET: id=%u at %lu (now=%lu)", Buffs::g_lastBitSetId,
				Buffs::g_lastBitSetTick, GetTickCount());

		ImGui::TextDisabled("Most recent transitions (newest first):");
		int shown = 0;
		for (int k = 0; k < Buffs::BIT_EVENT_RING && k < (int)Buffs::g_bitEventTotal; k++)
		{
			int idx = (Buffs::g_bitEventIndex - 1 - k + Buffs::BIT_EVENT_RING) % Buffs::BIT_EVENT_RING;
			const Buffs::BitEvent& e = Buffs::g_bitEvents[idx];
			if (e.set)
			{
				const char* name = GetStatusName((int)e.id);
				ImGui::TextColored(ImVec4(0.3f, 1.0f, 0.3f, 1.0f), "SET  id=%u  %s  end=%s",
					e.id, name ? name : "(no name)", Buffs::FormatRemaining((int)e.id));
			}
			else
			{
				ImGui::TextDisabled("CLR  id=%u", e.id);
			}
			if (++shown >= 10)
				break;
		}
		ImGui::TreePop();
	}
}