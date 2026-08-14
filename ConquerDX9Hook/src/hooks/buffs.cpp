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
// Buff names are defined in ini/StatusTips.ini (loaded by the CUserAttribMgr
// loader FUN_00e2c03c from userattribmgr.cpp; singleton DAT_01a56f20,
// accessor FUN_008329b1). The file uses [<id>] blocks with Name= lines.
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

	// FUN_00e48d33 - the server-driven status apply chokepoint:
	//   void __thiscall(mgr, statusId, displayType, seconds, flag, extra)
	// Prologue sanity bytes: 6A 1C B8 ?? ?? ?? ?? E8 (EH prolog).
	const uintptr_t STATUS_APPLY_FUNC = 0x00E48D33;

	// ---- runtime state -----------------------------------------------------
	struct BuffEntry
	{
		int  statusId;
		char name[64];
	};

	std::vector<BuffEntry> g_knownStatuses;   // id->name map from StatusTips.ini
	unsigned char g_statusBits[STATUS_BITFIELD_WORDS * 8] = {};
	bool g_statusReadOk = false;

	// Per-status end timestamps (GetTickCount ms) captured from the apply
	// hook. 0 = unknown / permanent buff (no countdown shown).
	unsigned long g_statusEndMs[STATUS_MAX_ID] = {};
	bool g_timerHookInstalled = false;

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

	// ---- name map from ini/StatusTips.ini ----------------------------------

	void LoadStatusNames()
	{
		if (!g_knownStatuses.empty())
			return;

		char iniPath[MAX_PATH];
		GetModuleFileNameA(GetModuleHandleA(NULL), iniPath, MAX_PATH);
		char* slash = strrchr(iniPath, '\\');
		if (!slash)
			return;
		strcpy_s(slash + 1, MAX_PATH - (slash + 1 - iniPath), "ini\\StatusTips.ini");

		FILE* f = nullptr;
		if (fopen_s(&f, iniPath, "r") != 0 || !f)
			return;

		int curId = -1;
		char line[512];
		while (fgets(line, sizeof(line), f))
		{
			// [<id>] block header.
			if (line[0] == '[')
			{
				curId = atoi(line + 1);
				continue;
			}
			if (curId >= 0 && strncmp(line, "Name=", 5) == 0)
			{
				char name[64];
				strncpy_s(name, line + 5, sizeof(name) - 1);
				name[sizeof(name) - 1] = '\0';
				char* nl = strchr(name, '\n');
				if (nl) *nl = '\0';
				char* cr = strchr(name, '\r');
				if (cr) *cr = '\0';

				BuffEntry e;
				e.statusId = curId;
				strncpy_s(e.name, name, sizeof(e.name) - 1);
				g_knownStatuses.push_back(e);
				curId = -1;
			}
		}
		fclose(f);
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
				g_statusEndMs[statusId] = GetTickCount() + (unsigned long)seconds * 1000UL;
			else
				g_statusEndMs[statusId] = 0;
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

		int user = GetMyUserObject();
		if (!user)
			return;

		const unsigned char* bits = (const unsigned char*)(user + STATUS_BITFIELD_OFFSET);
		if (!IsReadable(bits, sizeof(g_statusBits)))
			return;

		memcpy(g_statusBits, bits, sizeof(g_statusBits));
		g_statusReadOk = true;
		LoadStatusNames();
	}
}

// Free wrapper so imgui_interface.cpp can poll every frame.
void ApplyBuffsClientState()
{
	Buffs::PollBuffs();
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
		ImGui::TextDisabled("(%d defined in StatusTips.ini)", (int)Buffs::g_knownStatuses.size());
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
}