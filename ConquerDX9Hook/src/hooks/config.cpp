#include <windows.h>
#include <cstdio>
#include <vector>
#include "config.h"

// ============================================================================
// Config persistence (ConquerHook.ini)
// ----------------------------------------------------------------------------
// Saves the overlay's feature settings into ConquerHook.ini next to the game
// exe (same folder as overlay.ini). LoadConfig() runs at startup so the last
// session's settings are restored automatically; SaveConfig() is wired to the
// "Save Config" button in the ImGui menu.
//
// Only user preferences are stored - transient runtime state (e.g. whether
// auto-hunt is currently running, speed-scan results, live buff timers) is
// deliberately excluded.
// ============================================================================

// State owned by the feature modules (defined in their .cpp files).
namespace AutoHunt
{
	struct Waypoint { int x; int y; };
	extern bool g_notifyServer;
	extern bool g_spoofVipLevel;
	extern int  g_vipLevel;
	extern bool g_waypointsEnabled;
	extern std::vector<Waypoint> g_waypoints;
	extern int  g_arrivalThreshold;
	extern int  g_clearedSeconds;
	extern int  g_travelTimeoutSeconds;
	extern void ApplyClientSideState();
}

namespace Speed
{
	extern bool g_speedEnabled;
	extern int  g_speedPercent;
	extern bool g_fastLootTick;
	extern int  g_fastLootIntervalMs;
	extern bool g_autoMoveSpeedEnabled;
	extern int  g_autoMovePercent;
	extern bool g_attackSpeedEnabled;
	extern int  g_attackSpeedPercent;
	extern int  g_attackIntervalMs;
	extern void SetSpeedEnabled(bool);
	extern void SetAutoMoveSpeedEnabled(bool);
	extern void SetAttackSpeedEnabled(bool);
}

namespace XpSkill
{
	extern bool g_allowXpSkills;
	extern bool g_autoXpSkill;
	extern bool g_autoXpOnlyWhileHunting;
	extern bool g_forceXpSkillId;
	extern int  g_forcedXpSkillId;
	extern void ApplyXpSkillState();
}

namespace Buffs
{
	extern bool g_buffsEnabled;
}

namespace GearSwap
{
	extern bool g_autoSwap;
	extern int  g_iconStatusIdA;
	extern int  g_iconStatusIdB;
}

extern bool g_isWireframeEnabled;

static const char* GetConfigPath()
{
	static char path[MAX_PATH] = { 0 };
	if (path[0])
		return path;
	if (GetModuleFileNameA(NULL, path, MAX_PATH))
	{
		char* slash = strrchr(path, '\\');
		if (slash)
			*(slash + 1) = '\0';
		strcat_s(path, "ConquerHook.ini");
	}
	return path;
}

static void WriteInt(const char* section, const char* key, int value)
{
	char buf[32];
	_snprintf_s(buf, sizeof(buf), _TRUNCATE, "%d", value);
	WritePrivateProfileStringA(section, key, buf, GetConfigPath());
}

void SaveConfig()
{
	const char* path = GetConfigPath();

	// --- General ---
	WritePrivateProfileStringA("General", "Wireframe", g_isWireframeEnabled ? "1" : "0", path);

	// --- Auto Hunt ---
	WritePrivateProfileStringA("AutoHunt", "NotifyServer", AutoHunt::g_notifyServer ? "1" : "0", path);
	WritePrivateProfileStringA("AutoHunt", "SpoofVipLevel", AutoHunt::g_spoofVipLevel ? "1" : "0", path);
	WriteInt("AutoHunt", "VipLevel", AutoHunt::g_vipLevel);
	WritePrivateProfileStringA("AutoHunt", "WaypointsEnabled", AutoHunt::g_waypointsEnabled ? "1" : "0", path);
	WriteInt("AutoHunt", "ArrivalThreshold", AutoHunt::g_arrivalThreshold);
	WriteInt("AutoHunt", "ClearedSeconds", AutoHunt::g_clearedSeconds);
	WriteInt("AutoHunt", "TravelTimeoutSeconds", AutoHunt::g_travelTimeoutSeconds);

	WriteInt("AutoHunt", "WaypointCount", (int)AutoHunt::g_waypoints.size());
	for (size_t i = 0; i < AutoHunt::g_waypoints.size(); i++)
	{
		char key[16];
		char value[32];
		_snprintf_s(key, sizeof(key), _TRUNCATE, "Waypoint%zu", i);
		_snprintf_s(value, sizeof(value), _TRUNCATE, "%d,%d",
			AutoHunt::g_waypoints[i].x, AutoHunt::g_waypoints[i].y);
		WritePrivateProfileStringA("AutoHunt", key, value, path);
	}

	// --- Speed Control ---
	WritePrivateProfileStringA("Speed", "SpeedEnabled", Speed::g_speedEnabled ? "1" : "0", path);
	WriteInt("Speed", "SpeedPercent", Speed::g_speedPercent);
	WritePrivateProfileStringA("Speed", "FastLootTick", Speed::g_fastLootTick ? "1" : "0", path);
	WriteInt("Speed", "FastLootIntervalMs", Speed::g_fastLootIntervalMs);
	WritePrivateProfileStringA("Speed", "AutoMoveSpeedEnabled", Speed::g_autoMoveSpeedEnabled ? "1" : "0", path);
	WriteInt("Speed", "AutoMovePercent", Speed::g_autoMovePercent);
	WritePrivateProfileStringA("Speed", "AttackSpeedEnabled", Speed::g_attackSpeedEnabled ? "1" : "0", path);
	WriteInt("Speed", "AttackSpeedPercent", Speed::g_attackSpeedPercent);
	WriteInt("Speed", "AttackIntervalMs", Speed::g_attackIntervalMs);

	// --- XP Skills ---
	WritePrivateProfileStringA("XpSkill", "AllowXpSkills", XpSkill::g_allowXpSkills ? "1" : "0", path);
	WritePrivateProfileStringA("XpSkill", "AutoXpSkill", XpSkill::g_autoXpSkill ? "1" : "0", path);
	WritePrivateProfileStringA("XpSkill", "AutoXpOnlyWhileHunting", XpSkill::g_autoXpOnlyWhileHunting ? "1" : "0", path);
	WritePrivateProfileStringA("XpSkill", "ForceXpSkillId", XpSkill::g_forceXpSkillId ? "1" : "0", path);
	WriteInt("XpSkill", "ForcedXpSkillId", XpSkill::g_forcedXpSkillId);

	// --- Buffs ---
	WritePrivateProfileStringA("Buffs", "BuffsEnabled", Buffs::g_buffsEnabled ? "1" : "0", path);

	// --- Auto Gear Swap ---
	WritePrivateProfileStringA("GearSwap", "AutoSwap", GearSwap::g_autoSwap ? "1" : "0", path);
	WriteInt("GearSwap", "IconStatusIdA", GearSwap::g_iconStatusIdA);
	WriteInt("GearSwap", "IconStatusIdB", GearSwap::g_iconStatusIdB);
}

void LoadConfig()
{
	const char* path = GetConfigPath();
	// No config file yet - keep the built-in defaults.
	if (GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES)
		return;

	// --- General ---
	g_isWireframeEnabled = GetPrivateProfileIntA("General", "Wireframe", 0, path) != 0;

	// --- Auto Hunt ---
	AutoHunt::g_notifyServer = GetPrivateProfileIntA("AutoHunt", "NotifyServer", 0, path) != 0;
	AutoHunt::g_spoofVipLevel = GetPrivateProfileIntA("AutoHunt", "SpoofVipLevel", 0, path) != 0;
	AutoHunt::g_vipLevel = GetPrivateProfileIntA("AutoHunt", "VipLevel", 6, path);
	if (AutoHunt::g_vipLevel < 0) AutoHunt::g_vipLevel = 0;
	if (AutoHunt::g_vipLevel > 6) AutoHunt::g_vipLevel = 6;
	AutoHunt::g_waypointsEnabled = GetPrivateProfileIntA("AutoHunt", "WaypointsEnabled", 0, path) != 0;
	AutoHunt::g_arrivalThreshold = GetPrivateProfileIntA("AutoHunt", "ArrivalThreshold", 4, path);
	AutoHunt::g_clearedSeconds = GetPrivateProfileIntA("AutoHunt", "ClearedSeconds", 5, path);
	AutoHunt::g_travelTimeoutSeconds = GetPrivateProfileIntA("AutoHunt", "TravelTimeoutSeconds", 30, path);

	AutoHunt::g_waypoints.clear();
	int waypointCount = GetPrivateProfileIntA("AutoHunt", "WaypointCount", 0, path);
	if (waypointCount > 0 && waypointCount <= 64)
	{
		for (int i = 0; i < waypointCount; i++)
		{
			char key[16];
			char value[64];
			_snprintf_s(key, sizeof(key), _TRUNCATE, "Waypoint%d", i);
			GetPrivateProfileStringA("AutoHunt", key, "", value, sizeof(value), path);
			int x = 0, y = 0;
			if (sscanf_s(value, "%d,%d", &x, &y) == 2)
			{
				AutoHunt::Waypoint wp;
				wp.x = x;
				wp.y = y;
				AutoHunt::g_waypoints.push_back(wp);
			}
		}
	}

	// --- Speed Control ---
	Speed::g_speedEnabled = GetPrivateProfileIntA("Speed", "SpeedEnabled", 0, path) != 0;
	Speed::g_speedPercent = GetPrivateProfileIntA("Speed", "SpeedPercent", 200, path);
	Speed::g_fastLootTick = GetPrivateProfileIntA("Speed", "FastLootTick", 0, path) != 0;
	Speed::g_fastLootIntervalMs = GetPrivateProfileIntA("Speed", "FastLootIntervalMs", 50, path);
	Speed::g_autoMoveSpeedEnabled = GetPrivateProfileIntA("Speed", "AutoMoveSpeedEnabled", 0, path) != 0;
	Speed::g_autoMovePercent = GetPrivateProfileIntA("Speed", "AutoMovePercent", 500, path);
	Speed::g_attackSpeedEnabled = GetPrivateProfileIntA("Speed", "AttackSpeedEnabled", 0, path) != 0;
	Speed::g_attackSpeedPercent = GetPrivateProfileIntA("Speed", "AttackSpeedPercent", 500, path);
	Speed::g_attackIntervalMs = GetPrivateProfileIntA("Speed", "AttackIntervalMs", 650, path);

	// --- XP Skills ---
	XpSkill::g_allowXpSkills = GetPrivateProfileIntA("XpSkill", "AllowXpSkills", 0, path) != 0;
	XpSkill::g_autoXpSkill = GetPrivateProfileIntA("XpSkill", "AutoXpSkill", 0, path) != 0;
	XpSkill::g_autoXpOnlyWhileHunting = GetPrivateProfileIntA("XpSkill", "AutoXpOnlyWhileHunting", 1, path) != 0;
	XpSkill::g_forceXpSkillId = GetPrivateProfileIntA("XpSkill", "ForceXpSkillId", 1, path) != 0;
	XpSkill::g_forcedXpSkillId = GetPrivateProfileIntA("XpSkill", "ForcedXpSkillId", 47, path);

	// --- Buffs ---
	Buffs::g_buffsEnabled = GetPrivateProfileIntA("Buffs", "BuffsEnabled", 1, path) != 0;

	// --- Auto Gear Swap ---
	GearSwap::g_autoSwap = GetPrivateProfileIntA("GearSwap", "AutoSwap", 0, path) != 0;
	GearSwap::g_iconStatusIdA = GetPrivateProfileIntA("GearSwap", "IconStatusIdA", 10, path);
	GearSwap::g_iconStatusIdB = GetPrivateProfileIntA("GearSwap", "IconStatusIdB", 5, path);

	// --- Apply side effects ---
	// The enable paths kick off the my-role scan / raise the speed cap table
	// (the same work the checkbox handlers do). Idempotent per frame.
	if (Speed::g_speedEnabled)
		Speed::SetSpeedEnabled(true);
	if (Speed::g_autoMoveSpeedEnabled)
		Speed::SetAutoMoveSpeedEnabled(true);
	if (Speed::g_attackSpeedEnabled)
		Speed::SetAttackSpeedEnabled(true);

	// The XP unlock is byte patches - apply them now (no-op on unknown builds).
	// Auto-pop needs the unlock too, exactly like the checkbox handler.
	if (XpSkill::g_allowXpSkills)
		XpSkill::ApplyXpSkillState();

	// Auto-hunt's per-frame state assertion picks up the loaded flags on the
	// next frame, so no call is needed here.
	AutoHunt::ApplyClientSideState();
}
