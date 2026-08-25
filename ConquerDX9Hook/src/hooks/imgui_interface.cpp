#include "imgui.h"
#include "common.h"

extern GameWindowInfo g_gameWindow;
extern bool g_isWireframeEnabled;
extern void UpdateRainbowColors();
extern void RenderAutoHuntInterface();
extern void ApplyAutoHuntClientState();
extern void RenderXpSkillInterface();
extern void ApplyXpSkillClientState();
extern void RenderSpeedInterface();
extern void ApplySpeedClientState();
extern void RenderBuffsInterface();
extern void ApplyBuffsClientState();
extern void RenderGearSwapInterface();
extern void ApplyGearSwapClientState();
extern void ApplyAutoLoginClientState();
extern const char* GetAutoLoginStateString();
extern bool GetAutoLoginEnabled();
extern bool GetAutoLoginHooksInstalled();
extern unsigned long GetAutoLoginSubmitCount();
extern void AutoLoginSetManualCapture(bool on);
extern bool AutoLoginGetManualCapture();

// Diagnostics from directx_hooks.cpp
extern unsigned long g_debugMouseMessageCount;
extern unsigned long g_debugKeyboardMessageCount;
extern unsigned long g_debugSubclassedWindowCount;
extern bool g_subclassAllWindows;

void RenderImGuiInterface() 
{
	// Auto-hunt's client-side hunting flag is asserted every frame too, so the
	// hunt brain stays engaged even after the overlay is closed.
	ApplyAutoHuntClientState();

	// Speed control's fast-loot tick gate reset runs every frame as well.
	ApplySpeedClientState();

	// Auto XP pop ticks every frame too (it must run with the menu closed).
	ApplyXpSkillClientState();

	// Buff tracking ticks every frame so add/remove hooks stay armed.
	ApplyBuffsClientState();

	// Auto gear swap ticks every frame too (XP buff edge detection).
	ApplyGearSwapClientState();

	// Auto login/relogin ticks every frame (boot + back-to-login detection).
	ApplyAutoLoginClientState();

	if (!g_gameWindow.isGuiWindowOpen) 
		return;

	ImGui::SetNextWindowSize(ImVec2(420, 700), ImGuiCond_FirstUseEver);
	ImGui::SetNextWindowPos(ImVec2(50, 50), ImGuiCond_FirstUseEver);
	
	ImGui::Begin("ConquerDX9.Hook by Carniato", nullptr, ImGuiWindowFlags_None);

	UpdateRainbowColors();

	// Temporary diagnostics: these counters must go UP when moving/clicking
	// the mouse over the game and when pressing keys. If they stay at 0,
	// the input hook is not attached to the window receiving input.
	// "extra wnds" = additional subclassed windows (overlay.ini
	// [overlay] subclass_all_windows=1); 0 = only render+root hooked.
	ImGui::Text("Input debug - mouse: %lu | keys: %lu | extra wnds: %lu (%s)",
		g_debugMouseMessageCount, g_debugKeyboardMessageCount,
		g_debugSubclassedWindowCount, g_subclassAllWindows ? "allwnds on" : "allwnds off");
	ImGui::Separator();
	
	ImGui::Checkbox("Wireframe (Chams)", &g_isWireframeEnabled);   
	
	ImGui::Spacing();
	
	// Always show auto-login status, even when disabled, so the user can
	// diagnose "no login sequence" without checking a log file.
	{
		const char* st = GetAutoLoginStateString();
		bool en = GetAutoLoginEnabled();
		bool hk = GetAutoLoginHooksInstalled();
		ImVec4 col = en ? ImVec4(0.4f,1.0f,0.4f,1) : ImVec4(1.0f,0.6f,0.4f,1);
		ImGui::TextColored(col, "Auto login: %s | hooks: %s | submits: %lu%s",
			st ? st : "(null)",
			hk ? "ok" : "missing",
			GetAutoLoginSubmitCount(),
			en ? "" : " (disabled)");
		if (!en) {
			ImGui::TextDisabled("Enable: auto_login.ini [accounts] enabled=1 -> [account_0] account/password");
		}
		bool mc = AutoLoginGetManualCapture();
		ImGui::PushStyleColor(ImGuiCol_Text, mc ? ImVec4(1.0f, 0.9f, 0.3f, 1) : ImVec4(1, 1, 1, 1));
		if (ImGui::Checkbox("MANUAL LOGIN CAPTURE (pauses auto-login)", &mc))
			AutoLoginSetManualCapture(mc);
		ImGui::PopStyleColor();
		if (mc) {
			ImGui::TextDisabled("Auto frozen. Do the login by hand - everything");
			ImGui::TextDisabled("(realm row, GetServerInfo, packets) is recorded.");
		}
		ImGui::Separator();
	}
	
	RenderAutoHuntInterface();
	
	ImGui::Spacing();

	RenderXpSkillInterface();

	ImGui::Spacing();
	
	RenderSpeedInterface();

	ImGui::Spacing();

	RenderBuffsInterface();
	
	ImGui::Spacing();

	RenderGearSwapInterface();
	
	ImGui::End();
}