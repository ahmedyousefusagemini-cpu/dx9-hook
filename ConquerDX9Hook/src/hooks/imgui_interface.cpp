#include "imgui.h"
#include "common.h"

extern GameWindowInfo g_gameWindow;
extern bool g_isWireframeEnabled;
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

	if (!g_gameWindow.isGuiWindowOpen) 
		return;

	ImGui::SetNextWindowSize(ImVec2(420, 700), ImGuiCond_FirstUseEver);
	ImGui::SetNextWindowPos(ImVec2(50, 50), ImGuiCond_FirstUseEver);
	
	ImGui::Begin("ConquerDX9.Hook by Carniato", nullptr, ImGuiWindowFlags_None);

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