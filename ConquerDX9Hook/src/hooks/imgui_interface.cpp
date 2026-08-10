#include "imgui.h"
#include "common.h"
#include "memory_scanner.h"

extern GameWindowInfo g_gameWindow;
extern bool g_isAlwaysJumpEnabled;
extern bool g_isWireframeEnabled;
extern std::vector<StringConfiguration> g_itemStringConfigurations;
extern bool g_serverNameEnabled;
extern bool g_serverNameUseRainbow;
extern void UpdateRainbowColors();
extern void RenderAutoHuntInterface();
extern void ApplyAutoHuntClientState();
extern void RenderXpSkillInterface();
extern void RenderSpeedInterface();
extern void ApplySpeedClientState();

// Diagnostics from directx_hooks.cpp
extern unsigned long g_debugMouseMessageCount;
extern unsigned long g_debugKeyboardMessageCount;

void RenderImGuiInterface() 
{
	// Frozen values must be re-applied every frame, even while the
	// menu is closed, so this runs before the visibility check.
	g_memoryScanner.ApplyFrozenValues();

	// Auto-hunt's client-side hunting flag is asserted every frame too, so the
	// hunt brain stays engaged even after the overlay is closed.
	ApplyAutoHuntClientState();

	// Speed control's fast-loot tick gate reset runs every frame as well.
	ApplySpeedClientState();

	if (!g_gameWindow.isGuiWindowOpen) 
		return;

	ImGui::SetNextWindowSize(ImVec2(420, 700), ImGuiCond_FirstUseEver);
	ImGui::SetNextWindowPos(ImVec2(50, 50), ImGuiCond_FirstUseEver);
	
	ImGui::Begin("ConquerDX9.Hook by Carniato", nullptr, ImGuiWindowFlags_None);

	UpdateRainbowColors();

	// Temporary diagnostics: these counters must go UP when moving/clicking
	// the mouse over the game and when pressing keys. If they stay at 0,
	// the input hook is not attached to the window receiving input.
	ImGui::Text("Input debug - mouse: %lu | keys: %lu", g_debugMouseMessageCount, g_debugKeyboardMessageCount);
	ImGui::Separator();
	
	ImGui::Text("Game Features");
	ImGui::Separator();
	ImGui::Checkbox("Always Jump", &g_isAlwaysJumpEnabled);        
	ImGui::Checkbox("Wireframe (Chams)", &g_isWireframeEnabled);   
	
	ImGui::Spacing();
	
	RenderAutoHuntInterface();
	
	ImGui::Spacing();

	RenderXpSkillInterface();

	ImGui::Spacing();
	
	RenderSpeedInterface();
	
	ImGui::Spacing();
	
	ImGui::Text("String Modifications");
	ImGui::Separator();
	ImGui::Checkbox("Server Name Rainbow", &g_serverNameUseRainbow); 
	
	ImGui::Spacing();
	
	ImGui::Text("Item Strings");
	ImGui::Separator();

	ImGui::BeginChild("ItemStrings", ImVec2(0, 200), true);
	
	for (size_t i = 0; i < g_itemStringConfigurations.size(); i++) 
	{
		ImGui::PushID(static_cast<int>(i));
		StringConfiguration& config = g_itemStringConfigurations[i];
		
		ImGui::Checkbox("Rainbow", &config.useRainbowColor);
		ImGui::SameLine(); 
		ImGui::Checkbox("Background", &config.showBackground);
		
		if (!config.useRainbowColor) 
		{
			ImGui::Checkbox("Custom Color", &config.useCustomTextColor);
			if (config.useCustomTextColor) 
			{
				ImGui::ColorEdit4("Color", &config.textColorRed);
			}
		}
		
		ImGui::Spacing();  
		ImGui::PopID();
	}
	ImGui::EndChild();

	ImGui::Spacing();

	ImGui::Text("Memory Scanner");
	ImGui::Separator();
	RenderMemoryScannerInterface();
	
	ImGui::End();
}