#pragma once

// Persists the overlay's feature settings to coinfo.ini (next to the game
// exe, same folder as overlay.ini).
//
// SaveConfig() is called from the in-game ImGui menu ("Save Config" button).
// LoadConfig() runs automatically at DLL load so the settings from the last
// launch are restored before the first rendered frame.

void SaveConfig();
void LoadConfig();
