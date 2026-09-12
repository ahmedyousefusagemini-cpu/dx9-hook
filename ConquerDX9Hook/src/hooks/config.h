#pragma once

// Persists the feature settings to coinfo.ini (next to the game exe, same
// folder as overlay.ini).
//
// The AccountManager writes coinfo.ini before each launch (its accounts.txt
// is the master config); LoadConfig() runs automatically at DLL load so the
// settings are restored before the first rendered frame.

void SaveConfig();
void LoadConfig();
