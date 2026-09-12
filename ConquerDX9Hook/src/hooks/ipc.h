// IPC command channel for the AccountManager control plane.
#pragma once

// Creates the message-only window (call once from the init thread). The
// window stays alive for the process lifetime; WM_COPYDATA commands from
// the manager are queued and applied by DrainIpcQueue.
bool InstallIpcWindow();

// Destroys the window and the queue critical section.
void UninstallIpcWindow();

// Drains queued commands and applies them (call every frame from
// HookedEndScene so mutations happen on the game thread).
void DrainIpcQueue();
