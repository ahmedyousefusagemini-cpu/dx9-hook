# Conquer.exe + TqNDProtect.dll — Anti-Debug / Anti-Cheat-Engine Bypass Report

**Binaries analyzed:**
- `H:\client\Env_DX9\Conquer.exe` (x86 PE32, image base `0x00400000`, no ASLR — `DllCharacteristics=0x8100`, no base-reloc dir) — 209k functions
- `H:\client\Env_DX9\TqNDProtect.dll` (x86 PE32, preferred base `0x10000000`) — 1180 functions, self-decrypting anti-cheat

**Method:** static analysis only; no EXE/DLL bytes changed, no Ghidra project writes (report-only).
**Goal:** allow live debugger (Ghidra-MCP dbgeng) + Cheat Engine attach without the game closing/disconnecting.

---

## 1. Verdict — TWO independent protection layers

### Layer A — Conquer.exe (the debugger killer)
One active anti-debug routine in the login-dialog init (plus 4 legacy SoftICE probes).
Attaching a debugger sets `PEB.BeingDebugged=1`; the routine's `IsDebuggerPresent`
returns TRUE → `CDialog::EndDialog(this,0)` → instant app exit.
No NTAPI query, no `CheckRemoteDebuggerPresent`, no process/window blacklist,
no timing/VEH/CRC checks in the EXE.

### Layer B — TqNDProtect.dll (the Cheat-Engine killer)
A self-decrypting, polymorphic anti-cheat DLL loaded once by the game (`TQNDP_Initialize`).
Its CE scanner is compiled inside a **runtime-decrypted blob** and calls every Windows API
through an **obfuscated API-cache** (`try_get_function`). Opening Cheat Engine trips this
scanner → the game disconnects/crashes even though the EXE itself never sees CE.

`.vlizer` (4.5 MB RWX in the EXE) is **inert** packer residue (TLS callback array
`0x014F7964` all zeros, no live code refs).

---

## 2. The anti-debug routine

| Item | Value |
|---|---|
| Function entry (vtable slot) | `0x00A227E9` (vtable `0x01653C00`, slot 0) |
| Calling convention | `__thiscall` (this in ECX) |
| Nature | MFC dialog initializer (login/main window) |
| On detection | `0x00A22F76: CALL 0x01264450` = `CDialog::EndDialog(this,0)` then return 0 |

### 2.1 SoftICE device probes (legacy, harmless on modern Windows)
Each probe: `PUSH <device-path>; CALL 0x00A4BEA3; TEST AL,AL; JNZ fail`
where `0x00A4BEA3` = `_lopen(path, 0)` — returns 1 if the device opens.

| # | Call site | Jump (6 bytes) | Device string | String address |
|---|---|---|---|---|
| 1 | `0x00A22C85` | `0x00A22CB8` `0F 85 B4 02 00 00` | `\\.\SICE` | `0x0165CB34` |
| 2 | `0x00A22CB0` | `0x00A22CCB` `0F 85 A1 02 00 00` | `\\.\SIWDEBUG` | `0x0165CB40` |
| 3 | `0x00A22CD6` | `0x00A22CDE` `0F 85 8E 02 00 00` | `\\.\NTICE` | `0x0165CB50` |
| 4 | `0x00A22CE9` | `0x00A22CF1` `0F 85 7B 02 00 00` | `\\.\SIWVID` | `0x0165CB5C` |

All four jump to the common failure block at `0x00A22F72`.

### 2.2 IsDebuggerPresent check (the live killer)

```
0x00A22CF7: FF 15 2C 52 4F 01   CALL dword ptr [0x014F522C]  ; IsDebuggerPresent (IAT)
0x00A22CFD: 6A 00               PUSH 0
0x00A22CFF: 85 C0               TEST EAX,EAX
0x00A22D01: 0F 85 6D 02 00 00   JNZ  0x00A22F74              ; <-- jump if debugger
```

- IAT slot for `IsDebuggerPresent`: **`0x014F522C`**
- This is the **only** non-CRT call site of `IsDebuggerPresent` in the binary.

### 2.3 Failure path
```
0x00A22F72: 6A 00               PUSH 0
0x00A22F74: 8B CF               MOV  ECX, EDI               ; this
0x00A22F76: E8 D5 14 84 00      CALL 0x01264450             ; CDialog::EndDialog(this,0)
0x00A22F7B: 33 DB               XOR  EBX, EBX               ; result = 0 (fail)
...
0x00A22F8E: E8 D0 E9 83 00      CALL 0x01261963
0x00A22F93: C3                  RET
```

---

## 3. Runtime bypass (no EXE modification)

Apply in memory with Cheat Engine Auto Assembler **before** attaching the debugger.
The image is not ASLR-rebased, so absolute addresses are stable.

| Address | Original bytes | Patch | Effect |
|---|---|---|---|
| `0x00A22CB8` | `0F 85 B4 02 00 00` | `90 90 90 90 90 90` | never jump on `\\.\SICE` |
| `0x00A22CCB` | `0F 85 A1 02 00 00` | `90 90 90 90 90 90` | never jump on `\\.\SIWDEBUG` |
| `0x00A22CDE` | `0F 85 8E 02 00 00` | `90 90 90 90 90 90` | never jump on `\\.\NTICE` |
| `0x00A22CF1` | `0F 85 7B 02 00 00` | `90 90 90 90 90 90` | never jump on `\\.\SIWVID` |
| `0x00A22D01` | `0F 85 6D 02 00 00` | `90 90 90 90 90 90` | never jump on debugger-present |
| `0x00A22CF7` | `FF 15 2C 52 4F 01` | `33 C0 90 90 90 90` | force `IsDebuggerPresent` → 0 |

Patches 1–5 (the `JNZ` → NOPs) are the essential ones; #6 is belt-and-braces.
All are fully reversible with the `[DISABLE]` section of the included script.

---

## 4. Other findings (cleared)

| Address | What | Verdict |
|---|---|---|
| `0x014F5130` | TerminateProcess caller `FUN_012219F7` | `ping.exe` latency probe (network ping), kills ping on timeout — benign |
| `0x00D8890F` | EnumWindows caller | window dock/positioning helper (taskbar layout) — benign |
| `0x00A0DEA3` | FindWindowA caller | window resize logic (`Shell_TrayWnd`) — benign |
| `0x014F5260` + strings `0x0165E558..` | GetProcAddress cluster | `SkillEditorBridge.dll` / `InitBridge` — dev tool bridge — benign |
| `0x0044F24E`, `0x0043EDAF`, `0x00436D8B` | GetProcAddress | shop-DLL bridges (`startShop`/`isShopOpen`/`closeShop`) — benign |
| `0x01075568` | GetProcAddress | `TQNDPCAnaly.dll` network packet analyzer (anti-cheat *telemetry*, not anti-debug) — benign for attach |
| `0x0076BB54` | GetProcAddress | `C3Video.dll` video bridge — benign |
| `0x0122E15C` | dynamic `CreateToolhelp32Snapshot`/`Module32First/Next` | address→module-name resolver (crash symbolization) — not a blacklist scan |
| `0x0128A310` | GetProcAddress | `_OPENSSL_isservice` + window-station name check — benign |
| `0x014F5264` IAT | module-handle cache `[0x01A5A640]` | skill-editor DLL — benign |
| `.vlizer` / TLS | callback array `0x014F7964` all zeros | inert packer residue |

---

## 5. TqNDProtect.dll — Cheat Engine detector (Layer B)

### 5.1 Why it's hard to see statically
- `TQNDP_Initialize` (export @ `0x10013D20`) → `FUN_100FF3A5` → decryptor stub:
  `PUSH 0xBBC63CCF; CALL FUN_10093103; NOT EAX; JMP FUN_1007A89E`
- `FUN_10093103` is a **XOR-stream decryptor** (`ROR/BSWAP/NEG` key transform,
  `MOV EDX,[ESI]; XOR EDX,EBX; ... JMP 0x100C99A6` = self-modifying continuation).
- `FUN_100C99A6` / `FUN_100C5E2B` (`JMP EDI`) = **decrypted-blob jump**.
- The actual detector code is only visible **after runtime decryption**.

### 5.2 The API cache chokepoint (`try_get_function`)
Every detector API call funnels through `try_get_function` @ `0x10021AE5`:
```
10021AF0  LEA EBX,[EAX*4 + 0x10038350]   ; slot = base + function_id*4
10021AF9  MOV EDX,[0x10037004]           ; rotation key = 0xBB40E64E
10021B09  XOR ESI,EAX ; ROR ESI,CL        ; decode cached pointer
10021B0D  CMP ESI,0xFFFFFFFF
10021B11  TEST ESI,ESI
10021B15  (cached -> return it)
10021B45  CALL [0x1002E044] = GetProcAddress  ; resolve if empty
10021B6A  (else store poison marker)
```
The API-cache table is `DAT_10038350` (base) + `id*4`; slots are **0 on disk**,
filled lazily at runtime. The `function_id` → API map lives in a name table at
`0x10035E00..0x10036600` (format: 2-byte LE id + ASCII name).

### 5.3 Relevant function_ids (decoded)
| id | API | Role |
|---|---|---|
| `0x003` | `IsDebuggerPresent` | debugger present |
| `0x010` | `CoCreateInstance` | WMI/process enumeration |
| `0x0DD` | `DeviceIoControl` | CE kernel-driver detection |
| `0x12E` | `FindClose` | file-scan cleanup |
| `0x133` | `FindFirstFileExA` | CE driver/file scan |
| `0x143` | `FindNextFileA` | CE driver/file scan |
| `0x245` | `GetProcAddress` | resolver itself (do NOT poison) |
| `0x4C0` | `TerminateProcess` | kill path (do NOT poison) |

Also imports/loads: `KERNEL32.dll`, `SHELL32.dll`, `ole32.dll`, `OLEAUT32.dll`,
plus an **opaque 64-byte encrypted signature blob** at `0x10035E7C`
(`7E 3B C3 E2 93 C0 2B 05 50 55 46 66 63 C1 53 8C ...`).

### 5.4 Bypass — pre-poison the API cache slots (memory-only)
Poison encoding (from `try_get_function`'s poison-write path):
`slot = ROR(0xFFFFFFFF, 0x20 - rot) ^ 0xBB40E64E`, where `rot = 0xBB40E64E & 0x1F = 0x0E`.
Since `ROR(-1,n) = -1`, **poison = `0xFFFFFFFF ^ 0xBB40E64E = 0x44BF19B1`**.

Writing `0x44BF19B1` into a slot makes `try_get_function` decode it to `0xFFFFFFFF`
(the "never resolve" marker) and return NULL immediately — the detector's
`TEST EAX,EAX / JZ` then skips that check. Slot addresses (DLL-relative to load base):

| function_id | slot RVA = `0x38350 + id*4` | API |
|---|---|---|
| `0x003` | `0x3835C` | `IsDebuggerPresent` |
| `0x010` | `0x38390` | `CoCreateInstance` |
| `0x0DD` | `0x38544` | `DeviceIoControl` |
| `0x12E` | `0x38808` | `FindClose` |
| `0x133` | `0x3881C` | `FindFirstFileExA` |
| `0x143` | `0x3885C` | `FindNextFileA` |

> The DLL uses these same slots for legitimate purposes too (file I/O). If the game
> breaks (e.g. save/render file paths), remove `Find*` / `CoCreateInstance` from the
> poison set — keep `IsDebuggerPresent` and `DeviceIoControl` (detector-specific).

---

## 6. Procedure

1. Launch `Conquer.exe` normally (no debugger).
2. Open Cheat Engine, select the `Conquer.exe` process.
3. Load `bypass_aa.ct` and run the script — it patches the EXE **and** pre-poisons
   the TqNDProtect.dll API-cache slots in one pass.
4. Now attach the Ghidra-MCP debugger (`debugger_attach Conquer.exe`), or use CE —
   the game will no longer self-close or disconnect on CE detection.
5. Patches are memory-only; restart the game to restore original behavior,
   or run the script's `[DISABLE]` block.

## 7. Caveats / notes

- The EXE check is a vtable method of the login dialog. If the dialog is re-created
  (reconnect, re-login) the patched code persists (same memory) — one application
  covers the whole session.
- The DLL is **self-decrypting**: the slot-poison works regardless of what the
  decrypted blob does, because the blob *must* route API calls through the cache.
  If a future build changes `try_get_function`'s table base/key, re-derive:
  base = `0x10038350`, key = `0xBB40E64E`, poison = `~key`.
- If the game was already running when the script is enabled, cached real pointers
  in the slots get overwritten by the poison — still effective.
- No integrity (CRC) check exists over the EXE `.text`, so in-memory patching is safe.
- If CE still trips something after this, the remaining suspects are
  `TQNDPCAnaly.dll` (packet telemetry, loaded by the EXE) — next step is dynamic
  observation with the live debugger once attach works.

---

## 8. Full anti-cheat module review (H:\client + H:\client\Env_DX9)

All anti-cheat/auxiliary DLLs were imported into Ghidra and reviewed.
Columns: how the game reaches it, what it does, and whether it can detect CE.

### 8.1 Loaded by Conquer.exe (delay-load descriptors @ 0x019DD4F0)

| DLL | Descriptor | IAT (RVA) | Slots | Purpose | CE detection? | Blocked? |
|---|---|---|---|---|---|---|
| `TqNDProtect.dll` | 0x019DD584 | 0x01654448 | 3 | self-decrypting anti-cheat; API-cache `try_get_function` | **YES** (watchdog in decrypted blob) | ✅ in hook |
| `ndac.dll` | 0x019DD534 | 0x01654474 | 26 (ordinals) | 18.7MB **VMProtect** `.gfids`; `.rc00`/`.rc02` packed exec | likely (obfuscated) | ✅ in hook |
| `Assist.dll` | 0x019DD55C | 0x01654378 | 10 | `CMonitorManager` process/window monitor (`monitor.ini`) | partial (enumerates processes) | ✅ in hook |
| `C3Browser.dll` | 0x019DD5D4 | 0x01654340 | — | embedded browser (web views) | no | ❌ (harmless) |
| `RecordGame.dll` | 0x019DD5AC | 0x01654384 | — | game recorder | no | ❌ (harmless) |

Key detail: `Assist.dll` imports `Process32First/Next` + `CreateToolhelp32Snapshot`
(process enumeration) and `GetForegroundWindow`/`EnumChildWindows`/`GetClassNameA`
(window scanning) — a process/watchdog monitor. `StartMonitor` had no statically
visible caller (started via vtable/register), so it may be armed at runtime.
`ndac.dll`'s 26 delay-load thunks had no direct code callers either — both were
never invoked through statically-tracked paths, but the crash proves one of them
(or TqNDProtect) runs at CE-open time; blocking all three IATs covers it.

### 8.2 Not statically referenced by Conquer.exe (launcher-side / auxiliary)

| DLL | Size | Purpose | CE detection? |
|---|---|---|---|
| `AntiRobotClient.dll` | 2.9MB | `AntiRobo` export; obfuscated (EFLAGS reconstruction); Winsock + registry + `GetVolumeInformationW` (machine bind) | possible but not referenced by game |
| `TQAnp.dll` | 5.3MB | `TQANP_PackVerifyData`; IPHLPAPI (MAC) + WININET | no (packet verify) |
| `TQPlat.dll` | 7.5MB | 129 stripped `EXT_` exports; `IsDebuggerPresent` string | unknown (protected) |
| `license.dll` | 3.3MB | `Inject` export; licensing + `regkey.dat` machine binding | no |
| `nd_lanucher.exe` | 2.7MB | bootstrap: `CreateProcess("Conquer")`, no injection APIs | no |

### 8.3 Checked and cleared

| DLL | Verdict |
|---|---|
| `TQNDPCAnaly.dll` | analytics SDK only (`CTQNDPCAnalyApp` event logger; `IsDebuggerPresent` is a bare name string, no callers) — not a CE detector |
| `ndCompress.dll`, `ndist.dll`, `NDSound.dll`, `TqPackage*.dll`, `tqpdata.dll` | compression/distribution/audio/package utils — not anti-cheat |

### 8.4 Bottom line

The only modules that can crash the game on CE open are the three now blocked in
`anticheat.cpp`: `TqNDProtect.dll`, `ndac.dll`, `Assist.dll`. If the crash persists
after the build with all three IATs redirected, the detector is **outside the game
process** — i.e. Kaspersky (its `klhkum` hook is injected into Conquer.exe and
Kaspersky HIPS reacts to CE's kernel driver / known-cheat process), which must be
handled via Kaspersky exclusions rather than game patching.


