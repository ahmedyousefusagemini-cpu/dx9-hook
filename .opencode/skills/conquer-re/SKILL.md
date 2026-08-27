---
name: conquer-re
description: Use when reverse engineering Conquer.exe (Conquer Online private server client) with Ghidra MCP, finding/verifying game offsets (AOB signatures, string/RTTI anchors, call-graph), implementing game functions in the hook modules (auto_hunt, xp_skill, speed, buffs, gear_swap), re-finding offsets after a client recompile, or documenting findings in OFFSETS.md / RESEARCH_NOTES.md. Also use when the user says "find this function", "update offsets", "client updated", "add a hook", "reverse X", or asks to implement a new game feature and commit+push it.
---

# Conquer.exe Reverse Engineering & Implementation Workflow

Precision RE workflow for this repo. Every step has a verification gate —
**never trust a pattern hit or an address without disassembly/decompile
confirmation**. This skill exists because blind offsets broke the client
repeatedly (wrong handlers, dead sockets, corrupted dialog state). When done,
EVERY successful finding is committed and pushed immediately.

## Repo layout (canonical knowledge)

| File | Purpose |
|---|---|
| `OFFSETS.md` | THE canonical offset reference. Top sections: latest-build migration table + **AOB re-find map** (30 numbered anchors with signatures). Read it FIRST — it is the source of truth and must be updated on every finding. |
| `RESEARCH_NOTES.md` | Dated research log. Newest entry at top after the header. Document every finding here (how it was found, verification evidence, gotchas). |
| `ConquerDX9Hook/src/hooks/*.cpp` | Hook modules. Each feature = one namespace + one file. |
| `build.bat` | Builds Release/x86 via MSBuild then copies `Release\D3DX9_43.dll` to the RDP client. No local MSBuild — verification build happens there. |
| `img` / `README.md` | UI screenshot / usage docs. |

Current client: **7950** (image base `0x00400000`, x86, MSVC). Hook modules:
`auto_hunt.cpp` (AutoHunt), `xp_skill.cpp` (XpSkill), `speed.cpp` (Speed),
`buffs.cpp` (Buffs), `gear_swap.cpp` (GearSwap), `always_jump.cpp`,
`chams.cpp`, `utils.cpp` (globals), `directx_hooks.cpp` (EndScene/WndProc),
`dllmain.cpp` (init thread).

## Phase 0 — Session start (always)

1. `git status` — tree must be clean before starting; the previous finding's
   commit+push should already be in `origin/master`.
2. `ghidra-mcp list_instances` + `ghidra-mcp get_current_program_info` — confirm
   `Conquer.exe` is open, x86:LE:32, image base `00400000`. **Check the program
   creation date**: if it is NEWER than the last documented build in
   `OFFSETS.md`, the client was recompiled — run the re-find workflow (Phase 1
   variant below) over ALL existing offsets before touching anything new.
3. Read the top of `OFFSETS.md` (latest migration table + AOB re-find map) and
   the newest `RESEARCH_NOTES.md` entry. Internalize current addresses.
4. Confirm the version the game reports (user states it, or check `version.dat`
   loader / strings) and note it in any doc updates.

## Phase 1 — Find the target

Pick anchors in this order of durability:

1. **String/RTTI anchor (most durable)** — `search_strings` for a unique
   string/key (e.g. `STR_CANNOT_USE_XP_WHEN_HANGUP`, `AutoHangUpFlag`,
   `msguserattrib.cpp`), then `get_xrefs_to` the string address. The code
   xrefs land inside the function that uses it. For message handlers, the
   source-file path strings (`network\msguserattrib.cpp`) are the best anchor.
2. **AOB signature** — use `search_byte_patterns` with a signature from the
   re-find map in `OFFSETS.md` (`??` = wildcard). Or build one from
   `read_memory` bytes of a known anchor. Check match COUNT: a unique match is
   gold; dozens/hundreds of matches need a disambiguation rule (see gotchas).
3. **Call graph** — from a verified anchor: `get_function_callers` /
   `get_function_callees` / `analyze_call_graph`. Example: the hunt brain is
   the hub — its callees ARE walk/find-target/my-role-match; its first call
   after the client accessor is the is-hunting check; its tick-gate sequence
   (`MOV EDX,[g]; ADD EDX,0x3E8; CMP EAX,EDX`) reveals the brain-tick global.
4. **Data global** — `get_xrefs_to` a global address to find readers/writers.
   Exclusivity test: a "tick" global is read+written ONLY inside one function.

### Re-find after a client recompile

The 7950 (2026-08-27) re-find proved the workflow. Do exactly this:

1. Globals first: `search_byte_patterns` `83 3D ?? ?? ?? ?? 00 75 05 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? C3`
   → hundreds of matches. `disassemble_function` each candidate accessor; the
   global dword right after `83 3D` / `A1` IS the new global. Client accessor
   is `FUN_0043e581`, manager `FUN_00482805`, CUserAttribMgr
   `FUN_00832a5d` (all verified this round).
2. Then the unique AOBs from the re-find map (auto-battle getter
   `8A 81 85 53 00 00 C3`, magic getter `8D 41 70 C3`, XP panel
   `55 8B EC 8A 45 08 88 81 C8 0A 00 00 5D C2 04 00`, XP gates
   `75 4B/75 3C 68 44 40 74 01` — the string address is embedded).
3. Behavioral chains for anything ambiguous: the status apply was re-found via
   the `msguserattrib.cpp` string → MsgUserAttrib processor → the 6-arg call
   (`statusId, displayType, seconds, flag, extra`).
4. Data arrays: the speed cap table is a 52-byte data pattern
   `{100,105,110,115,120,130,140,150,165,185,190,195,200}` — exact scan, unique.

## Phase 2 — Verify (the precision gate, NEVER skip)

For EVERY candidate address:

1. `get_function_by_address` — the address must be a FUNCTION ENTRY, not
   mid-function. If it lands inside a function body, the offset is wrong.
2. `disassemble_function` — confirm the prologue and the semantic instructions
   match the docs (e.g. toggle handler = `PUSH 0; CALL accessor; MOV ECX,EAX;
   CALL impl; RET`; swap = `PUSH 0x94C` + `MOV EAX,[ESI+0x193C]`; XP panel =
   `MOV [ECX+0xAC8],AL`).
3. `decompile_function` — confirm the behavior: argument shapes (thiscall vs
   fastcall vs cdecl — check `RET` vs `RET n`), field offsets, return values.
4. Cross-check callers/callees against the documented chain. If the docs say
   the brain calls the walk function, the found walk function must be a callee
   of the brain, with the right pushed args (`(x, y, radius)` / `&outPair`).
5. Record WHAT verified it (bytes seen, decompiled behavior) — that evidence
   goes into RESEARCH_NOTES.md.

## Phase 3 — Implement (follow existing module conventions)

### New offset constant

In the right namespace, same style as existing:

```cpp
const uintptr_t NAME_ADDRESS = 0x00XXXXXX;  // FUN_00xxxxxx - what it is
```

### Calling a game function

```cpp
// Match the REAL calling convention from the disassembly (RET vs RET n).
typedef void (__thiscall* WalkFunc)(void* mgr, int x, int y, int radius);
((WalkFunc)WALK_FUNC)(mgr, x, y, 4);
```

### Patching a gate (byte patch)

Follow `xp_skill.cpp` exactly: `BytePatch {address, original, patched}` array,
`IsClientSupported()` verifying the ORIGINAL bytes still hold (never patch a
changed build blindly), `VirtualProtect(PAGE_EXECUTE_READWRITE)` write,
restore on disable.

### MinHook hook

Prologue sanity-check BEFORE `MH_CreateHook` (like buffs.cpp does with
`6A 1C B8`): read the first bytes, verify they match, else bail silently.
Then `MH_CreateHook` → `MH_EnableHook`, guard with an `installed` bool.
Hook signature must match the real convention (`__fastcall(ecx, edx, ...)` for
thiscall with the dummy edx).

### Field reads/writes

Use the documented offsets (`client+0x5385`, `+0xaec`, `+0x268`, `+0x138`
bitfield, `mgr+0x11`, `role+0x44/+0x48/+0xc0`, `hero+0x193C`). Guard with
`IsBadReadPtr` and `__try/__except` when the game does MFC/heavy work — a
crash in a hook kills the whole client.

### UI wiring

`imgui_interface.cpp`: checkbox/slider in the matching `Render*Interface()`
section; per-frame state in `Apply*ClientState()` (runs with the overlay
closed). Keep the same comment style.

### New module

Copy the structure of `buffs.cpp`/`speed.cpp`: header comment block (what +
verified anchors), `namespace`, constants, state, hooks, `Apply*ClientState`,
`Render*Interface`, and add the file to `ConquerDX9Hook.vcxproj` (ClCompile).
`dllmain.cpp` externs for anything the init thread needs.

## Phase 4 — Document (mandatory, same commit)

1. `OFFSETS.md`:
   - New finding → update the AOB re-find map (or add a row) with the
     current-build bytes from `read_memory`.
   - Client recompile → add a new dated migration table at the top (keep old
     ones as history).
   - Verify the "field offsets unchanged" note still holds.
2. `RESEARCH_NOTES.md`: new dated section at the top — what was found, which
   anchor type found it, the disambiguation rule, the verification evidence,
   and any gotchas (changed prologues, non-unique patterns, polarity changes).
3. Update stale `// comment` addresses in the module itself.

## Phase 5 — Commit + auto-push (after EVERY successful finding)

- One commit per finding. Style: lowercase verb, concise, mention the
  addresses/functions. Examples from this repo:
  - `update all offsets for client 7950 build`
  - `add AOB re-find map for 7950 build + document re-find workflow`
  - `fix: add server-select (FUN_00883ed4) before login handler`
- `git add -A` → `git commit -m "<message>"` → `git push origin master`.
- **Push immediately after every successful finding** — do not batch findings
  into one commit, do not wait for the user to ask.
- Only build-verify via `build.bat` when asked (it needs the RDP client up).

## Gotchas (all learned the hard way in this repo)

- **MSVC prologue is everywhere**: `PUSH 0xNN; MOV EAX,imm; CALL` (and
  `6A xx B8`) appears at the start of EVERY function. Never treat it as
  unique. The hunt brain, find-target, etc. all needed behavioral checks.
- **The accessor pattern matches ~150 times** — disambiguate by the global
  dword, never by position.
- **Old addresses point at unrelated functions after a recompile** — an
  address that was `FUN_00f48b93` is now INSIDE a different function. Always
  re-verify; `IsClientSupported()` byte checks exist exactly for this.
- **Signatures go stale**: the XP-panel setter's old 13-byte signature failed
  because the new build added `POP EBP` before `RET 4`. Keep AOBs short past
  the semantic instruction, and always disassemble to confirm.
- **Prologue AOBs become non-unique**: the status-apply `6A 1C B8` prologue
  now matches hundreds of functions. Behavioral anchors (string xrefs →
  callers) outlive prologues.
- **Field offsets survive recompiles** (0x5385, 0xaec, 0x138, 0x193C, 0x44,
  0xc0...) even when function addresses move — verify fields separately from
  code addresses.
- **The hunt brain is the hub**: find it (is-hunting call right after the
  client accessor + the 0x3E8 tick-gate), then walk its callees for
  walk/find-target/my-role, and read its tick global for the brain-tick
  constant.
- **IsClientSupported() must check the ORIGINAL bytes** — a changed build
  self-disables instead of patching garbage.
- **Gate polarity can flip between builds** (JZ → JNZ) — re-verify polarity,
  not just the address.
- **Never send packets you don't need**: the 0x855 notify makes the server
  reset XP — client-side state writes are preferred over server packets.
- **The DLL loads twice** (proxy + injected) — hooks must be idempotent and
  single-owner (see the old autologin single-instance guard pattern).

## Quick anchor cheat sheet (7950 build — verify against OFFSETS.md)

- client/hero global `0x01A549A0` (accessor `FUN_0043e581`)
- manager global `0x01A55220` (accessor `FUN_00482805`)
- CUserAttribMgr `0x01A58FE0` (accessor `FUN_00832a5d`)
- toggle handler `0x00BD8035` → impl `0x00F31335`
- hunt brain `0x00F556FC` (tick global `0x01A5EE04`)
- walk `0x00F49497` / find-target `0x00F4412C` / my-role `0x00D3313A`
- is-hunting `0x01117C44`
- interval virtual `0x010B148B` → master `0x00DE93F2` → cap table `0x016F9E84`
- XP gates `0x01116F39` / `0x011B3CE6` / `0x011B5658`; use-skill `0x011B39C9`
- status apply `0x00E49BD7` / bitset `0x00A73B8E` / Add/Clear/Chk
  `0x00EEE64D` / `0x00EF2E91` / `0x00F1B838`
- swap `0x00FF2B8E` / XP panel `0x00AE6208` / magic getter `0x00D96E6C`
