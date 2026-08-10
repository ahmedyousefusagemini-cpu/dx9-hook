# Reverse Engineering Notes — Conquer.exe (client 7937)

**Current status: auto-hunt FULLY WORKING from the ImGui overlay** (kills, loots
gold/items, XP + skill bars fill normally). See the "WORKING STATE" section below for
the final solution; the detailed research follows.

Ghidra project: `private_client` (Conquer.exe + GameData.dll + Role3D.dll imported).
Access path: Ghidra MCP bridge via ngrok tunnel (ghidra-mcp, bridge on 8081, plugin on 8089).

---

## ✅ XP skills while auto-hunting (2026-08-10, night) — client block removed

**Problem:** with auto-hunt engaged, activating an XP skill was refused with
"[System] Unable to use XP skills when auto-fighting"
(string key `STR_CANNOT_USE_XP_WHEN_HANGUP` @ `0x01741FA4`).

**Root cause — three gates, all reading `IsHunting` (`FUN_0111621f`):**

1. `FUN_011154f5` (XP charge-bar fill): the 0-100 XP bar (object `+0xaec`) is only
   incremented when NOT hunting — while hunting the bar never charges client-side.
   Callers: `FUN_011354b1` (kill/combo tick, `FUN_011154f5(1)`) and `FUN_00d3fb0f`
   (projectile-complete on self → GreenGlow effect → `FUN_011154f5(1)` + notify 0x40f).
2. `FUN_011b1ec9` (use skill on target) and 3. `FUN_011b3503` (use skill at position):
   `if (IsHunting && currentSkill->field_0x30 == 1)` → show the string and bail.
   `currentSkill` = `FUN_00d9612c(client)` = `client + 0x70` (`LEA EAX,[ECX+0x70]; RET`);
   its `+0x30` dword == 1 marks an XP-type skill. `find_undocumented_by_string`
   confirms exactly these two functions reference the block string.

**Fix — three 2-byte code patches applied live by the overlay** (new
`src/hooks/xp_skill.cpp`, "Allow XP skills while hunting" checkbox):

| Site | Function | Original | Patched | Effect |
|---|---|---|---|---|
| `0x01115514` | FUN_011154f5 | `75 49` JNZ | `90 90` NOPs | XP bar charges while hunting |
| `0x011B21D8` | FUN_011b1ec9 | `74 59` JZ | `EB 59` JMP | block never fires (target skills) |
| `0x011B3B21` | FUN_011b3503 | `74 4A` JZ | `EB 4A` JMP | block never fires (position skills) |

Each site is guarded by an original-byte check (same pattern as
`AutoHunt::IsClientSupported`) so the feature self-disables on a different build.
Server side needs nothing: the 0x855 packet stays withheld, so the server treats the
XP pop as normal gameplay.

Note: the hunt brain (`FUN_00f54058`) itself calls `FUN_011b1ec9` / `FUN_011b3503`,
so brain-driven XP skills are unblocked too.

---

## ✅ WORKING STATE (2026-08-10, late PM) — auto-hunt fully working

The breakthrough was realizing the hunting is **client-driven** and the 0x855 packet is
the *problem*, not the trigger. Three pieces, all in `src/hooks/auto_hunt.cpp`:

### 1. Client-side activation (don't rely on the packet)
The in-game toggle `FUN_00bd7355` only *sends* the 0x855 packet — it never sets the
client hunting state (verified at instruction level). A bare packet toggle played the
activation effect but never hunted. The overlay instead asserts the client state
directly **every frame** (so a server update can't knock it off):
- `mgr+0x11 = 1`   (hunting-active flag)
- `client+0x5385 = 1` (auto-battle flag)

That is the exact gate the per-frame hunt brain `FUN_00f54058` checks
(`FUN_0111621f == client+0x5385 != 0 && mgr+0x11 != 0`). Setting both makes the brain
engage and the character hunt.

### 2. Do NOT send the 0x855 packet (fixes the XP reset)
Sending 0x855 tells the server "this character is auto-hunting", and the server then
**reset the XP bar to 0 and stopped counting kills**. The hunting is client-driven, so
the server doesn't need the packet. Withholding it → the server treats the kills as
normal gameplay → XP and skill bars fill normally. There's an opt-in "Notify server"
checkbox (default OFF) in case a server ever needs it.

### 3. VIP level spoof (client-side)
The VIP getter `FUN_00fd3271` reads the level from the client object (`client+0x9e4`,
or `+0x9ec` when the `FUN_01118b17` branch flag is set). The auto-hunt feature gates
`FUN_00f3314b` / `FUN_00f3316c` just do `requiredLevel <= vipLevel`. The overlay forces
both fields to `6` every frame → passes every gate (jump-search VIP3+, auto-pick VIP4+).
**Client-side only** — server-enforced VIP features (shop, teleport) still fail.

### Loot (auto-pick)
Auto-pick is a separate VIP4-gated option. It worked once the option was enabled in the
client's auto-hunt dialog (the VIP spoof unlocks the checkbox so it can be ticked).

### New findings this session
- **Message factory** `FUN_00f36f4e` = `CNetMsg::CreateNetMsg` — maps packet type →
  message ctor (`case 0x855` → `CMsgHangUp`).
- **Incoming messages route to Lua**: dispatch `FUN_0103ef3e` → `FUN_00ba2d7b` →
  `FUN_00c3c2d0` → `CQMain_OnNetMsg`. So the 0x855 ack is handled in Lua — that's why
  there's no C++ manager state-writer (the earlier "missing setter" mystery).
- `CMsgHangUp` vtable @ `0x017012d8`: [0]=dtor, [3]=type-check, [4]=getter,
  [5]=`FUN_010ce686` (Process/send — what the toggle calls), [6]=error/assert.
- Manager state confirmed live: idle word `0x001`, hunting word `0x101`
  (only byte `+0x11` flips).

### Commits (repo `dx9-hook`, branch `master`)
| Commit | Change |
|---|---|
| `b0d7494` | initial auto-hunt (bare toggle) + debug tree |
| `6e3acde` | client-side state assertion (made the brain engage) |
| `ddae3cc` | also assert `client+0x5385` (fixed the "shows Idle" gate) |
| `824ebfb` | VIP spoof |
| `a93cb41` | don't send the 0x855 packet by default (fixed XP reset) |
| `f7605b5` | added `OFFSETS.md` (durable signatures/offsets for re-finding after updates) |

### Open / next
- Auto-pick is currently enabled via the client dialog; could be set directly from the
  overlay if we want it fully dialog-free (find the auto-pick config flag).
- Verify jump-search (VIP3) engages while hunting.

---

## Auto-Hunt system (the auto-grind feature)

The auto-hunt feature is implemented by the class **`CAutoHangUpMgr`** ("HangUp" / 挂机 =
Chinese game-dev term for AFK auto-grinding). Its settings window is the dialog class
**`CDlgAutoHangUp`**.

### Key addresses (image base 0x00400000)

| What | Address | Notes |
|---|---|---|
| Global manager singleton | `0x01a531e0` | `CAutoHangUpMgr*`, null until first use |
| Singleton accessor | `FUN_00482705` (0x00482705) | `if (DAT_01a531e0 == 0) FUN_004830ef(); return DAT_01a531e0;` — everything calls this first |
| Singleton creator (critical-section guarded) | `FUN_004830ef` (0x004830ef) | creates + stores instance, registers atexit cleanup |
| Manager factory (new 0x44 + ctor) | `FUN_0047b74e` (0x0047b74e) | `FUN_0125fb3e(0x44)` then `FUN_00f26499()` |
| Manager constructor | `FUN_00f26499` (0x00f26499) | sets vtable, loads AttackRange from `ini/Info.ini`, fills `DAT_01a5cdb8[3]` |
| Manager destructor / scalar dtor | `FUN_00f2a150` / `FUN_00f2d133` | dtor body / deleting dtor (vtable[0]) |
| Manager vtable | `0x01713bb4` | vtable[0] = FUN_00f2d133 (scalar deleting destructor); class has only that virtual — all real methods are non-virtual, called directly |
| Manager RTTI type descriptor name | `0x01a498b9` | `".?AVCAutoHangUpMgr@@"` |
| Dialog RTTI type descriptor name | `0x019f3649` | `".?AVCDlgAutoHangUp@@"` (name starts 0x019f3648 with the '.') |
| Dialog vtables | `0x015086fc` and `0x01508914` | two vtables (multiple inheritance); via COLs 0x0179b358 / 0x0179b3b8 |
| Dialog-button toggle handler | `FUN_00bd7355` (0x00bd7355) | 5 instructions, no args: `PUSH 0; CALL FUN_00482705; MOV ECX,EAX; CALL FUN_00f2fcd5; RET` |
| Toggle implementation | `FUN_00f2fcd5` (0x00f2fcd5) | `void __thiscall Toggle(CAutoHangUpMgr* this, int flag)` — RET 4 |
| Is-hunting check | `FUN_0111621f` (0x0111621f) | takes client in **ECX** (undocumented); see warning below |
| Client object global | `DAT_01a52960` (0x01a52960) | via accessor `FUN_0043e481`; null outside the game |

### Manager object layout (size 0x44)

```
+0x00  vtable ptr
+0x04  dword = 0          (ctor)
+0x08  dword = 0x7fffffff (ctor)
+0x0c  dword = 0x7fffffff (ctor)
+0x10  WORD state — 0x001 idle / 0x101 hunting (only byte +0x11 flips; confirmed live)
+0x11  byte  — hunting-active flag; read by getter FUN_00f4761b; the brain's gate
+0x12  byte  — ctor sets 0; read by getter FUN_00f4761f; per-frame dispatcher FUN_0112ef9d checks it
+0x14  DWORD timestamp — written by FUN_00f2fcd5 (timeGetTime) when called with flag=0
+0x18..+0x2c assorted lists/flags (ctor zeroes); +0x18/+0x1c = hunt anchor X/Y, +0x04 = radius
```

### Manager methods identified so far

| Address | Behavior |
|---|---|
| FUN_00f4761b (0x00f4761b) | `return *(byte*)(mgr+0x11)` |
| FUN_00f4761f (0x00f4761f) | `return *(byte*)(mgr+0x12)` |
| FUN_00f476c3 (0x00f476c3) | position/range validation (fields +0x18/+0x1c vs +0x4) |
| FUN_00f47cd1 (0x00f47cd1) | validation, returns bool (checks +0x268, calls FUN_00fd497f) |
| FUN_00f4760f (0x00f4760f, 59 xrefs) | forwards fields +8/+0xc to FUN_00f475f0 |
| FUN_00f2fcd5 (0x00f2fcd5) | Toggle(flag): if flag==0 → mgr+0x14 = timeGetTime(); constructs stack CMsgHangUp, fills via FUN_00e6a590(flag), sends via FUN_010ce686, destroys via FUN_00e6179c |
| FUN_00e5e50d (0x00e5e50d) | CMsgHangUp constructor (sets `CMsgHangUp::vftable`, msg buffer init 0x3ea) |
| FUN_00e6179c (0x00e6179c) | CMsgHangUp destructor |
| FUN_00e6a590 (0x00e6a590) | PACKET BUILDER: writes [0]=0x16, [2]=0x855 (packet type 2133), [4]=(arg^1)*2+1 — the auto-hunt start/stop notification packet |

### Toggle chain (verified at instruction level 2026-08-10 PM)

```
command 0x201 (dialog Begin) / 0x202 (dialog Stop)   <- BOTH buttons run the SAME code
  -> FUN_00be7d0d  (dispatcher: if cmd-0x201 < 2 ->)
      -> FUN_00bd7355   (PUSH 0; CALL FUN_00482705; MOV ECX,EAX; CALL FUN_00f2fcd5; RET)
      -> FUN_00c25801(0)  (big CWnd show/hide: hides the dialog; not needed by overlay)
```

Because Begin and Stop send the identical packet (field = 3 for flag=0), the SERVER
performs the actual toggle — client code must gate on current state before calling.

`FUN_00bca328` = same pair (FUN_00bd7355 + FUN_00c25801(0)); third FUN_00bd7355 caller
at 0x00a1665b.

Handler table referencing FUN_00be7d0d: `0x016a9f70` (array of function pointers:
0x00be7d0d, 0x012625f4, 0x01262600, 0x01262606, 0x0126260c, ... — command-id -> handler table).

### Client-level auto-battle flag

- Client object (from FUN_0043e481 accessor, global `DAT_01a52960`) has a byte flag at `client+0x5385`
- Getter: `FUN_0111524b` (0x0111524b) — literally `MOV AL,[ECX+0x5385]; RET`, NO null check.
  WARNING: FUN_0111621f passes ECX straight through, so never call it bare from the
  overlay — replicate with plain reads: DAT_01a52960 -> client+0x5385; DAT_01a531e0 -> mgr+0x11.
- Setter: `FUN_01140772` (0x01140772) — `SetAutoBattle(client, bool)`: if changed, fires "Auto_battle"
  event (FUN_00de457e when turning off / FUN_00ddbf64 when turning on) then writes the byte.
  No direct callers (called via vtable).
- Read every frame by the action dispatcher FUN_0112ef9d (calls FUN_00482705 + FUN_00f4761f).
- Hunting-active check: FUN_0111621f = `client+0x5385 != 0 && mgr+0x11 != 0`.

### Other leads

- `FUN_00bd7355` callers: FUN_00bca328, FUN_00be7d0d, and one at 0x00a1665b.
- Dialog packet handlers cluster: 0x004c1641 ... 0x004c1bd9 (serialize dialog state to/from packets).
- Conquer.exe: 208,365 functions analyzed; strings are mostly in data files (exe has few UI strings).

---

## 2026-08-10 (PM) — Toggle path resolved; ImGui integration shipped

### Corrections to earlier hypotheses

- **FUN_00c822eb is NOT the "start hunting" state setter.** It initializes a small
  0x14-byte per-item state struct (zeroes +0x00..+0x0C, word +0x10 = 0x101, byte +0x12 = 0).
  Only callers: `FUN_00c8238b` (ctor of a 0x80-byte dialog-list item; stores the struct
  at item+0x40) and `FUN_00c824ff` (ctor of a 0x60-byte object; two such structs at
  +0x10/+0x14) — both called only from `FUN_00c8482d`, a packet/config deserializer
  (FUN_00ca6xxx reader family: strings, dwords, bytes, floats, shorts). So 0x101 is a
  load-time default on the item struct, never a runtime write to CAutoHangUpMgr; the
  manager and the item struct merely share the +0x10 state-word layout.
- Exhaustive byte-pattern scans (`66 C7 4? 10 xx xx` = `mov word [reg+0x10], imm16`):
  - imm = 0x0101 → unique hit 00c822fc (the item-struct initializer above).
  - imm = 0x0100 → 3 hits: manager ctor 00f264e2, manager dtor 00f2a19c, and
    FUN_010a8c39 @ 010a8c4f (different class; sets +0x10=0x100 alongside timeGetTime).
  - **No immediate-write "stop hunting" setter exists for the manager.** The runtime
    state flip is the client-side byte write (which the overlay now performs) — see the
    WORKING STATE section.

### Overlay integration (src/hooks/auto_hunt.cpp)

- Originally called the game's toggle `FUN_00bd7355` directly. **That turned out to be
  insufficient** — the toggle only sends the notify packet and never sets the client
  hunting state, and the packet made the server reset XP. See the WORKING STATE section
  for the final client-side approach that replaced it.
- Sanity guard: feature self-disables unless bytes at 0x00BD7355 are `6A 00 E8`
  (PUSH 0; CALL) — protects against running on a different client build.
- A collapsible "Auto Hunt Debug" tree dumps live client+0x5385 / client+0x9e4 (VIP) and
  mgr+0x10/+0x11/+0x12/+0x14.
- Calls run inside HookedEndScene (game thread on this client).

---

## Overlay/DLL work (separate repo state)

- D3DX9_43 proxy DLL, ImGui overlay (INSERT), memory scanner with background scans + unknown-value
  snapshot scans, input hooked on BOTH parent window (keyboard) and render window (mouse),
  window non-collapsible reverted to collapsible per user request, debug input counters added.
- Auto Hunt section: client-side Start/Stop + VIP spoof + optional notify-packet + debug state dump.

## Next steps

1. ~~Find the auto-hunt start mechanism~~ — **done**: it's client-side. Assert
   `mgr+0x11=1` + `client+0x5385=1` every frame; don't send the 0x855 packet.
2. ~~Fix XP reset~~ — **done**: withholding the 0x855 packet keeps the server out of
   auto-hunt mode so XP fills normally.
3. ~~VIP unlock~~ — **done**: force `client+0x9e4`/`+0x9ec` = 6 (jump-search + auto-pick).
4. ~~XP skills while hunting~~ — **done** (2026-08-10 night): patch the three
   `IsHunting` gates (see the top section). New module `src/hooks/xp_skill.cpp`.
5. Optional: set auto-pick directly from the overlay (currently enabled via the client
   dialog). Find the auto-pick config flag if we want it dialog-free.
6. Verify jump-search (VIP3) engages while hunting.
7. If the binary updates: use `OFFSETS.md` (AOB signatures + object maps + string
   anchors) to re-locate every value.
