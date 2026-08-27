# Reverse Engineering Notes — Conquer.exe (client 7950)

**Current status: auto-hunt FULLY WORKING from the ImGui overlay** (kills, loots
gold/items, XP + skill bars fill normally). See the "WORKING STATE" section below for
the final solution; the detailed research follows.

Ghidra project: `private_client` (Conquer.exe + GameData.dll + Role3D.dll imported).
Access path: Ghidra MCP bridge via ngrok tunnel (ghidra-mcp, bridge on 8081, plugin on 8089).


> **2026-08-27 (2): Auto-login — ImGui auto-click for the MFC Login button.**

The login screen is a real MFC dialog (`CDlgLogin`, `myshell/dlglogin.cpp`) hosting
a WS_CHILD window with real Edit (account/password) + Button (Login) HWND controls
(live-confirmed earlier by the directx_hooks.cpp subclassing work). It also hosts an
fgui canvas window named `login_xzk` (`0x01603D80`) for the themed background/buttons
(`Login_xOrangeBtn`/`Login_xRedBtn` @ `0x015598F8`/`0x01559940`).

RE-verified click chain (all on the 7950 build):
- Login button BN_CLICKED → **`FUN_LoginButtonHandler` @ `0x008A8FCA`** — `__fastcall
  (CDlgLogin*)`. Reads account (`dlg+0x13B88` std::string), password (`dlg+0x13BD0`
  buffer), group/server ints (`dlg+0x135F8`/`+0x135FC`), server-name config, then calls
  `FUN_0101C9D8`.
- **`FUN_0101C9D8` @ `0x0101C9D8`** — `login(account, password, serverName, mode, extra)`:
  mode 0 = `CMsgAccountEx` (`FUN_00F7F7E8`), mode 1 = QR code (`CMsgAccountByQRCode`,
  `FUN_00DE30E0`), mode 2 = poker (`CMsgAccountPoker`, `FUN_00F7F9E3`). The actual
  login-packet sender.
- The handler is dispatched from the big UI event dispatcher (`FUN_00A5B653` area,
  bodies run through `0x00A69E14`) with `ECX = appObj + 0x39B948` (the CDlgLogin
  instance is a member of the main app object), gated by `FUN_00BFEE8B` =
  `IsWindow(dlg+0x20) && IsWindowVisible(dlg+0x20)`.
- `FUN_LoginButtonHandler` has NO static callers (function-pointer dispatch only —
  MFC/fgui), so a byte-pattern search for its address `CA 8F 8A 00` finds nothing.
  Found via the `dlglogin.cpp` path-string xref (`0x016035F8`), which Ghidra had named
  `FUN_LoginButtonHandler`; the single `UNCONDITIONAL_CALL` xref to it is the
  dispatcher at `0x00A5B90E`.

Implementation (`auto_login.cpp`): **window-shape discovery, zero game addresses, real
mouse click.** The overlay finds the login dialog by child-window shape (≥1 Edit + ≥1
Button, process-owned), finds the Login button (pinned CtrlID override → exact-text match
on "Login"/"log in"/"enter game" etc. → fallback: longest enabled+visible non-close
button), and performs a REAL mouse click (SetCursorPos + SendInput) at the button's
screen center — `BM_CLICK` is ignored by the fgui controls (see the follow-up below).
Auto mode re-clicks every 1 s (configurable) until the dialog disappears (= login went
through), then self-disables; a manual "Click Login Now" button is also exposed. This
needs NO re-finding after a recompile (window-enumeration based).

Gotcha: `FUN_008827D2` (the server-info reader the handler calls) is NOT the login
sender — it just loads `ServerIP`/`ServerPort` etc. from ini. The one-and-only login
packet builder is `FUN_0101C9D8`.

**Follow-up fix (same day): `BM_CLICK` does NOT work — the login button is fgui.**
Live test on the 7950 client: `SendMessage(btn, BM_CLICK)` × 784 with the login dialog
up → zero effect (dialog never closed, no login attempt). The found button's Win32 text
was `"EnterGame"` (CtrlID 5680) while the visible label reads `"Log In"` — the text is
set at runtime (neither literal exists in the binary, not even in the dialog template
resource), and the fgui UI layer ignores BM_CLICK entirely.

**Second fix (same day): SendInput real clicks only worked with the ImGui overlay
CLOSED.** Live observation: with the overlay open, the auto-click did nothing; closing
the overlay (Insert) made the same button click succeed immediately. Root cause: the
overlay's subclassed WndProc (`HookedWindowProcedure` in `directx_hooks.cpp`) calls
`ImGui_ImplWin32_WndProcHandler` on EVERY message, and that handler runs
`::SetCapture(hwnd)` + `io.AddMouseButtonEvent()` on every `WM_LBUTTONDOWN`
(`imgui_impl_win32.cpp` ~line 697) — corrupting the fgui control's click handling.

**Final click mechanism (current build):** `SendMessage(btn, WM_LBUTTONDOWN,
MK_LBUTTON, center)` + `SendMessage(btn, WM_LBUTTONUP, 0, center)` — a purely
programmatic press, **no cursor movement**, wrapped in the new
`g_suppressImGuiWndProc` flag (`directx_hooks.cpp`) so `HookedWindowProcedure` skips
the ImGui WndProc handler for those two messages and the game's fgui WndProc sees them
raw (exactly as when the overlay is closed). Click methods now: 0 = Message (default),
1 = SendInput real mouse (moves cursor), 2 = BM_CLICK (proven dead). Config key
`ClickMethod` was renumbered (legacy 1 = BM_CLICK remapped to 2 on load).

Also confirmed the alternative direct-call path for future use: the app object accessor
`FUN_0041f880` (same `83 3D` lazy-accessor shape, reads `DAT_01a546f4`) and the
`CDlgLogin` instance = `appObj + 0x39B948` (the dispatcher at `0x00A5B90E` does
`LEA ECX,[EBX+0x39B948]; CALL FUN_LoginButtonHandler`). Not used — the window-shape +
message-click route needs no addresses and survives recompiles.

**Account auto-fill (added):** `auto_login.cpp` now reads `accountinfo.ini` (next to the
exe) — `[AccountN]` sections with `User=<name>` and `Use=1/0` — picks the first `Use=1`
entry and fills its `User` into the account edit (the topmost Edit child of the login
dialog, found by smallest Y) via `WM_SETTEXT`, once per dialog instance, never
overwriting a non-empty field. To get the name into the login member (`dlg+0x13B88`)
the game syncs on EN_KILLFOCUS, so the fill ends with `SetFocus(accountEdit)` →
`SetFocus(passwordEdit)` — that fires the game's own sync handler and leaves the cursor
in the password field. The `CDlgLogin::OnEnKillfocusEditAccount` handler string is
`0x016042E4` (its Catch stub at `0x0088CDF8`).

**Account typing (reworked):** the auto-fill (WM_SETTEXT + per-frame loop) was REMOVED
after the user reported it did not fill — the fgui edit controls ignore WM_SETTEXT.
The "Fill Account" button now loads `accountinfo.ini` (`[AccountN]` sections,
first `Use=1` wins, `User=` value) and TYPES the name into the account edit (the
topmost **visible** Edit child, found by smallest Y among visible edits) with real
`SendInput` `KEYEVENTF_UNICODE` keystrokes: `SetFocus(edit)` → Ctrl+A → Delete →
type the name → `SetFocus(passwordEdit)`. Real key input is exactly what a human
typing produces, so the fgui edit accepts it; the EN_KILLFOCUS sync into
`dlg+0x13B88` fires when focus moves to the password field. The debug tree lists
all Edit children (Y + text) to verify the pick. `CDlgLogin::OnEnKillfocusEditAccount`
handler string is `0x016042E4` (Catch stub at `0x0088CDF8`). The client's
`accountinfo.ini` (ANSI, `[Account1] User=halms Use=1 ...`) parses fine with
GetPrivateProfileStringA.

---

> **2026-08-27: client recompiled again (version 7950).** All hook modules
> re-pointed at the new build via Ghidra MCP. Full migration table in OFFSETS.md.
> Key AOB signatures from the 2026-08-20 work still matched; the re-find workflow
> (signature -> xref -> decompile verify) was identical to the last update.

---

## 2026-08-20 — client recompiled; all hook addresses re-located and patched

The Conquer.exe build updated (real recompile, not a uniform rebase). All four
hook modules (`auto_hunt.cpp`, `xp_skill.cpp`, `speed.cpp`, `buffs.cpp`) were
re-pointed at the new build and committed. Full old → new table + per-region
shifts: see the migration section at the top of `OFFSETS.md`.

Key re-find mechanisms that worked (repeat these on the next update):
- **`ADD ECX,0x138` byte pattern** (`81 c1 38 01 00 00`) found the new
  AddStatus (`0x00EEDD80`) / ClearStatus (`0x00EF25C5`) / ChkStatus
  (`0x00F1AF78`) and the shared core bitfield setter **`0x00A73B7E`**
  (`CMP EDI,0x240; JNC; AND EAX,0x3f; BTS ECX,EAX; SHR EDI,6` shape).
- **Behavioral caller chain** for the status apply chokepoint: the new
  MsgUserAttrib processor `FUN_01041965` calls the mgr accessor
  (`thunk_FUN_00832ab1`) then the apply fn `0x00E49AC2` — identified by
  decompiling the other msguserattrib.cpp-referencing function after
  `FUN_01041965` was found via its prologue/caller pattern.
- **XP-use gate polarity changed**: the old `JZ` gates are `JNZ` in the new
  build. `IsClientSupported()` in `xp_skill.cpp` checks the original bytes,
  so an unpatched run on the old build would have self-disabled — always
  re-verify the original bytes when re-finding.
- **Hunt brain exclusivity check**: `DAT_01a5dde4` (old `0x01A5CDB4` +0x1030)
  xrefs = exactly one READ + one WRITE, both inside the new brain
  `FUN_00f54df8` — the same exclusivity test used last time.
- **Speed cap table**: found from the new nSpeedPercent scaler
  `FUN_00dec267` (`MOV EDI,[EAX*4+0x16f8e84]` with the `CMP [EBP-4],0xc; JA`
  guard) — old `0x016F7E44` +0x1040.
- **Find-target disambiguation**: TWO functions write `{id,dist}` pairs.
  `0x00F43828` (old +0xDA0, region-consistent) is the one the hunt brain
  calls for the walk/attack path; `0x00F4344B` feeds the skill-cast path
  (→ use-skill-on-target). auto_hunt.cpp uses `0x00F43828`.

Doc-only follow-ups still open: CMsgHangUp ctor confirmation
(`0x00E5F29D`), the second-bitfield ClearStatus pair for `+0x1c8`.

---

## 2026-08-27 — client recompiled again (version 7950); all hooks re-pointed

Third recompile. Everything the overlay hooks was re-located and verified in
Ghidra (AOB scan → disassemble → decompile). Full old→new table + the durable
**AOB re-find map** live at the top of `OFFSETS.md`. What worked this time,
per anchor:

- **Globals (`DAT_01a549a0` client/hero, `DAT_01a55220` mgr, `DAT_01a58fe0`
  CUserAttribMgr)**: the `83 3D ?? ?? ?? ?? 00 75 05 E8 ?? ?? ?? ?? A1 ?? ?? ?? ??
  C3` lazy-accessor pattern still matches — but ~150 times. Disambiguate by
  disassembling the accessor and reading the global dword right after `83 3D`
  / `A1`. The accessors are `FUN_0043e581` (client), `FUN_00482805` (mgr —
  unchanged address this round), `FUN_00832a5d` (CUserAttribMgr).
- **Toggle handler**: the `6A 00 E8 ?? ?? ?? ?? 8B C8 E8 ?? ?? ?? ?? C3` pattern
  matched 40+ times; the real one is the candidate whose `CALL` target
  (`0x00F31335`) is the toggle impl (prologue `68 14 04 00 00`, `CMP byte
  [EBP+8],0`). New toggle handler `0x00BD8035`, impl `0x00F31335`.
- **Hunt brain**: the generic `6A 2C B8` prologue has ~40 hits. Picked by
  structure: entry near the old region (`0x00F556FC`), calls is-hunting right
  after the client accessor, then the `MOV EDX,[g]; ADD EDX,0x3E8; CMP EAX,EDX`
  tick gate. The tick global it reads/writes is the NEW brain tick global
  `DAT_01a5ee04` (old `0x01A5DDE4` — the exclusivity test re-verified: only the
  brain touches it).
- **Walk / find-target**: the OLD addresses now sit inside unrelated functions
  (`0x00F48B93` → inside a status-check fn; `0x00F43828` → inside another) —
  they moved entirely. Re-found as the brain's callees: the brain pushes
  `&outPair` then `ECX=mgr` and calls `0x00F4412C` (find-target, RET 4, writes
  `{id,dist}` to the out param), and pushes `(4, y, x)` with `ECX=mgr` into
  `0x00F49497` (walk, radius 4 — exactly how `auto_hunt.cpp` calls it).
- **Is-hunting check**: the brain's `CALL` right after `FUN_0043e581` =
  `0x01117C44`; the old 18-byte AOB (`E8 ?? ?? ?? ?? 84 C0 74 13 E8 ... B0 01 C3
  32 C0 C3`) still matches byte-for-byte.
- **Interval virtual / master interval**: both old AOBs matched unchanged:
  `55 8B EC 56 8B F1 83 BE ?? ?? ?? ?? 00 74 ?? FF 75 08` → `0x010B148B`;
  `6A 18 B8 ... 8B 8B 70 07 00 00 33 FF 85 C9` → `0x00DE93F2`. The decompiled
  master-interval still ends in the `role+0x44/+0x48` divisor and the
  `role+0xc0` (nSpeedPercent) path — field offsets unchanged.
- **Speed cap table**: the old address is now a string blob. Found by scanning
  for the exact 52-byte data array `{100,105,110,115,120,130,140,150,165,185,
  190,195,200}` → **`0x016F9E84`** (unique match).
- **XP gates**: all three found via the `STR_CANNOT_USE_XP_WHEN_HANGUP` string
  (now `0x01744044`) — its two code xrefs are the use-skill functions
  `0x011B39C9` (target) / `0x011B502C` (position), and the JNZ gate is the
  instruction IMMEDIATELY before the `PUSH <string>`:
  `75 4B` @ `0x011B3CE6`, `75 3C` @ `0x011B5658`. The XP-fill gate was found via
  the callers of the is-hunting check: `FUN_01116f1a` (charges `client+0xaec`)
  with the `75 49` JNZ @ `0x01116F39` right after `TEST AL,AL` of the hunting
  check and before `PUSH 0x96` (a status-150 gate).
- **Status machinery**: `ADD ECX,0x138` (`81 C1 38 01 00 00`) still finds
  AddStatus/ClearStatus/ChkStatus → `0x00EEE64D` / `0x00EF2E91` / `0x00F1B838`,
  and AddStatus's `CALL 0x00a73b8e` reveals the new bitfield core
  **`0x00A73B8E`** (same `BTS`/`SHR EDI,6` shape; the old `0x00A73B7E` is now a
  thunk to unrelated code — the bitfield core MOVED). The status apply
  chokepoint's `6A 1C B8` prologue is now useless (hundreds of matches, the
  old address hosts a different 3-arg icon-vector fn). Re-found behaviorally:
  the `msguserattrib.cpp` string xrefs lead to the MsgUserAttrib processor
  `FUN_01040f3c`, which calls
  `FUN_00e49bd7(statusId, displayType, seconds, flag, extra)` — the 6-arg
  apply, prologue still `6A 1C B8`, RET 0x14 → **`0x00E49BD7`**.
- **Gear swap**: `68 4C 09 00 00 ... 8B F1 8B 86 3C 19 00 00` still matches →
  `0x00FF2B8E` (verified: reads `hero+0x193C`, sends 0x2C/0x2D/0x198). The XP
  panel setter's OLD 13-byte signature FAILED (the new build adds `5D` POP EBP
  before `C2 04 00`) — the short `88 81 C8 0A 00 00` (`MOV [ECX+0xAC8],AL`)
  matched → `0x00AE6208`. Lesson: keep signatures short past the instruction
  that matters; prologue-only AOBs survive refactors of the epilogue.
- **My-role match**: re-found as the brain's call right after the role-list
  owner accessor (`FUN_0041f86c`) → `0x00D3313A` (thunk `ADD ECX,0x78; JMP`).

Same gate polarities as 2026-08-20 (`JNZ` gates), same client-side field
offsets (`+0x5385`, `+0xaec`, `+0x268`, `+0x138`, `mgr+0x11`, `role+0x44/
+0x48/+0xc0`, `hero+0x193C`) — only addresses moved.

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
- Hunting-active check: FUN_0111621f = `client+0x5385 != 0 && mgr && mgr+0x11 != 0`.

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
4. Optional: set auto-pick directly from the overlay (currently enabled via the client
   dialog). Find the auto-pick config flag if we want it dialog-free.
5. Verify jump-search (VIP3) engages while hunting.
6. If the binary updates: use `OFFSETS.md` (AOB signatures + object maps + string
   anchors) to re-locate every value.

---

## 2026-08-11 — Speed control (movement / attack / looting) — `src/hooks/speed.cpp`

### The interval system (ONE function controls every action speed)

Every role action (walk / run / attack / pickup / skill) gets its duration from the
per-role **action-interval virtual `FUN_010afd05`** (ECX = role, one stack arg = time
delta, `RET 4`; verified at instruction level). It forwards to the master computation
**`FUN_00de86b2`** (3drole\role.cpp) unless an override component at `role+0x8f8`
handles it (vtable call `[obj+0x80]`). Smaller interval = faster action.

`FUN_00de86b2` pipeline (for the role's current action state `role+0xb4`, states < 0xD):
1. base interval from `RoleDataQuery()` vtable+0x30
2. assorted buff/debuff percent modifiers
3. **`FUN_00deb537` — the nSpeedPercent path** (gated; move-ish states):
   `interval = interval * 100 / min(100 + role+0xc0, capTable[role+0xb4])`
   - cap table `0x016F7E44` (13 dwords) = {100,105,110,115,120,130,140,150,165,185,190,195,200}
   - mount (type 0x2c9) extra scaling from tables `0x016F7E78` / `0x016F7EAC`
   - transform states 0x78–0x7B get a baked ×5/4
   - NEVER let nSpeedPercent drop below 1 (`role+0xc0 <= -100`): the
     `CHECKF "nSpeedPercent > 0"` assert (role.cpp:0x1ae9) forces interval = 0.
4. **final generic divisor (ALL actions)**: `interval = ceil(interval*100 / (100 +
   role+0x44/100))` when `role+0x48 != 0` (and `role+0xf4` adds percent in the
   `FUN_00efb7f9` branch). `role+0x44` is in 1/100-% units: 10000 → divisor 200 → 2x.
   **No cap table on this path.**
5. final clamp: interval >= 1 (can't hit 0 from these paths).
`role+0x4a` byte = set to 1 whenever the computed interval is below base (client-side
"faster than normal" marker).

### LIVE finding: the interval virtual is hooked at runtime (server anti-cheat)

On the live server, `FUN_010afd05`'s first 5 bytes were observed overwritten with
`E9 66 3D 26 73` = `JMP 0x74313A70` (a dynamically allocated trampoline page) —
something (server anti-cheat / launcher patch) detours the classic speed-hack spot.
It comes and goes (pristine `55 8B EC ...` bytes seen both at the login screen and
in-game later). **Conclusion: no code hooks on our side.** The overlay drives speed
with data writes only, feeding the computation that runs inside the
(sometimes-)hooked function.

### My-role discovery (no hooks)

- Client object global: `DAT_01a52960` (accessor `FUN_0043e481`).
- The game's own my-role lookup is **`FUN_00d3203a`** (called by the brain via the thunk
  `FUN_00d3244a`): it walks the role list (`manager+0x4` = std::list sentinel,
  node+0x10 → role via `FUN_00d22860`) and accepts the candidate whose
  **`role+0x54` == `client+0x268`**. The list-owner singleton is `DAT_01a526bc`
  (accessor `FUN_0041f76c`, creator `FUN_0041f8f9`).
- Second id placement: `FUN_00fcd1e8` = `CALL FUN_0043e481; MOV ECX,EAX; JMP
  FUN_0098c58d` → returns `client+0x26c`; and `FUN_01000e06` compares a role's `+0x268`
  against it for message type 0x186ad. **This server leaves `client+0x26c` = 0 even
  in-game** — the scan therefore tries both variants plus a cross rule. What actually
  hit live: `role+0x268 == client+0x268` (my id was `1206741`).
- Candidate class validation: the object's vtable must contain `FUN_010afd05` or
  `FUN_00de86b2` (only role classes carry them; vtables are unaffected by the E9 hook),
  plus vtable-in-image and `role+0xb4 < 13` sanity. (First-hit rule-3 objects turned out
  to be non-roles carrying the same id — the vtable content check rejects them.)

### What speed.cpp writes every frame

- `role+0x48 = 1`, `role+0x44 = (percent-100)*100`   (uncapped final divisor)
- `role+0xc0 = percent-100`                           (nSpeedPercent / move states)
- cap table at `0x016F7E44` raised to 500 while enabled (VirtualProtect on the
  read-only page; originals restored on disable). Only affects entities with a
  positive +0xc0 — i.e. just the local role.
- Fast loot tick: `DAT_01a5cdb4 = 0` every frame → hunt brain `FUN_00f54058` ticks at
  frame rate instead of once per second (only the brain reads/writes that global —
  xref-verified).

### Pickup flow (loot speed rides on movement + interval)

`FUN_00f93854` (roleaction.cpp, `_COMMAND_PICKUP` processor on the role): state
machine — 0 = init (if already on the item cell → `FUN_00fa240d` then finish), 2/3 =
walk to the item cell (movement speed applies), then `FUN_00fa252b(0x118, itemId)`
performs the pick. Target coords are XOR-obfuscated at role+0x468..+0x478.

### Open / verify

- Whether visible WALK speed responds to the interval scaling on this server or is
  animation-driven + server-corrected (rubber-band). Attack/pickup go through the
  interval system regardless — verify in-game.
- Conditions gating the +0xc0 path (`FUN_00efb7f9` / `FUN_00deeaf0`) are not fully
  mapped; the +0x44 path is unconditional apart from `role+0xf4 == 0`.
- If the binary updates: re-find via `OFFSETS.md` (AOBs + the "nSpeedPercent > 0" and
  role-list anchors).

### Commits (speed control)

| Commit | Change |
|---|---|
| `caeec46` | speed.cpp v1: MinHook interval-scaling hook + fast loot tick |
| `461a7b1` | diagnostic byte dump at 0x010AFD05 in the unsupported-build message |
| `7810102` | v3: hook-free field writes + background my-role scan (after the E9 finding) |
| `be5468b` | no hard gate on login; auto-retry scan; scan diagnostics |
| `bd244f52` | dual-variant id matching (role+0x54/client+0x268 is the game's own pair) |
| `dede331` | vtable class validation + role+0xc0 path + raised cap table |
