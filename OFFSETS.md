# RE Offsets & Signatures — Conquer.exe (client 7937)

Durable reverse-engineering reference for the auto-hunt / VIP / speed work. **Absolute
addresses shift on every recompile** — the byte signatures (AOB) and the unique
string/RTTI anchors below are what let you re-locate each value after a binary
update.

Image base for all addresses below: `0x00400000`. Build analyzed: client 7937.

> **2026-08-20: client recompiled (new build).** All addresses below were
> re-located and VERIFIED against the new binary; the old → new migration
> table is in the next section. The older tables further down still list
> previous-build addresses (kept as the signature/anchor reference — every
> entry's "Found via" mechanism still works on the new build).

---

## 2026-08-20 rebuild — verified old → new address table

The update is a real recompile (not a uniform rebase). Per-region shifts:
`+0x100` (0x004xxxxx accessors), `+0xD30` (0x00D9xxxx, 0x00DEBxxx, magic
getter), `+0xD90` (0x00E5/0x00E6/0x010C region), `+0xDA0` (0x00F1/0x00F3/0x00F4),
`+0x1020` (0x01A5xxxx globals), `+0x1035` (0x0111xxxx), `+0x1040` (0x016F7xxx
tables), `+0x10BD` (0x011Bxxxx gates). Every entry below was re-verified by
disassembly / byte check / xref in Ghidra.

| Old (previous build) | New (this build) | What |
|---|---|---|
| `0x01A52960` | `0x01A53980` | client object global `DAT_01a53980` |
| `0x01A531E0` | `0x01A54200` | CAutoHangUpMgr singleton global |
| `0x00482705` | `0x00482805` | manager accessor (lazy-create) |
| `0x00BD7355` | `0x00BD8025` | in-game toggle handler (0x855 notify) |
| `0x00F2FCD5` | `0x00F30A75` | toggle impl `Toggle(mgr, flag)` |
| `0x00E6A590` | `0x00E6B320` | CMsgHangUp packet builder (`B9 55 08 00 00`) |
| `0x00E5E50D` | `0x00E5F29D` | CMsgHangUp ctor (candidate) |
| `0x00E6388E` | `0x00E6252C` | CMsgHangUp dtor |
| `0x010CE686` | `0x010CF416` | CMsgHangUp Process/send (vtable[5]) |
| `0x00F36F4E` | `0x00F37CEE` | `CNetMsg::CreateNetMsg` factory |
| `0x0103EF3E` | `0x0103FC75` | incoming dispatch → Lua |
| `0x00BA2D7B` | `0x00BA3A4B` | dispatch helper (→ CQMain_OnNetMsg) |
| `0x0111621F` | `0x01117254` | Is-hunting check (`client+0x5385 && mgr+0x11`) |
| `0x0111524B` | `0x01116280` | auto-battle byte getter (`8A 81 85 53 00 00 C3`) |
| `0x00F54058` | `0x00F54DF8` | per-frame hunt brain |
| `0x01A5CDB4` | `0x01A5DDE4` | brain tick timestamp global (read+write only in the brain) |
| `0x00F47DF3` | `0x00F48B93` | walk-to-coord (brain helper) |
| `0x00F42A88` | `0x00F43828` | find-target (brain helper, writes `{id,dist}` pair) |
| `0x00DEB082` | `0x00DEBDB2` | player-pos getter (client +0x98 chain walk) |
| `0x00FD3271` | `0x00FD4038` | VIP level getter |
| `0x01118B17` | `0x01119B4C` | VIP field-branch check |
| `0x00F3314B` / `0x00F3316C` | `0x00F33EEB` / `0x00F33F0C` | VIP feature gates (jump-search / auto-pick) |
| `0x010AFD05` | `0x010B0A9A` | action-interval virtual (vtable check) |
| `0x00DE86B2` | `0x00DE93E2` | master interval computation |
| `0x00DEB537` | `0x00DEC267` | nSpeedPercent scaler (cap-table consumer) |
| `0x016F7E44` | `0x016F8E84` | speed cap table (13 dwords) |
| `0x016F7E78` / `0x016F7EAC` | `0x016F8EB8` / `0x016F8EEC` | mount speed tables |
| `0x00F93854` | `0x00F945F4` | pickup processor (roleaction.cpp) |
| `0x00D9612C` | `0x00D96E5C` | magic-info getter (this + 0x70) |
| `0x01115514` | `0x01116549` | XP-fill gate (`75 49` → `90 90`; FUN_011154f5 → FUN_0111652a) |
| `0x011B21D8` | `0x011B3286` | use-skill-on-target gate — **polarity changed**: old `JZ 74 59` is now `JNZ 75 4B` → patch `EB 4B` (FUN_011b1ec9 → FUN_011b2f69) |
| `0x011B3B21` | `0x011B4BF8` | use-skill-at-position gate — **polarity changed**: `JNZ 75 3C` → `EB 3C` (FUN_011b3503 → FUN_011b45cc) |
| `0x011B1EC9` | `0x011B2F69` | use skill on target (callable: `__thiscall(client, magicId, selfUid, 0, 1)`) |
| `0x011A930F` | `0x011B3B05` | magic-info +0x5C id compare (inside FUN_011b2f69) |
| `0x01741FA4` | `0x01743024` | string `STR_CANNOT_USE_XP_WHEN_HANGUP` |
| `0x01A56F20` | `0x01A57F40` | CUserAttribMgr singleton global |
| `0x008329B1` | `0x00832AB1` | CUserAttribMgr accessor (reads `DAT_01a57f40`) |
| `0x00A72EAB` | `0x00A73B7E` | status bitfield core set/clear (`C3DUser` bitfield +0x138 / +0x1c8) |
| `0x00EECFF1` | `0x00EEDD80` | `C3DUser::AddStatus` (+0x1c8 pair: `0x00EEDDA0`) |
| `0x00EF1835` | `0x00EF25C5` | `C3DUser::ClearStatus` |
| `0x00F1A1D8` | `0x00F1AF78` | `C3DUser::ChkStatus` |
| `0x00E48D33` | `0x00E49AC2` | status apply chokepoint (`6A 1C B8` prologue; 6-arg thiscall) |
| `0x01040C2E` | `0x01041965` | MsgUserAttrib processor (calls the accessor + apply chokepoint) |

Gate-patch polarity note: the old `JZ` use-skill gates became `JNZ` in this
build (same `skip if NOT hunting` semantics after the `JNZ`→`JMP` patch).

---

## How to re-find a value after a binary update

1. **Byte signature (AOB)** — pattern-scan the new binary for the signature
   (`??` = wildcard byte). Verify the match is unique.
2. **String / RTTI anchor** — find a unique string (e.g. `"AutoHangUpFlag"`,
   `".?AVCAutoHangUpMgr@@"`), then follow the code xref to the function.
3. **Call graph** — reach a known function from a found one (e.g. the toggle
   handler calls the manager accessor; the accessor reads the manager global).

---

## Globals

| What | Address | Found via |
|---|---|---|
| Client object | `DAT_01a52960` = `0x01A52960` | read by the client accessor `FUN_0043e481` |
| CAutoHangUpMgr singleton | `DAT_01a531e0` = `0x01A531E0` | read by the manager accessor `FUN_00482705` |
| Role/entity list owner singleton | `DAT_01a526bc` = `0x01A526BC` | accessor `FUN_0041f76c` (creator `FUN_0041f8f9`) |
| Second config singleton | `DAT_01a52980` = `0x01A52980` | accessor `FUN_0043e495` (used by the hunt brain for ini flags) |
| Hunt brain tick timestamp | `DAT_01a5cdb4` = `0x01A5CDB4` | read+written ONLY by `FUN_00f54058` (xref-verified) — the 1000 ms brain gate |
| Speed cap table | `0x016F7E44` (13 dwords) | indexed by `role+0xb4` inside `FUN_00deb537` |
| Mount speed tables | `0x016F7E78` / `0x016F7EAC` (13 dwords each) | mount (type 0x2c9) scaling in `FUN_00deb537` |

---

## Functions

> Addresses are this build. Signatures are the re-find mechanism.

### Accessors

**Client accessor — `FUN_0043e481` @ `0x0043E481`**
Returns the client object (`DAT_01a52960`), lazy-creating it. Almost every
auto-hunt call starts here.
```
83 3D ?? ?? ?? ?? 00 75 05 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? C3
```
The client global address is the dword right after `83 3D` (and after `A1`).

**Manager accessor — `FUN_00482705` @ `0x00482705`**
Returns the CAutoHangUpMgr singleton (`DAT_01a531e0`), lazy-creating it.
```
83 3D ?? ?? ?? ?? 00 75 05 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? C3
```
(Same code shape as the client accessor — disambiguate by which global it
reads: this one reads the manager singleton.)

### Auto-hunt toggle / packet

**Toggle handler — `FUN_00bd7355` @ `0x00BD7355`**  
Exactly what the in-game dialog Begin/Stop buttons and the icon run:
`GetManager()` then `mgr->Toggle(0)`. No args, plain `RET`.
```
6A 00 E8 ?? ?? ?? ?? 8B C8 E8 ?? ?? ?? ?? C3
```

**Toggle impl — `FUN_00f2fcd5` @ `0x00F2FCD5`**  
`void __thiscall Toggle(CAutoHangUpMgr* this, int flag)` (`RET 4`). Stamps
`mgr+0x14 = timeGetTime()` when flag==0, builds CMsgHangUp, sends it. **Does
NOT write the hunting state — it only notifies the server.**
```
68 ?? ?? ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B F1 80 7D 08 00 75 ?? E8 ?? ?? ?? ?? 89 46 14
```
(`89 46 14` = `MOV [ESI+0x14],EAX` is the `mgr+0x14` timestamp write — the anchor.)

**Packet builder — `FUN_00e6a590` @ `0x00E6A590`**  
Fills the CMsgHangUp packet: `[0]=0x16`, `[2]=0x855` (type 2133),
`[4]=(arg^1)*2+1` (=3 for the toggle). Notify only — no config payload.
```
55 8B EC 56 8B F1 E8 ?? ?? ?? ?? 8B 86 ?? ?? ?? ?? 6A 16 59 66 89 08 B9 55 08 00 00
```
(contains `B9 55 08 00 00` = `MOV ECX,0x855` = the packet type — very unique.)

### State checks

**Is-hunting — `FUN_0111621f` @ `0x0111621F`**  
Returns true while hunting: `client+0x5385 != 0 && mgr && mgr+0x11 != 0`.
**Takes the client in ECX with no null check — don't call it bare; replicate
with plain reads.**
```
E8 ?? ?? ?? ?? 84 C0 74 13 E8 ?? ?? ?? ?? 8B C8 E8 ?? ?? ?? ?? 84 C0 74 03 B0 01 C3 32 C0 C3
```

**Client auto-battle byte getter — `FUN_0111524b` @ `0x0111524B`**  
`return *(byte*)(client+0x5385)`. The offset `0x5385` is embedded in the bytes.
```
8A 81 85 53 00 00 C3
```

**Manager hunting/gate getters — `FUN_00f4761b` / `FUN_00f4761f` @ `0x00F4761B`**  
Two adjacent getters: `return *(byte*)(mgr+0x11)` then `return *(byte*)(mgr+0x12)`.
```
8A 41 11 C3 8A 41 12 C3
```

### Hunt brain

**Per-frame hunt brain — `FUN_00f54058` @ `0x00F54058`**  
The client-side auto-hunt loop: gates on `IsHunting`, rate-limits to 1s, then
finds targets / walks / attacks / loots. Each phase is gated by an
`AutoHangUpFlag<N>` ini bit and (for jump/loot) a VIP gate.
```
6A 2C B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B D9 89 5D E8 E8 ?? ?? ?? ?? 8B C8 E8 ?? ?? ?? ?? 84 C0
```
Called once per frame from `FUN_01128c86` (the big per-frame updater).

### VIP

**VIP level getter — `FUN_00fd3271` @ `0x00FD3271`**  
Returns the VIP level (0–6) from the client object: `client+0x9e4` normally,
`client+0x9ec` if the `FUN_01118b17` branch flag is set.
```
56 8B F1 E8 ?? ?? ?? ?? 8B C8 E8 ?? ?? ?? ?? 84 C0 74 08 8B 86 ?? ?? ?? ??
```

**VIP branch check — `FUN_01118b17` @ `0x01118B17`**  
`return (client+0x57f4 >> 10) & 1` — selects which VIP field the getter reads.
```
8B 81 F4 57 00 00 C1 E8 0A 24 01 C3
```

**VIP feature gates — `FUN_00f3314b` @ `0x00F3314B`, `FUN_00f3316c` @ `0x00F3316C`**  
Both return `requiredLevel <= vipLevel` (the auto-hunt jump-search / auto-pick
gates). Adjacent and identically shaped — tell them apart by order.
```
56 57 8B F9 E8 ?? ?? ?? ?? 8B C8 E8 ?? ?? ?? ?? 8B CF 8B F0
```

### Action interval / speed

**Interval virtual — `FUN_010afd05` @ `0x010AFD05`**
`CRole`-family virtual: ECX = role, one stack arg (time delta), `RET 4`. Forwards
to `FUN_00de86b2` unless the override component at `role+0x8f8` handles it.
⚠️ Observed hooked LIVE (first 5 bytes = `E9 xx xx xx xx` JMP to a trampoline
page; comes and goes). Prefer data writes over hooking it.
```
55 8B EC 56 8B F1 83 BE ?? ?? ?? ?? 00 74 ?? FF 75 08 E8 ?? ?? ?? ?? 85 C0 74
```
(`83 BE ?? ?? ?? ?? 00` = `CMP [ESI+0x8F8],0` — the override-component check.)

**Master interval computation — `FUN_00de86b2` @ `0x00DE86B2`**
Computes the per-action interval for the role's current action (walk/attack/
pickup; state `role+0xb4` < 0xD): base from `RoleDataQuery()` vtable+0x30, buff
modifiers, the nSpeedPercent scaler `FUN_00deb537`, then the final generic
divisor `100 + role+0x44/100` (gated by `role+0x48`). Clamps result to >= 1.
```
6A 18 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B D9 8B 8B 70 07 00 00 33 FF 85 C9 0F 84
```
(`8B 8B 70 07 00 00` = `MOV ECX,[EBX+0x770]` — the anchor.)

**nSpeedPercent scaler — `FUN_00deb537` @ `0x00DEB537`**
`interval = interval * 100 / min(100 + role+0xc0, capTable[role+0xb4])`, plus
mount-table scaling (type 0x2c9) and the ×5/4 transform boost (states 0x78–0x7B).
Re-find via the string anchor `"nSpeedPercent > 0"` @ `0x016F7EE0` (its only code
xref is inside this function), or from `FUN_00de86b2` (calls it near the end).

**My-role list match — `FUN_00d3203a` @ `0x00D3203A`** (thunk `FUN_00d3244a`)
Walks the role list (owner singleton `DAT_01a526bc`, accessor `FUN_0041f76c`) and
accepts the candidate whose `role+0x54` == `client+0x268`. Re-find from the hunt
brain `FUN_00f54058` (calls `FUN_00d3244a` right after the `FUN_0041f76c` accessor).

**My-id getter (variant B) — `FUN_00fcd1e8` @ `0x00FCD1E8` → `FUN_0098c58d` @ `0x0098C58D`**
`CALL FUN_0043e481; MOV ECX,EAX; JMP FUN_0098c58d` → `return *(client+0x26c)`.
NOTE: reads 0 on at least one private server — prefer the variant-A pair
(`client+0x268` ↔ `role+0x54`) above.

**Pickup processor — `FUN_00f93854` @ `0x00F93854`** (roleaction.cpp)
`_COMMAND_PICKUP` state machine on the role: init → walk to the item cell →
`FUN_00fa252b(0x118, itemId)` picks. Re-find via the assert string
`"m_Info.cmdProc.iType == _COMMAND_PICKUP"` @ `0x01718928`.

### Packet / message system (the 0x855 flow)

**CMsgHangUp constructor — `FUN_00e5e50d` @ `0x00E5E50D`**  
Sets the vtable and inits the 0x408-byte message buffer.
```
6A 04 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B F9 89 7D F0 E8 ?? ?? ?? ?? 83 65 FC 00 8D B7 08 04 00 00
```
(`8D B7 08 04 00 00` = `LEA ESI,[EDI+0x408]` — the buffer offset.)

**CMsgHangUp Process / send — `FUN_010ce686` @ `0x010CE686`**  
Transmits the built message. This is vtable[5] — the method the toggle calls.
```
56 68 ?? ?? ?? ?? 8B F1 E8 ?? ?? ?? ?? 8B C8 E8 ?? ?? ?? ?? 84 C0 75 ?? 0F B7 46 06
```
(`0F B7 46 06` = `MOVZX EAX, word [ESI+6]` — reads the packet-type field.)

**Message factory — `FUN_00f36f4e` @ `0x00F36F4E` (`CNetMsg::CreateNetMsg`)**  
Giant switch mapping packet type → message ctor (`case 0x855` → `FUN_00e5e50d`).
Too large to signature reliably — re-find via the anchor string
`"CNetMsg::CreateNetMsg Miss MsgType:%d at %s, %d"`.

**Incoming dispatch → Lua — `FUN_0103ef3e` @ `0x0103EF3E` → `FUN_00ba2d7b` → `FUN_00c3c2d0`**  
Incoming packets are created via the factory, then routed to the Lua handler
`CQMain_OnNetMsg`. (This is why there's no C++ manager state-writer — the 0x855
ack is handled in Lua.)
```
FUN_0103ef3e: 89 5F 08 FF 77 70 E8 ?? ?? ?? ?? 59 80 7F 7C 00 74 0A 88 5F 7C 8B CF E8
FUN_00c3c2d0: 55 8B EC 83 7D 08 00 74 1F FF 75 0C 83 C1 04 FF 75 08 E8 ?? ?? ?? ??
```

**CMsgHangUp vtable** @ `0x017012d8` (7 entries): [0]=dtor `0x00e6388e`,
[3]=type-check `0x00e69782`, [4]=getter `0x010b3cc3`, [5]=Process/send
`FUN_010ce686`, [6]=error `0x00e83f56`.

---

## Object maps

### Client object (from `DAT_01a52960`)

| Offset | Type | Meaning |
|---|---|---|
| `+0x9e4` | dword | VIP level (FUN_00fd3271 default branch) |
| `+0x9ec` | dword | VIP level (FUN_00fd3271 alt branch, when the 0x57f4 flag is set) |
| `+0x1da0` | dword | hunt brain gate — must be 0 (checked by FUN_011ae8b7) |
| `+0x5385` | byte | auto-battle flag (read by FUN_0111524b) |
| `+0x57f4` | dword | source of the VIP-field branch flag (FUN_01118b17) |
| `+0x268` | dword | my entity id (variant A — matched against `role+0x54` in FUN_00d3203a) |
| `+0x26c` | dword | my entity id (variant B — read by FUN_0098c58d; 0 on some servers) |

### CRole / CMyRole (scan: id match + vtable contains FUN_010afd05/FUN_00de86b2)

| Offset | Type | Meaning |
|---|---|---|
| `+0x44` | dword | speed boost in 1/100 % → final divisor `100 + value/100` (ALL actions; gated by `+0x48`) |
| `+0x48` | byte | enables the `+0x44` divisor when nonzero |
| `+0x4a` | byte | set to 1 when the computed interval is below base (client-side marker) |
| `+0x54` | dword | entity id (variant A — the game's own my-role match) |
| `+0xb4` | dword | action state (< 0xD); indexes the speed cap table |
| `+0xc0` | dword | nSpeedPercent delta: effective % = 100 + value (FUN_00deb537). Keep > -100! |
| `+0xf4` | dword | additive speed percent (FUN_00efb7f9 branch) |
| `+0x268` | dword | entity id (variant B — msg filter FUN_01000e06) |
| `+0x8f8` | ptr | interval-override component (FUN_010afd05 tail-jumps to its vtable+0x80 when set) |
| `+0x468..+0x478` | dwords | XOR-obfuscated target/cell coords (pickup processor FUN_00f93854) |

### CAutoHangUpMgr (from `DAT_01a531e0`, size `0x44`)

| Offset | Type | Meaning |
|---|---|---|
| `+0x00` | ptr | vtable (only virtual = dtor) |
| `+0x10` | word | state: `0x001` idle / `0x101` hunting (only byte +0x11 flips; confirmed live) |
| `+0x11` | byte | hunting-active flag (the brain's gate; read by FUN_00f4761b) |
| `+0x12` | byte | per-frame gate flag (read by FUN_00f4761f; brain skips while nonzero) |
| `+0x14` | dword | `timeGetTime()` of last toggle (written by FUN_00f2fcd5) |
| `+0x18`/`+0x1c` | int | hunt anchor X/Y (the brain re-sets these each tick) |
| `+0x04` | int | hunt radius (the brain re-computes it each tick) |

### Speed cap table contents (client 7937)

`0x016F7E44` — per-state caps (max nSpeedPercent), states 0–12:
`{100, 105, 110, 115, 120, 130, 140, 150, 165, 185, 190, 195, 200}`
(state 0 = 100 → the `+0xc0` path alone can't speed it up; raise the table to exceed)

`0x016F7E78` / `0x016F7EAC` — mount scaling (`interval = t1[state] * interval / t2[state]`):
t1 = `{16,16,16,17,17,18,18,18,18,19,19,20,20}`
t2 = `{22,22,22,22,22,18,18,18,18,16,16,14,14}`

---

## Packet

**`0x855` (2133) = CMsgHangUp** — the auto-hunt start/stop *notification*.
Fields written by the builder: `[0]=0x16`, `[2]=0x855`, `[4]=(arg^1)*2+1`.
Both Begin and Stop send `[4]=3` — it's a pure toggle; the server flips state.
**It carries no configuration** — activation/config is client-side.

⚠️ **Do not send it if you want normal XP.** Telling the server the character is
auto-hunting makes it reset the XP bar and stop counting kills. The overlay
withholds this packet by default so the server treats kills as normal gameplay.

---

## Feature logic (how the overlay drives it)

- **Is-hunting gate:** `client+0x5385 != 0 && mgr+0x11 != 0`.
- **Start (client-side):** set `client+0x5385 = 1` and `mgr+0x11 = 1` every frame.
  Do NOT send the toggle packet (it causes the server-side XP reset). The overlay
  asserts the two flags each frame so a server update can't knock them off.
- **Stop:** clear both flags.
- **VIP unlock:** force `client+0x9e4` and `client+0x9ec` to `6` every frame.
  Passes every `requiredLevel <= vipLevel` gate (jump-search VIP3+, auto-pick
  VIP4+). Client-side only — server-enforced VIP features (shop, teleport) still fail.
- **Auto-pick (loot):** a separate VIP4-gated option. Enable it in the client's
  auto-hunt dialog (the VIP spoof unlocks the checkbox).
- **Speed (client-side):** write `role+0x48=1` + `role+0x44=(pct-100)*100` and
  `role+0xc0=pct-100` every frame; raise the cap table to lift the +0xc0 clamp.
  Do NOT hook FUN_010afd05 (the server hooks it itself — seen live as an E9 jmp).
- **Fast loot tick:** write `DAT_01a5cdb4 = 0` every frame so the hunt brain ticks
  at frame rate instead of 1/sec.
- **Find my role:** scan RW memory for a role-id == client-id (pairs above), then
  require the candidate's vtable to contain FUN_010afd05 or FUN_00de86b2.

---

## Re-find anchors (unique strings / RTTI)

Use these to locate the code after an update when signatures fail:

| Anchor | Address (this build) | Leads to |
|---|---|---|
| `"AutoHangUpFlag"` | `0x0172A648` | the ini phase-flag reader (FUN_010630e9) used by the brain |
| `".?AVCAutoHangUpMgr@@"` | `0x01A498B8` | manager RTTI → manager methods |
| `".?AVCDlgAutoHangUp@@"` | `0x019F3648` | the auto-hunt settings dialog |
| `".?AVCMsgHangUp@@"` | `0x01A46AE8` | the CMsgHangUp message class |
| `"AutoHangUpIconBtn"` | `0x01646F90` | the auto-hunt toolbar icon handler |
| `"VipLev"` | `0x0163AA70` | VIP-level handling |
| `"nVipLev >= 0 && nVipLev <= 6"` | `0x016160F8` | dlgvipquery.cpp — confirms VIP range 0–6 |
| `"CNetMsg::CreateNetMsg Miss MsgType:%d at %s, %d"` | (search the string) | the message factory `FUN_00f36f4e` |
| `"CQMain_OnNetMsg"` | (search the string) | the incoming-message → Lua dispatch |
| `msghangup.cpp` path string | `0x017012F8` | CMsgHangUp source module |
| `"nSpeedPercent > 0"` | `0x016F7EE0` | the nSpeedPercent scaler `FUN_00deb537` (role.cpp:0x1ae9) |
| `"m_Info.cmdProc.iType == _COMMAND_PICKUP"` | `0x01718928` | the pickup processor `FUN_00f93854` (roleaction.cpp:0x5e9) |
| `extend\myrole.cpp` path string | `0x015E3170` | CMyRole methods (FUN_007fd360 / FUN_007e0bb0) |
| `".?AVCMyRole@@"` | `0x019F2704` | CMyRole RTTI |
| `".?AVCRole@@"` | `0x01A45320` | CRole RTTI |

---

## Character Buffs / StatusIcons (VERIFIED on client 7937)

The client calls character buffs **StatusIcons**. The active buffs on the
character are a **576-bit bitfield at `C3DUser+0x138`** (72 bytes = 9×8-byte
words): bit `id` lives at `bitfield + (id/64)*8`, bit `(id%64)`.

| Function | Address | Meaning |
|---|---|---|
| `C3DUser::SetStatus` core | `FUN_00a72eab` @ `0x00A72EAB` | `SetStatus(bitfield, id, enable)` - 64-bit word set/clear |
| `C3DUser::AddStatus` | `FUN_00eecff1` @ `0x00EECFF1` | `ADD ECX,0x138` then set bit (1) |
| `C3DUser::ClearStatus` | `FUN_00ef1835` @ `0x00EF1835` | `ADD ECX,0x138` then clear bit (0) |
| `C3DUser::ChkStatus` | `FUN_00f1a1d8` @ `0x00F1A1D8` | `ADD ECX,0x138` then bit test (`FUN_00d4e0ae`) |
| second bitfield set/clear | `FUN_00eed011` / `FUN_00ef1855` | same pair on `user+0x1c8` |
| Lua binder `CPlayer::Lua_AddStatus` | binder @ `0x00DA36EC` (`PUSH 0x16f2540`) | script path → AddStatus |
| Lua binder `CPlayer::Lua_ClrStatus` | binder @ `0x00DA3711` | script path → ClearStatus |

**Remaining time (VERIFIED):** the server-driven apply chokepoint is
`FUN_00e48d33` @ `0x00E48D33` — called by the MsgUserAttrib processor
`FUN_01040c2e` as `e48d33(mgr, statusId, displayType, seconds, flag, extra)`
(stack: statusId@esp+4, displayType@esp+8, seconds@esp+0xC). It refreshes the
icon timer via `FUN_00e4c9d8` @ `0x00E4C9D8` → `icon+0x2c = seconds`,
`icon+0x24 = _time32(now)`, `icon+0x28 = timeGetTime()`. The icon render
(`FUN_00e4e217`) shows remaining = `icon+0x2c - (timeGetTime()-icon+0x28)/1000`.
The overlay MinHooks `FUN_00e48d33` (prologue `6A 1C B8`) and keeps
`endMs = now + seconds*1000` per status id; the per-frame bitfield poll drops
expired buffs automatically.

**Active-icon vectors (VERIFIED, timer source):** the mgr keeps
`std::vector<icon*>` at `mgr+0xe0` / `mgr+0xec` (second display group); each
0xac-byte icon: `+0x28` = timeGetTime() at apply, `+0x2c` = total seconds,
`+0xa8` = CUserAttrib* def (`def+0` = statusId, set by `FUN_00e4c3d2`).
Polling these per frame gives id + remaining time for every iconed buff.

**Buff DISPLAY names (VERIFIED 2026-08-14):**
- `ini/StatusTips.ini` `Name=` values are string **KEYS**
  (`STR_INI_STATUSTIPS_250_NAME`), not literal names.
- The literal name comes from the language table **`ini/Cn_Res.ini`**
  (GBK, codepage 936): `STR_INI_STATUSTIPS_250_NAME=Celestial Dance`.
  Status 47 has no entry (→ no name).
- The def's `+0x178` std::string is the **effect animation name**
  (e.g. `trojanblkt` from `ani/effect.ani`), NOT the display name — do not
  use it for the overlay.
- ⚠️ The client's ini paths are **CWD-relative** (game launched from
  `D:\AhmedProject\client`, not `Env_DX9\`). GetCurrentDirectory() is the
  right base for `ini\StatusTips.ini` / `ini\Cn_Res.ini`.
- NEXT STEP (not yet implemented): parse `ini/Cn_Res.ini` in buffs.cpp,
  GBK→UTF-8 via MultiByteToWideChar(936)/WideCharToMultiByte(CP_UTF8), key
  `STR_INI_STATUSTIPS_<id>_NAME`; fallback "Status <id>".
- XP skill names: not yet resolved (magic type id @ info+0x5C indexes the
  magic def; MagicType.dat has no literal "Superman" string — likely also a
  STR_ key in Cn_Res.ini; search `STR_MAGIC` keys next).

**Buff names** come from `ini/StatusTips.ini` (`[<id>]` blocks with `Name=`
lines), loaded by the CUserAttribMgr loader `FUN_00e2c03c` @ `0x00E2C03C`
(userattribmgr.cpp). CUserAttribMgr singleton = `DAT_01a56f20`, accessor
`FUN_008329b1` @ `0x008329B1`, ctor `FUN_00e1b059` @ `0x00E1B059`.
Each loaded CUserAttrib (0x198 bytes): statusId@0, displayType@4,
priority@0xC, icon@0x10/0x14, name string@0x178.

**My C3DUser** = tail of the client `+0x98` chain (same walk as `FUN_00deb082`
used by the hunt brain) + id match `user+0x54 == client+0x268`.

**Implementation note (`buffs.cpp`):** reads the 72-byte bitfield at
`user+0x138` every frame, parses `StatusTips.ini` for names, and renders every
named status green `[ON]` / gray `[OFF]` in the overlay (plus a raw-bits debug
tree). The Lua-binder MinHook approach was dropped - the bitfield catches
server-driven debuffs too (the binders only see script-applied ones).

---

## Verification checklist (after re-finding on a new build)

- [ ] Manager accessor signature resolves to the singleton that IsHunting reads.
- [ ] Toggle handler is the 5-instruction `PUSH 0; CALL; MOV ECX,EAX; CALL; RET`.
- [ ] Packet builder contains `B9 55 08 00 00` (`MOV ECX,0x855`).
- [ ] VIP getter's field offsets match the two dwords it returns.
- [ ] CMsgHangUp ctor contains `8D B? 08 04 00 00` (`LEA ...,+0x408` buffer).
- [ ] Interval virtual is the `55 8B EC 56 8B F1 83 BE` prologue (or is E9-hooked live).
- [ ] Cap table has 13 dwords starting at 100 and ending at 200.
- [ ] My-role match: candidate's vtable contains the interval virtual or the core fn.
- [ ] Confirm each AOB match is unique before trusting it.

---

## Auto Gear Swap (native alternate-equipment feature, client 7937)

The client ships a native "switch to alternate equipment" feature (the fgui
swap button, string key `STR_SWAP_SUB_WEAPONBTNTIP` = Cn_Res.ini line 672).
Verified chain (this build):

| Address | What | Verification anchor |
|---|---|---|
| `0x00FF219D` | `CMyHero::SwapEquipMode` (heroitem.cpp) - THE swap. `__fastcall(ECX = hero)`, no stack args. Sends CMsgItem{action 0x2D alt / 0x2C main} (0x97B) + CMsgAction{action 0x198} (0x833) | prologue `68 4C 09 00 00 ... 8B F1 8B 86 3C 19 00 00` (reads hero+0x193C) |
| `0x0043E581` | hero accessor - returns `DAT_01a53980` (same global as the client object) | `if (DAT==0) init; return DAT` |
| `0x01A53980` | `DAT_01a53980` - CMyHero singleton global | shared with xp_skill/buffs |
| hero `+0x193C` | equip mode flag: 0 = MAIN, 1 = ALT | read by FUN_00FF219D, FUN_00FCAD4C (getter) |
| `0x00A58AA8` | swap button dispatch site: `CALL 0x0043e581; MOV ECX,EAX; CALL 0x00ff219d` | unique 3-instruction tail |
| `0x00F0959C` | `CMsgItemPB::Process` (msgitem.pb.cc) - inbound item-action hub; `param+0x448` = action type; swap reply re-renders 8 equip slots (FUN_00ff1eff clear + FUN_00ff49c4 set pairs) when reply mode != current | registered @ 0x0170E270 table (CMsgItemPB methods) |
| `0x00D8B8FF` | CMsgAction serialize (msg id 0x833, action type at +0x45C) | `[msg+6]=0x833` |
| `0x00EF2E5E` | CMsgItem create/serialize (msg id 0x97B, action type at +0x448) | `[msg+6]=0x97b` |
| `0x010CF416` | packet send | vtable[5] |
| `0x00FCAD4C` | `CMyHero` equip-mode getter (`return *(int*)(this+0x193C)`) | all display/score callers |

Equipment positions: MAIN slots 0x65..0x73 (101..115); ALT = MAIN + 0x14 =
0x79..0x87 (121..135); special alt slots +0x384/+0x388. Action types:
0x2C = swap to MAIN, 0x2D = swap to ALT, 0x198 = equip/refresh.

Implementation (`gear_swap.cpp`): calls `FUN_00FF219D(hero)` via a
`__fastcall` fn pointer when an XP-style buff (status bit set + magic-derived
duration registered, `IsXpStyleBuffActive()` from buffs.cpp) becomes active
(gear -> ALT) and when it clears (gear -> MAIN); waits for hero+0x193C to
flip (5s timeout) before re-arming; 1.5s send cooldown.
