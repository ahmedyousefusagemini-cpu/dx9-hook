# RE Offsets & Signatures — Conquer.exe (client 7937)

Durable reverse-engineering reference for the auto-hunt / VIP work. **Absolute
addresses shift on every recompile** — the byte signatures (AOB) and the unique
string/RTTI anchors below are what let you re-locate each value after a binary
update.

Image base for all addresses below: `0x00400000`. Build analyzed: client 7937.

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
| Main window handle | `DAT_01a5a9cc` = `0x01A5A9CC` | `FUN_00df9561` posts `0x464` game-command messages to it |

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

### XP-skill gates ("cannot use XP when hangup" block)

The client refuses XP skills while the hunting state is active with
`STR_CANNOT_USE_XP_WHEN_HANGUP`. Three gates, all driven by `FUN_0111621f`;
the overlay patches all three (see `src/hooks/xp_skill.cpp`).

**XP charge-bar fill gate — `FUN_011154f5` @ `0x011154F5`**  
Adds to the 0-100 XP bar (client `+0xaec`) only when NOT hunting. Callers:
`FUN_011354b1` (kill tick) and `FUN_00d3fb0f` (projectile complete on self).
Also refuses to refill while an XP-skill buff status is active
(`FUN_00f1a1d8(0x96/0xc0/0xeb)`). Patch site `0x01115514`: `75 49` (JNZ
skip-fill) → `90 90` (NOPs).
```
E8 ?? ?? ?? ?? 6A 64 5B 84 C0 75 ?? 68 96 00 00 00
```
(`6A 64 5B` = `PUSH 0x64; POP EBX` right after the IsHunting call; `68 96`
starts the 0x96 status-flag check that follows — the rest of the fill logic
is unchanged, so those status gates still apply.)

**Use-skill-on-target gate — `FUN_011b1ec9` @ `0x011B1EC9`**  
If hunting AND the current skill is XP-type (`[FUN_00d9612c(client)+0x30] == 1`),
shows `STR_CANNOT_USE_XP_WHEN_HANGUP` and bails. Patch site `0x011B21D8`:
`74 59` (JZ skip-block) → `EB 59` (JMP — block never runs).
```
E8 ?? ?? ?? ?? 84 C0 74 ?? 8B 4D B8 E8 ?? ?? ?? ?? 83 78 30 01 75 ?? 68 ?? ?? ?? ??
```
(the trailing `68` pushes the string-key address — the anchor to the block.)

**Use-skill-at-position gate — `FUN_011b3503` @ `0x011B3503`**  
Same block as above. Patch site `0x011B3B21`: `74 4A` (JZ) → `EB 4A` (JMP).
```
E8 ?? ?? ?? ?? 84 C0 74 ?? 8B 4D 9C E8 ?? ?? ?? ?? 83 78 30 01 75 ?? 68 ?? ?? ?? ??
```

**Current-skill accessor — `FUN_00d9612c` @ `0x00D9612C`**  
`return client + 0x70` — the current-magic-info struct; its `+0x30` dword == 1
marks an XP-type skill; `+0x5c` is the current magic type id; `+0x10` the
cooldown ms.
```
8D 41 70 C3
```

### XP-skill auto-activation (auto Superman / Fatal Strike)

How the overlay pops the character's XP skill when the bar is full
(`src/hooks/xp_skill.cpp`, "Auto XP skill when bar is full").

**Use-skill-on-target — `FUN_011b1ec9` @ `0x011B1EC9`**  
The activation entry point. Call signature (verified at the hunt brain and
the hotkey dispatcher call sites):
`char __thiscall FUN_011b1ec9(client /*ECX*/, int magicId, int targetUid, int unk /*0*/, int showErr /*1*/)`.
XP skills are self-cast: `targetUid = *(uint*)(client+0x268)`.

**Learned-magic lookup — `FUN_011a92b4` @ `0x011A92B4`**  
`void __thiscall FUN_011a92b4(client /*ECX*/, void* out[2], int magicId)`.
Scans the learned-magic vector (`client+0x1d88` begin / `client+0x1d8c` end,
8-byte smart-pointer entries). `out[0] != 0` = the character knows the magic;
`out[1]` is an intrusive refcount block — release it with `FUN_00420f03`.
Re-find via its callers: the hotkey dispatcher `FUN_00a1d6bc` and the skill
queue processor `FUN_011b4477`.

**Smart-pointer release — `FUN_00420f03` @ `0x00420F03`**  
`int __fastcall FUN_00420f03(void* refBlock /*ECX*/)` — decrements the use
count at `block+4`, virtual-destroys on zero, then the weak count at `block+8`.

**XP skill ids (self-cast)** — the hotkey dispatcher `FUN_00a1d6bc` compares
the current skill's `+0x5c` against exactly seven ids and fires the match at
the self UID: `0x2845, 0x2B34, 0x2B2A, 0x2D5A, 0x3002, 0x323C, 0x3DA4`
(the class XP skills: Superman, Fatal Strike, etc.). The overlay probes them
with the learned-magic lookup and uses the first the character knows — no
per-class table needed. Re-find: dispatcher = the function that posts
`FUN_00df9561(0xc1f, 0)` and switches on command ids `0x10/0x6c..0x72`.

**Game-command poster — `FUN_00df9561` @ `0x00DF9561`**  
`PostMessageA(DAT_01a5a9cc, 0x464, wParam, lParam)`. The XP hotkey
(`FUN_00a37356` case `0x38b`) posts `0xe65` with `lParam = !IsHunting`.

### Hunt brain

**Per-frame hunt brain — `FUN_00f54058` @ `0x00F54058`**  
The client-side auto-hunt loop: gates on `IsHunting`, rate-limits to 1s, then
finds targets / walks / attacks / loots. Each phase is gated by an
`AutoHangUpFlag<N>` ini bit and (for jump/loot) a VIP gate. Uses skills via
`FUN_011b1ec9(currentSkill+0x5c, *(client+0x268), 0, 1)` /
`FUN_011b3503(currentSkill+0x5c, x, y, 1)`.
```
6A 2C B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B D9 89 5D E8 E8 ?? ?? ?? ?? 8B C8 E8 ?? ?? ?? ?? 84 C0
```
Called once per frame from `FUN_01128c86` (the big per-frame updater).

**Skill queue processor — `FUN_011b4477` @ `0x011B4477`**  
Iterates the client's skill queue (`client+0x1b10` list; entries: `+0x10`
magic id, `+0x14` active flag, `+0x18` last-used `timeGetTime`), honors the
current skill's cooldown (`+0x10`), fires via `FUN_011b1ec9`.

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
| `+0x268` | dword | own role/UID (the target arg the hunt brain / XP dispatcher pass to `FUN_011b1ec9`) |
| `+0x9e4` | dword | VIP level (FUN_00fd3271 default branch) |
| `+0x9ec` | dword | VIP level (FUN_00fd3271 alt branch, when the 0x57f4 flag is set) |
| `+0xaec` | dword | XP charge bar 0–100 (full = 100; read/written by FUN_011154f5) |
| `+0x1868` | dword | learned-magic list count (index getter FUN_00fcc707; entry `+0x1c` = magic id) |
| `+0x1b10` | list | skill queue head (processed by FUN_011b4477) |
| `+0x1d88`/`+0x1d8c` | ptr | learned-magic vector begin/end (8-byte smart-ptr entries; scanned by FUN_011a92b4) |
| `+0x1da0` | dword | hunt brain gate — must be 0 (checked by FUN_011ae8b7) |
| `+0x5385` | byte | auto-battle flag (read by FUN_0111524b) |
| `+0x57f4` | dword | source of the VIP-field branch flag (FUN_01118b17) |

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
- **XP skills while hunting:** three 2-byte code patches (see "XP-skill gates"
  above) applied by `xp_skill.cpp`. Server unaffected (0x855 stays withheld).
- **Auto XP skill (Superman / Fatal Strike):** every frame: if `client+0xaec >= 100`,
  find the character's XP skill by probing the seven dispatcher ids with the
  learned-magic lookup `FUN_011a92b4`, then call
  `FUN_011b1ec9(client, xpSkillId, *(client+0x268), 0, 1)` — the same call the
  hunt brain and the XP hotkey dispatcher make. Fire max 1/s; re-scan learned
  magics every 3s. Requires the XP gates patched (auto-enables them).

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
| `"STR_CANNOT_USE_XP_WHEN_HANGUP"` | `0x01741FA4` | the two use-skill gates (FUN_011b1ec9 / FUN_011b3503) |
| `"CNetMsg::CreateNetMsg Miss MsgType:%d at %s, %d"` | (search the string) | the message factory `FUN_00f36f4e` |
| `"CQMain_OnNetMsg"` | (search the string) | the incoming-message → Lua dispatch |
| `msghangup.cpp` path string | `0x017012F8` | CMsgHangUp source module |

---

## Verification checklist (after re-finding on a new build)

- [ ] Manager accessor signature resolves to the singleton that IsHunting reads.
- [ ] Toggle handler is the 5-instruction `PUSH 0; CALL; MOV ECX,EAX; CALL; RET`.
- [ ] Packet builder contains `B9 55 08 00 00` (`MOV ECX,0x855`).
- [ ] VIP getter's field offsets match the two dwords it returns.
- [ ] CMsgHangUp ctor contains `8D B? 08 04 00 00` (`LEA ...,+0x408` buffer).
- [ ] Each XP-skill gate signature matches: fill `6A 64 5B 84 C0 75`, use-skill
      `84 C0 74 ?? 8B 4D ?? E8 ?? ?? ?? ?? 83 78 30 01`.
- [ ] XP-skill ids: re-derive from the XP hotkey dispatcher (the function that
      posts `FUN_00df9561(0xc1f, 0)` and switches on `0x10/0x6c..0x72`).
- [ ] Confirm each AOB match is unique before trusting it.
