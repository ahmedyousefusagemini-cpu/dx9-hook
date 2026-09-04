# RE Offsets & Signatures — Conquer.exe (client 7952)

Durable reverse-engineering reference for the auto-hunt / VIP / speed work. **Absolute
addresses shift on every recompile** — the byte signatures (AOB) and the unique
string/RTTI anchors below are what let you re-locate each value after a binary
update.

Image base for all addresses below: `0x00400000`. Build analyzed: client 7952.

> **2026-09-01: client recompiled (new build, version 7952).** All addresses still
> used by the overlay were re-located and VERIFIED against the new binary via
> Ghidra (AOB / xref / decompile). The old → new migration table is in the next
> section. The older tables further down still list previous-build addresses
> (kept as the signature/anchor reference — every entry's "Found via" mechanism
> still works on the new build).

---

## 2026-09-01 (7952) — verified old → new address table

This recompile is mostly a **uniform +0x1A0 shift** for the code regions the
overlay touches (0x00F4/0x00F1/0x00FF/0x00E4/0x00EE/0x00EF/0x010B/0x0111/0x011B/
0x0101/0x00EA), while the globals, accessors, and the 0x00D9/0x00DE/0x00A7/
0x00AE/0x016F/0x0174 regions did NOT move. All entries below re-verified in
Ghidra on the 7952 build (AOB signature, xref or decompile).

| Old (7950 build) | New (7952 build) | What |
|---|---|---|
| `0x01A549A0` | `0x01A549A0` | client / CMyHero object global (read by `FUN_0043e581`) — unchanged |
| `0x01A55220` | `0x01A55220` | CAutoHangUpMgr singleton global (read by `FUN_00482805`) — unchanged |
| `0x01A58FE0` | `0x01A58FE0` | CUserAttribMgr singleton global (read by `FUN_00832a5d`) — unchanged |
| `0x01A5EE04` | `0x01A5EE04` | hunt brain tick global (read+write only in the brain) — unchanged |
| `0x01A5A510` | `0x01A5A510` | CMyShellApp / gpDlgShell global (auto_login) — unchanged |
| `0x0043E581` | `0x0043E581` | client accessor (unchanged) |
| `0x00482805` | `0x00482805` | manager accessor (unchanged) |
| `0x00832A5D` | `0x00832A5D` | CUserAttribMgr accessor (unchanged) |
| `0x008A8FCA` | `0x008A8FCA` | `FUN_LoginButtonHandler` (auto_login) — unchanged |
| `0x00BD8035` | `0x00BD8035` | auto-hunt toggle handler (PUSH 0; CALL mgr-accessor; MOV ECX,EAX; CALL) — unchanged |
| `0x00F31335` | `0x00F314D5` | toggle impl `Toggle(mgr, flag)` (called by the toggle handler) |
| `0x00F556FC` | `0x00F5589C` | per-frame hunt brain |
| `0x00F49497` | `0x00F49637` | walk-to-coord (brain helper, called by the brain with radius 4) |
| `0x00F4412C` | `0x00F442CC` | find-target (brain helper, writes `{id,dist}` pair) |
| `0x01117C44` | `0x01117DE4` | is-hunting check (`client+0x5385 && mgr+0x11`) |
| `0x01116C70` | `0x01116E10` | auto-battle byte getter (`8A 81 85 53 00 00 C3`) |
| `0x00D3313A` | `0x00D3313A` | my-role list match (thunk `ADD ECX,0x78; JMP`) — unchanged |
| `0x010B148B` | `0x010B162B` | action-interval virtual (vtable check) |
| `0x00DE93F2` | `0x00DE93F2` | master interval computation — unchanged |
| `0x016F9E84` | `0x016F9E84` | speed cap table (13 dwords `{100..200}`) — unchanged |
| `0x01116F39` | `0x011170D9` | XP-fill gate (`75 49` → `90 90`; inside FUN_011170ba) |
| `0x011B3CE6` | `0x011B3E86` | use-skill-on-target gate (`75 4B` → `EB 4B`; inside FUN_011b3b69) |
| `0x011B5658` | `0x011B57F8` | use-skill-at-position gate (`75 3C` → `EB 3C`; inside FUN_011b51cc) |
| `0x011B39C9` | `0x011B3B69` | use skill on target (callable: `__thiscall(client, magicId, selfUid, 0, 1)`) |
| `0x011B502C` | `0x011B51CC` | use skill at position |
| `0x01744044` | `0x01744054` | string `STR_CANNOT_USE_XP_WHEN_HANGUP` |
| `0x00D96E6C` | `0x00D96E6C` | magic-info getter (this + 0x70) — unchanged |
| `0x00E49BD7` | `0x00E49D77` | status apply chokepoint (`6A 1C B8` prologue, 6-arg thiscall, RET 0x14) |
| `0x00A73B8E` | `0x00A73B8E` | status bitfield core set/clear (`__thiscall(bitfield, id, set)`) — unchanged |
| `0x00EEE64D` | `0x00EEE7ED` | `C3DUser::AddStatus` (`ADD ECX,0x138`; calls `0x00a73b8e`) |
| `0x00EF2E91` | `0x00EF3031` | `C3DUser::ClearStatus` |
| `0x00F1B838` | `0x00F1B9D8` | `C3DUser::ChkStatus` (`ADD ECX,0x138; JMP bit-tester`) |
| `0x00FF2B8E` | `0x00FF2D2E` | `CMyHero::SwapEquipMode` (reads `hero+0x193C`, sends 0x2C/0x2D + 0x198) |
| `0x00AE6208` | `0x00AE6208` | XP-pop panel show/hide setter (`MOV [ECX+0xAC8],AL / RET 4`) — unchanged |
| `0x0101C9D8` | `0x0101CB78` | login-packet sender `login(account, pwd, serverName, mode, extra)` (auto_login) |
| `0x00EA1F50` | `0x00EA20F0` | `CEncryptData::SetString` (auto_login) |
| `0x00EB31E3` | `0x00EB3383` | `CEncryptData::GetString` (auto_login debug) |
| `0x008A8FCA` | `0x008A8FCA` | `FUN_LoginButtonHandler` — `__fastcall(CDlgLogin*)`. Reads account `dlg+0x13B88` std::string, password `dlg+0x13BD0` CEncryptData, server name; then calls `FUN_0101CB78`. Reconnect gate: if `(*(dlg+0xdc68)+0x80)()` nonzero AND `FUN_0111a10b()` (byte at `obj+0x5428`) == 0 → `FUN_008a965f` (QR mode 1, uses 0x13938/0x13980) instead of normal mode 0. |
| `0x008A965F` | `0x008A965F` | reconnect login path — sends `FUN_0101CB78(0x13938 acct, 0x13980 pwd, server, mode=1, 0)` (QR code). Filling 0x13938 can trigger this; it must stay EMPTY for normal login. |
| `0x005F2380` | `0x005F2380` | returns `this + 0x20C` — the mygameinput raw text buffer pointer (CGameInput sub-object). |
| `0x00602CBB` | `0x00602CBB` | `CGameInput::Process` (mygameinput.cpp) — per-keystroke text handling. `this`=editCEnc, sub-object at `editCEnc+0x2C`, reads text at `FUN_005f2380(editCEnc+0x2C)` = `editCEnc+0x238`, SetStrings into `editCEnc+0x30C`. |
| `0x0089C013` | `0x0089C013` | `CDlgLogin::Process` / killfocus handler — password branch (focus == `dlg+0xFE8`) syncs `0x13BD0` ↔ `editCEnc+0x30C`; account branch writes `dlg+0x13B88`; token branch `dlg+0x13BB8`. |
| `0x0089C5A0` | `0x0089C5A0` | killfocus password-sync call site: `FUN_00607cd5(editCEnc, dlg+0x13BD0)` then `GetString(editCEnc+0x30C)` → `SetString(0x13BD0)`. |
| — | `0x00ED3CD1` | `CEncryptData` key-table expansion: copies 16 DWORDs cyclically into 64 DWORDs (`this+0..0xFF`). Used by ctor and CDlgLogin ctor re-seed. |
| — | `0x00E9CC3F` | `CEncryptData::CEncryptData` — new finding. Constructor seeds `this+0..0xFF` key table from LCG via `GetGameRandomByte(0xff,0)`. Layout: `+0..+0xFF` key[256], `+0x100` nEncLen, `+0x104` nLen, `+0x108..+0x207` encBuf[256]. Deterministic per-build (uses `DAT_019ebaac` seed=0x0e89 from `.data`). Only verified caller is `CDlgLogin::CDlgLogin` @ `0x0086bdb5` calling it at `0x0086c0d4` with `ECX = EBX+0x13bd0`. The destructor `FUN_00ea1f0d` previously misattributed to CEncryptData belongs to a different class with 5 `std::string` sub-objects. |
| — | `0x00ECE5FC` | `GetGameRandomByte(max, reseed)` — the LCG used by CEncryptData ctor. `state = (state * 0x355d + 0x17061b) % 0x6cf39b; return state / (0x6cf39b / max)`. `reseed=1` → `state = timeGetTime()`. Global state at `0x019ebaac` (initial value `0x0e89`). |
| — | `0x00EA20F0` | `CEncryptData::SetString` (thiscall, `this=encData, plain`). Writes `this+0x104 = strlen`, `this+0x108 = plain`, then per-byte transform `out[i] = (i*0x67-0x7f)*i ^ key[i&0xff] ^ (i>>4)*0x66 ^ in[i] ^ 0xB9`. Symmetric with GetString. |
| — | `0x010C1C27` | `CMsgEncryptCode` handler — `srand(code); DAT_019ec240[i] = rand()&0xff` for 16 bytes; stores code at singleton `FUN_0043e581()`+0x5328; posts `0x464/0xcdf`. Seeds the packet-level session key (sessKey16) — NOT the CEncryptData key tables. |
| — | `0x019EC240` | 16-byte session key buffer (from `srand(code)` in CMsgEncryptCode handler). |
| — | `0x01A549A0` | session singleton (lazy-inited by `FUN_0043e581`), code stored at `+0x5328` (via `FUN_01141A00`). |
| — | `0x00EB0999` | `CEncryptData::GetEncLen` — returns `*(this+0x104)`. |
| — | `0x00ED3655` | `CEncryptData::SetEncLen` — `*(this+0x104) = len`. |
| — | `0x00EAF323` / `0x00EAF85A` | encrypt-data key-table helpers (old SetEncCode path). |
| — | `0x00D02F5C` | fgui edit message dispatch (called by `FUN_006074ED`). |
| — | `0x006074ED` | fgui edit text-set helper: `Ordinal_133(editCEnc+4, msg)` (0x81 = set text). |
| — | `0x00ED3602` | edit-sync worker — `GetString(src) → SetString(this)` (direction: 0x13BD0 → editCEnc+0x30C). |
| — | `0x00607CD5` | thunk `ADD ECX,0x30C; JMP 0x00ED3602` — edit-sync (password). Called as `FUN_00607cd5(editCEnc, dlg+0x13BD0)`. |
| `0x01A5FB44` (file `.data` RVA `0x165FB44`) | unchanged | `CPacket` frame header used by `Ordinal_8` (20-byte struct: opcode 2 / length 0x14 / GetTickCount / `client+0x5328` / data ptr / 0x40). See RESEARCH_NOTES.md 2026-09-01 "login-packet encryption routing found" entry for full layout. |
| `0x0126F254` / `0x0126F25E` | unchanged | `DelayLoad_Ordinal_8` / dispatch thunk to `ndac.dll` Ordinal_8. Slot at `[0x01A54490]`. |
| `0x0126F2D4` / `0x0126F2DE` | unchanged | `DelayLoad_Ordinal_55` / dispatch thunk to `ndac.dll` Ordinal_55. Slot at `[0x01A54480]`. |
| `0x019DD580` | unchanged | `ImgDelayDescr_019dd580` — delay-load descriptor for `ndac.dll`. DLL name at RVA `0x012e9c00` = "ndac.dll". `rvaIAT=0x01654474`, `rvaINT=0x019DD57C`. |
| `H:\client\ndac.dll` (NOT in `Conquer.exe`) | — | VMProtect-packed network DLL, 18.7 MB, image base `0x10000000`, 139 ordinal-only exports, no names. `Ordinal_8` → RVA `0x00020B60` (dispatcher stub, real impl in encrypted `.rc00`). `Ordinal_55` → RVA `0x00020D80` (same shape). The packet-level encryption uses the **COCAC asymmetric stream cipher** (see RESEARCH_NOTES.md 2026-09-04) with the hardcoded 8-byte seed `9D 0F FA 13 62 79 5C 6D`. The 512-byte working key is derived from this seed deterministically inside the VM bytecode at session start. **The seed is identical across every client release since patch 4232.** Source: `shekohex/coemu` `crates/crypto/src/cq_cipher.rs` + `tq_cipher.rs`. |

Client-side field offsets unchanged and still verified: `client+0x5385`
(auto-battle byte), `client+0xaec` (XP bar 0–100), `client+0x268` (my id),
`mgr+0x11` (hunting flag), `mgr+0x04` (attack-target X / loot ptr),
`hero+0x193C` (equip mode), `role+0x44/+0x48/+0xc0` (speed paths),
`status bitfield at client+0x138` (576 bits).

---

## 7952 AOB signatures — the re-find map

All entries below were re-verified in Ghidra on the 7950 build (AOB signature,
xref check or decompile). This is a full recompile: per-region shifts are not
uniform.

| Old (2026-08-20 build) | New (7950 build) | What |
|---|---|---|
| `0x01A53980` | `0x01A549A0` | client / CMyHero object global (read by `FUN_0043e581`) |
| `0x01A54200` | `0x01A55220` | CAutoHangUpMgr singleton global (read by `FUN_00482805`) |
| `0x01A57F40` | `0x01A58FE0` | CUserAttribMgr singleton global (read by `FUN_00832a5d`) |
| `0x01A5DDE4` | `0x01A5EE04` | hunt brain tick global (`timeGetTime` gate, read+write only in the brain) |
| `0x00482805` | `0x00482805` | manager accessor (unchanged) |
| `0x00832AB1` | `0x00832A5D` | CUserAttribMgr accessor |
| `0x00BD8025` | `0x00BD8035` | auto-hunt toggle handler (PUSH 0; CALL mgr-accessor; MOV ECX,EAX; CALL) |
| `0x00F30A75` | `0x00F31335` | toggle impl `Toggle(mgr, flag)` (called by the toggle handler) |
| `0x00F54DF8` | `0x00F556FC` | per-frame hunt brain |
| `0x00F48B93` | `0x00F49497` | walk-to-coord (brain helper, called by the brain with radius 4) |
| `0x00F43828` | `0x00F4412C` | find-target (brain helper, writes `{id,dist}` pair) |
| `0x01117254` | `0x01117C44` | is-hunting check (`client+0x5385 && mgr+0x11`) |
| `0x01116280` | `0x01116C70` | auto-battle byte getter (`8A 81 85 53 00 00 C3`) |
| `0x00D3203A` / `0x00D3244A` | `0x00D3313A` | my-role list match (role+0x54 == client+0x268) |
| `0x010B0A9A` | `0x010B148B` | action-interval virtual (vtable check) |
| `0x00DE93E2` | `0x00DE93F2` | master interval computation |
| `0x016F8E84` | `0x016F9E84` | speed cap table (13 dwords `{100..200}`) |
| `0x01116549` | `0x01116F39` | XP-fill gate (`75 49` → `90 90`; inside FUN_01116f1a) |
| `0x011B3286` | `0x011B3CE6` | use-skill-on-target gate (`75 4B` → `EB 4B`; inside FUN_011b39c9) |
| `0x011B4BF8` | `0x011B5658` | use-skill-at-position gate (`75 3C` → `EB 3C`; inside FUN_011b502c) |
| `0x011B2F69` | `0x011B39C9` | use skill on target (callable: `__thiscall(client, magicId, selfUid, 0, 1)`) |
| `0x011B45CC` | `0x011B502C` | use skill at position |
| `0x01743024` | `0x01744044` | string `STR_CANNOT_USE_XP_WHEN_HANGUP` |
| `0x00D96E5C` | `0x00D96E6C` | magic-info getter (this + 0x70) |
| `0x00E49AC2` | `0x00E49BD7` | status apply chokepoint (`6A 1C B8` prologue, 6-arg thiscall, RET 0x14) |
| `0x00A73B7E` | `0x00A73B8E` | status bitfield core set/clear (`__thiscall(bitfield, id, set)`) |
| `0x00EEDD80` | `0x00EEE64D` | `C3DUser::AddStatus` (`ADD ECX,0x138`; calls `0x00a73b8e`) |
| `0x00EF25C5` | `0x00EF2E91` | `C3DUser::ClearStatus` |
| `0x00F1AF78` | `0x00F1B838` | `C3DUser::ChkStatus` (`ADD ECX,0x138; JMP 0x00f2012d`) |
| `0x00FF219D` | `0x00FF2B8E` | `CMyHero::SwapEquipMode` (reads `hero+0x193C`, sends 0x2C/0x2D + 0x198) |
| `0x00AE61F8` | `0x00AE6208` | XP-pop panel show/hide setter (`MOV [ECX+0xAC8],AL / RET 4`) |

Client-side field offsets unchanged and still verified: `client+0x5385`
(auto-battle byte), `client+0xaec` (XP bar 0–100), `client+0x268` (my id),
`mgr+0x11` (hunting flag), `mgr+0x04` (attack-target X / loot ptr),
`hero+0x193C` (equip mode), `role+0x44/+0x48/+0xc0` (speed paths),
`status bitfield at client+0x138` (576 bits).

---

## 7952 AOB signatures — the re-find map

Scan the NEW binary for these byte signatures (`??` = wildcard byte) to
re-locate every anchor after the next recompile. Addresses are the 7952 build
(most code regions shifted +0x1A0 from 7950; the 0x00D9/0x00DE/0x00A7/0x00AE/
0x016F/0x0174 regions and all globals/accessors did not move).
Ordered by reliability (unique first); a "disambiguate" note explains how to
pick the right match when a signature is not unique.

| # | What | 7952 address | AOB signature (bytes) |
|---|---|---|---|
| 1 | auto-battle byte getter (`MOV AL,[ECX+0x5385]; RET`) | `0x01116E10` | `8A 81 85 53 00 00 C3` — **unique** |
| 2 | magic-info getter (`LEA EAX,[ECX+0x70]; RET`) | `0x00D96E6C` | `8D 41 70 C3` — **unique** |
| 3 | XP-pop panel show/hide setter (`MOV [ECX+0xAC8],AL; RET 4`) | `0x00AE6208` | `55 8B EC 8A 45 08 88 81 C8 0A 00 00 5D C2 04 00` — **unique** |
| 4 | use-skill-at-position gate (JNZ over the XP-block; pushes `STR_CANNOT_USE_XP_WHEN_HANGUP` @ the address below) | `0x011B57F8` | `75 3C 68 ?? ?? ?? ?? 8B` — string address changed to `0x01744054` |
| 5 | use-skill-on-target gate (same block) | `0x011B3E86` | `75 4B 68 ?? ?? ?? ?? 8B` — string address changed to `0x01744054` |
| 6 | status apply chokepoint prologue + icon-vector init | `0x00E49D77` | `6A 1C B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B D9 8D 45 08 8D 73 D0` |
| 7 | status bitset core (BTS/AND 64-bit word, `CMP EDI,0x240`) | `0x00A73B8E` | `55 8B EC 53 56 57 8B 7D 08 8B F1 81 FF 40 02 00 00 73 48 33 C9 8B C7 83 E0 3F` |
| 8 | `C3DUser::AddStatus` (`CMP [EBP+8],0x23F; PUSH 1`) | `0x00EEE7ED` | `55 8B EC 81 7D 08 3F 02 00 00 77 10 6A 01 FF 75 08 83 C1 38` |
| 9 | `C3DUser::ClearStatus` (same, `PUSH 0`) | `0x00EF3031` | `55 8B EC 81 7D 08 3F 02 00 00 77 10 6A 00 FF 75 08 83 C1 38` |
| 10 | `C3DUser::ChkStatus` (`ADD ECX,0x138; JMP bit-tester`) | `0x00F1B9D8` | `55 8B EC 81 7D 08 3F 02 00 00 77 0C 81 C1 38 01 00 00 5D E9` |
| 11 | toggle handler (auto-hunt notify) | `0x00BD8035` | `6A 00 E8 ?? ?? ?? ?? 8B C8 E8 ?? ?? ?? ?? C3` — matches many; disambiguate: the CALL target reads the manager global (see #14) |
| 12 | toggle impl `Toggle(mgr, flag)` (`PUSH 0x414` prologue) | `0x00F314D5` | `68 14 04 00 00 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B F1 80 7D 08 00 75 08` |
| 13 | per-frame hunt brain | `0x00F5589C` | `6A 2C B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B D9 89 5D E8 E8 ?? ?? ?? ?? 8B C8 E8 ?? ?? ?? ?? 84 C0 74 ?? E8` — the 3rd call is the is-hunting check (see #16); disambiguate from the dozens of `6A 2C B8` prologues by it |
| 14 | client accessor (reads `DAT_01a549a0`) | `0x0043E581` | `83 3D ?? ?? ?? ?? 00 75 05 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? C3` — **hundreds of matches**; disambiguate: only the CLIENT accessor's 2nd dword (after `83 3D`) equals the global that `auto_hunt`/`xp_skill`/`buffs` read at runtime; it is the one at `FUN_0043e581` in this build |
| 15 | manager accessor (reads `DAT_01a55220`) | `0x00482805` | `83 3D ?? ?? ?? ?? 00 75 05 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? C3` — same shape as #14; disambiguate by the global dword = `0x01A55220` |
| 16 | is-hunting check (`client+0x5385 && mgr+0x11`) | `0x01117DE4` | `E8 ?? ?? ?? ?? 84 C0 74 13 E8 ?? ?? ?? ?? 8B C8 E8 ?? ?? ?? ?? 84 C0 74 03 B0 01 C3 32 C0 C3` |
| 17 | XP-fill gate (`JNZ` skipping the XP-bar charge) | `0x011170D9` | `75 49 68 96 00 00 00 8B` — unique: JNZ + `PUSH 0x96` (status 150 check right after the hunting gate) |
| 18 | use skill on target (`PUSH 0x18C` prologue) | `0x011B3B69` | `68 8C 01 00 00 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B F9 89 7D AC` |
| 19 | action-interval virtual (`CMP [ESI+0x8F8],0`) | `0x010B162B` | `55 8B EC 56 8B F1 83 BE F8 08 00 00 00 74 1C FF 75 08 E8 ?? ?? ?? ?? 85 C0` |
| 20 | master interval computation (`MOV ECX,[EBX+0x770]`) | `0x00DE93F2` | `6A 18 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B D9 8B 8B 70 07 00 00 33 FF 85 C9` — the `8B 8B 70 07 00 00` anchor; many `8B 8B 70 07` hits — disambiguate: entry prologue `6A 18` + this is the one with the `+0x44/+0x48` final divisor (decompile) |
| 21 | walk-to-coord (brain helper) | `0x00F49637` | `68 3C 01 00 00 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 0F 02 00 00 E8 ?? ?? ?? ?? 8B C8` — verify: called by the brain (#13) with `(x, y, 4)` |
| 22 | find-target (brain helper, writes `{id,dist}`) | `0x00F442CC` | `6A 2C B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B D9 89 5D E8 33 C9 89 4D F0` — verify: called by the brain (#13) with `&outPair` |
| 23 | my-role list match (thunk: `ADD ECX,0x78; JMP`) | `0x00D3313A` | `55 8B EC 83 C1 78 5D E9 ?? ?? ?? ??` — unique |
| 24 | `CMyHero::SwapEquipMode` (`PUSH 0x94C`; reads `[ESI+0x193C]`) | `0x00FF2D2E` | `68 4C 09 00 00 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B F1 8B 86 3C 19 00 00` |
| 25 | `STR_CANNOT_USE_XP_WHEN_HANGUP` string | `0x01744054` | string search; its code xrefs land in #4/#5's functions |
| 26 | speed cap table (13 dwords `{100..200}`) | `0x016F9E84` | data scan: `64 00 00 00 69 00 00 00 6E 00 00 00 73 00 00 00 78 00 00 00 82 00 00 00 8C 00 00 00 96 00 00 00 A5 00 00 00 B9 00 00 00 BE 00 00 00 C3 00 00 00 C8 00 00 00` — **unique** |
| 27 | brain tick global (`DAT_01a5ee04`) | `0x01A5EE04` | no AOB (data global); re-find from the hunt brain (#13): the `MOV EDX,[<g>]; ADD EDX,0x3E8; CMP EAX,EDX` sequence right after its is-hunting call |
| 28 | client / hero global (`DAT_01a549a0`) | `0x01A549A0` | no AOB; re-find from #14 (client accessor `A1` dword) |
| 29 | manager global (`DAT_01a55220`) | `0x01A55220` | no AOB; re-find from #15 (manager accessor `A1` dword) |
| 30 | CUserAttribMgr global (`DAT_01a58fe0`) | `0x01A58FE0` | no AOB; re-find from its accessor (same `83 3D` shape as #14/#15, disambiguate by the `0x01A58FE0` dword; accessor @ `0x00832A5D` in this build) |

Verification workflow after every pattern hit: disassemble the candidate,
confirm the semantic (e.g. the toggle handler's `CALL` targets the manager
accessor; the XP gates' JNZ is immediately followed by the `PUSH <string>` of
`STR_CANNOT_USE_XP_WHEN_HANGUP`; the cap table is data, not code), then update
the `*_ADDRESS` constants in the hook modules and the tables above.

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
| `+0x04` | int | attack-target X written by the brain (FUN_00f54df8) when attacking in range; `0` while walking / target out of range. **In-combat signal for the attack boost** — treat as combat only when `0 < value < 0x100000` (the brain writes a loot POINTER here while looting). Can go stale after a kill — clear it (`ClearAutoHuntTarget`) when the finder sees nothing |

### Speed cap table contents (client 7950)

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
- **Cancel attack animation (`speed.cpp`, 2026-08-20):** while auto-hunt is
  hunting and `mgr+0x04 != 0` (brain attacking in range), write the `role+0x44`
  boost (slider 100–3000%, default 500 → attack interval
  `ceil(base*100/600)` ≈ 217 ms for a 1300 ms melee base) so the attack
  animation is largely skipped and attacks fire at the brain-tick rate
  (fast-loot tick, default 50 ms). Walking keeps the
  manual slider speed; a stale `mgr+0x04` is cleared via the brain's finder
  (`FUN_00f43828`) when no monster is near. Attack packet = `CMsgAction` id
  0x12/0x13 sent by `FUN_00f67675` from the combat handler `FUN_0112112c`
  (called by the brain each tick). Server tolerates ~20 attack packets/sec —
  the 500% cadence (~4.6/sec) is well inside it; raising the slider toward
  3000% (~23/sec) matches the fast-loot tick that already works.
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

## Character Buffs / StatusIcons (VERIFIED on client 7950)

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

**My C3DUser** = `DAT_01a53980` itself. Every status API (`AddStatus`
`FUN_00eedd80`, `ClearStatus` `FUN_00ef25c5`, `ChkStatus` `FUN_00f1af78`)
does `ADD ECX,0x138` on the object `FUN_0043e581` returns — i.e.
`DAT_01a53980+0x138` is the ground-truth bitfield. ⚠️ The `+0x98` chain tail
is a DIFFERENT object on some builds (the client object links other entities)
— do NOT read statuses from the tail; use `DAT_01a53980+0x138` (the chain
walk is kept in buffs.cpp for diagnostics only).

**Implementation note (`buffs.cpp`):** reads the 72-byte bitfield at
`DAT_01a53980+0x138` every frame (mirroring the game's own ChkStatus object —
NOT the +0x98 chain tail), parses `StatusTips.ini` for names, and renders every
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

## Auto Gear Swap (native alternate-equipment feature, client 7950)

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
| `0x00A653E4` | main-window WndProc XP-icon show gate: `ChkStatus(hero, 0xA) || ChkStatus(hero, 0x5) → FUN_005F254F` (status 5 is the EDI loaded via `PUSH 5; POP EDI` at 0x00A65346) — **NOT live in this build** (both statuses verified off while the pop was up) | byte `6A 05 5F 8B B5 04 8D FF FF` |
| `0x005F254F` | XP-icon show handler (thiscall, ECX = mainWindow+0x3B7B68) → `SetBar(mainWindow+0x408BF8, 1)` — dead chain (never called live) | prologue `56 8B F1 6A 00` |
| `0x005F25BA` | XP-icon hide handler → `SetBar(mainWindow+0x408BF8, 0)` — dead chain | prologue `56 8B F1 E8` |
| `0x00AE622B` | `CDlgXp::SetBar` (dlgxp.cpp) — sets `CDlgXp+0xAA8` = 1/0, then `FUN_00AE4949 → FUN_00AE6708` (render) / hides the window. **Never fired live** (hook stayed at 0 while the icon was up) | prologue `55 8B EC 56 6A 05` |
| `0x00AE61F8` | **THE LIVE XP-pop show/hide setter** — MinHook target. `__thiscall(panel, show)` writes `panel+0xAC8 = show`. Show: WndProc msg → `FUN_00601E67(mainWindow+0x3B7B68)` → `FUN_00AE61F8(panel,1)` + `FUN_00AD0EA2` (picks `XpSkillType%u` from `FUN_00D96E5C()+0x5c`, MoveWindow). Hide: WndProc msg → `FUN_00AE61F8(panel,0)` (panel+0x7C0760) + `FUN_00C264D1` fgui hide. Third caller 0x00A667F9 syncs +0x7C0760's flag from a WndProc state local | body `55 8B EC 8A 45 08 88 81 C8 0A 00 00 C2 04 00` (11 bytes, RELOCATABLE) |
| panel `+0xAC8` | pop show flag (byte): 1 = XP pop on screen, 0 = hidden — read as ground truth each frame | written by FUN_00AE61F8 |
| `0x00601E67` | WndProc XP-pop show handler (thiscall, ECX = mainWindow+0x3B7B68): gated on `*(int*)(&DAT_004096a4+param_1)==0`; XP level count `FUN_011AEBF7()`; if `FUN_00DEFE15()` and unlocked count>0 → `FUN_00AD0EA2()` + `FUN_00AE61F8(1)` | called @ 0x00A53B46 |
| `0x00AD0EA2` | per-frame XP-pop panel updater (thiscall, panel in ECX): reads +0xaa8/+0xab0, `EnableWindow` on +0xbc0 child from `FUN_011AEBF7()` count, `XpSkillType%u` icon pick, MoveWindow | callers 0x00A4AE74, 0x00601E67, 0x00A54230, 0x00AE5FC7 |
| `DAT_01a53980 + 0x138` | hero 576-bit status bitfield — the object/field the game's own ChkStatus reads (`FUN_00F1AF78`: `ADD ECX,0x138`); bit `(id&63)` of 64-bit word `(id>>6)` (layout per `FUN_00D4ED8E`). Used as a configurable fallback gate | `CMP [EBP+8],0x23F; JA; ADD ECX,0x138; JMP 0x00f1f86d` |

Equipment positions: MAIN slots 0x65..0x73 (101..115); ALT = MAIN + 0x14 =
0x79..0x87 (121..135); special alt slots +0x384/+0x388. Action types:
0x2C = swap to MAIN, 0x2D = swap to ALT, 0x198 = equip/refresh.

Implementation (`gear_swap.cpp`): calls `FUN_00FF219D(hero)` via a
`__fastcall` fn pointer. Trigger: **the LIVE pop signal** — MinHook on
`FUN_00AE61F8` (the pop show/hide setter, body `MOV [ECX+0xAC8],AL / RET 4`)
captures the panel instance(s) and each frame `gear_swap.cpp` reads
`panel+0xAC8` (plus real HWND visibility via `CWnd::m_hWnd` at +0x20) as
ground truth, wearing ALT while it is 1, MAIN the moment it clears (the skill
activation consumes the pop). Both the CDlgXp::SetBar chain (`FUN_00AE622B`)
and the status-gate path (status 10/5) were verified NOT live in this build
(SetBar hook fired 0 times, statuses stayed off while the icon was up); the
status ids remain in the UI as an optional OR-fallback for other servers.
Waits for hero+0x193C to flip (5s timeout) before re-arming; 1.5s send
cooldown; auto-stops after 2 consecutive unconfirmed sends.

---

## Login flow / Auto Login (VERIFIED on client 7950)

The login screen is a real MFC dialog `CDlgLogin` (source `myshell/dlglogin.cpp`,
RTTI string `CDlgLogin` @ `0x016036A0`) with real Edit (account/password/token) +
Button (Login) HWND controls, plus an fgui canvas `login_xzk` (`0x01603D80`) for the
themed chrome (`Login_xOrangeBtn`/`Login_xRedBtn` @ `0x015598F8`/`0x01559940`).

| Function | Address | Meaning |
|---|---|---|
| `FUN_LoginButtonHandler` | `0x008A8FCA` | `__fastcall(CDlgLogin*)` — the Login button handler. Reads account (`dlg+0x13B88` std::string), password (`dlg+0x13BD0` CEncryptData, alt `dlg+0x13980` for poker path, selected via `dlg+0x13620` flag; `PUSH EAX` `LEA EAX,[EDI+0x13BD0]` @ `0x008a92c1`), group/server (`dlg+0x135F8`/`+0x135FC`), server name; then calls `FUN_0101C9D8` |
| `FUN_0101C9D8` | `0x0101C9D8` | **the login-packet sender**: `login(account, password, serverName, mode, extra)` (`PUSH 0x408` prologue, `password` is `CEncryptData*` checked `if(pwd==0) CHECK pStrPsw` @ `0x0101c9ea`, len via `FUN_00eb07f9` @ `0x0101ca2f`). mode 0 → `CMsgAccountEx` (`FUN_00F7F7E8`), 1 → QR `CMsgAccountByQRCode` (`FUN_00DE30E0`), 2 → poker `CMsgAccountPoker` (`FUN_00F7F9E3`) |
| `FUN_00ea1f50` | `0x00EA1F50` | `CEncryptData::SetString` — `void __thiscall(void* this, const char* plain)` encrypts plain into `this+0x108` buf[0x100], len at `this+0x104` (`encryptdata.cpp:0x1dc`, `strncpy +0x108,0x100` then `*pb = (c*'g'-0x7f)*c ^ key ^ (i>>4)*'f' ^ *pb ^ 0xb9`). Hook target for password packet guarantee |
| `FUN_00eb07f9` | `0x00EB07F9` | `return *(CEncryptData+0x104)` — password length accessor (called on `ESI` password @ `0x0101ca2d`) |
| `FUN_00607cd5` | `0x00607CD5` | thunk `ADD ECX,0x30C; JMP 0x00ED3462` — password field edit-sync helper (called as `FUN_00607cd5(dlg+0x13BD0)` @ `0x0089c...` in `CDlgLogin::Process`) |
| `FUN_00BFEE8B` | `0x00BFEE8B` | visibility gate used by the dispatcher: `IsWindow(dlg+0x20) && IsWindowVisible(dlg+0x20)` |
| app object accessor | `0x0041F880` | returns `DAT_01a546f4` (the main app object; same `83 3D` lazy-accessor shape as #14/#15 in the re-find map — disambiguate by the `0x01A546F4` dword) |
| `appObj + 0x39B948` | member | the `CDlgLogin` instance inside the app object (dispatcher does `LEA ECX,[EBX+0x39B948]` before `CALL FUN_LoginButtonHandler`) |
| dispatcher call site | `0x00A5B90E` | `LEA ECX,[EBX+0x39B948]; CALL FUN_LoginButtonHandler` — the fgui button click route |
| `FUN_008A965F` | `0x008A965F` | the server-select-first variant (called instead when the client must pick a server before login) |
| `FUN_0089C013` | `0x0089C013` | `CDlgLogin::Process` (per-frame input/focus handling; identifies the edits via `dlg+0xCD0`/`+0xFE8`/`+0x1300` CWnd members) |
| `CDlgLogin::OnEnSetfocusEditPwd` | `0x0088CEE7` | EN_SETFOCUS on password edit — `__fastcall(this)`; if `*(this+0x13DD8)!=0` then vtable-SetFocus on `*(*(this+0x13DD8)+0x34)`. **Does NOT call CEncryptData::SetString** — just forwards focus to the underlying edit HWND. (string `0x016042c4`, throw name in catch @ `0x0088cf10`) |
| `CDlgLogin::OnEnSetfocusEditAccount` | `0x0088CEA1` | EN_SETFOCUS on account edit — same shape, calls vtable-SetFocus via `FUN_005eb941`. (string `0x016042a0`, throw name in catch @ `0x0088ceca`) |
| `CDlgLogin::OnEnKillfocusEditPwd` | `0x0088CE15` | EN_KILLFOCUS on password edit — same shape, calls vtable-`vfunc[0x20]` via `FUN_006102f6 → 0x006102e8`. (string `0x01604308`) |
| `CDlgLogin::OnEnKillfocusEditAccount` | `0x0088CDCF` | EN_KILLFOCUS on account edit — same shape as KillPwd. (string `0x016042e4`) |
| `login_xzk` fgui window | `0x01603D80` | shown via `FUN_00875E43`, hidden via `FUN_008A79AE` |

**⚠️ The login button is an fgui control, NOT a standard MFC button.** Live test:
`SendMessage(btn, BM_CLICK)` × 784 did NOTHING (dialog stayed up). The button's Win32
text is e.g. `"EnterGame"` (CtrlID 5680, set at runtime — the literal is not in the
binary) while the displayed label is e.g. `"Log In"` (drawn by the fgui engine). The
fgui UI layer only responds to mouse input.

**⚠️ ImGui overlay corrupts the click (root cause of "works only with overlay
closed"):** `ImGui_ImplWin32_WndProcHandler` (called from the overlay's subclassed
WndProc for every message) calls `::SetCapture(hwnd)` + `io.AddMouseButtonEvent()` on
every `WM_LBUTTONDOWN` — this breaks the fgui control's click processing while the
overlay is open (a SendInput real click logged in fine the moment the overlay was
closed). Fix: `auto_login.cpp` sets the new `g_suppressImGuiWndProc` flag
(`directx_hooks.cpp`) around its synthetic click so the game's WndProc sees the raw
messages. The flag also covers real SendInput clicks.

Re-find anchors: the `dlglogin.cpp` path string `0x016035F8` — its code xrefs land in
every `CDlgLogin` method (Ghidra auto-names the handler `FUN_LoginButtonHandler`);
the `"CDlgLogin"` RTTI string `0x016036A0` → type-info at `0x015FD208`.

**Implementation (`auto_login.cpp`): window-shape discovery (no game addresses) +
programmatic press.** Finds the login dialog by child-window shape (process-owned
window with ≥1 Edit + ≥1 Button child), finds the Login button (pinned CtrlID override
→ text match → longest enabled+visible non-close Button), then — default method —
sends `WM_LBUTTONDOWN` + `WM_LBUTTONUP` straight to the button HWND via `SendMessage`
(**no cursor movement**), with `g_suppressImGuiWndProc` held so the fgui WndProc gets
them clean. Auto mode re-clicks every `g_clickIntervalMs` (1 s default) until the dialog
disappears, then disarms. Selectable methods: 0 = Message (default), 1 = SendInput real
mouse (moves cursor), 2 = BM_CLICK (proven dead on this build). The debug tree lists
every Button child with its CtrlID + per-button "use"/"click" testers.

**Account + Password fill (`accountinfo.ini`, next to the exe):** `LoadActiveAccount()` scans
`[AccountN]` sections, picks the first with `Use=1`, reads `User=` (plain account) and
`Pass=` (plain password, optional) into `g_activeAccount`/`g_activePassword`.

* **Fill Account button** — `WM_SETTEXT` for display + `MinHook` on `FUN_0101C9D8`
  (`0x0101C9D8`) that replaces the `account` arg (when empty/matching) so the server
  always gets the ini `User` regardless of fgui sync. Also types via `SendInput` if needed
  (fgui edits ignore `WM_SETTEXT`, real keys trigger `CDlgLogin::Process` `+0x13B88` sync).

* **Fill Password button** — separate button, same ini section. Types plain `Pass=` with real
  `SendInput` `KEYEVENTF_UNICODE` keystrokes into the password Edit (second smallest Y,
  `dlg+0xFE8` `CWnd`; `ResolveAccountEdit` finds it as `scan.second`). `Ctrl+A → Delete → type`
  triggers `Process` `FUN_00607cd5(dlg+0x13BD0)` → `CEncryptData::SetString` `0x00EA1F50`
  that encrypts into `dlg+0x13BD0+0x108` (len `+0x104`), so the handler's
  `FUN_0101C9D8(dlg+0x13BD0)` carries the right pwd. The same `FUN_0101C9D8` hook
  also re-encrypts `Pass=` into the passed `CEncryptData*` in-place (via `0x00EA1F50`)
  as a packet-level guarantee — survives offset moves, no `dlg+0x13BD0` write needed.

Format:

```ini
[Account1]
User=myusername
Pass=myplainpassword
Use=1
[Account2]
User=otheruser
Pass=otherpass
Use=0
```

Account/Password/section diagnostics are shown in the Auto Login UI and debug tree. `Pass=` is plain text — keep the file private.

---

## Auto Relogin / Disconnect Handling (VERIFIED on client 7952, 2026-09-02)

Extends the Auto Login module with a per-frame relogin state machine. Startup
login works automatically; after a server drop (error box → OK → login screen
reappears) the module auto-dismisses the box, checks internet reachability, and
re-arms fill+click when the connection is back.

### State machine (auto_login.cpp, `ApplyClientSideState`)

```
REL_IDLE (0) ──dialog visible──► REL_WAIT_LOGIN (1) ──dialog closed──► REL_IN_GAME (2)
REL_IN_GAME ──dialog reappeared──► REL_DISCONNECTED (3) ──dialog usable──► REL_CHECK_NET (4)
REL_CHECK_NET ──internet up──► re-arm fill+click → REL_WAIT_LOGIN
REL_CHECK_NET ──internet down──► REL_WAIT_NET (5) ──backoff expired──► REL_CHECK_NET
```

* Disconnect detected when the login dialog (CDlgLogin m_hWnd) reappears while
  in `REL_IN_GAME`.
* Internet check: non-blocking TCP `connect()` to `8.8.8.8:53` with a 3s
  `select()` timeout (`IsInternetUp()`).
* Retry backoff: 5s → 10s → 20s → 40s → 60s (capped).
* Click pacing: first click after arming uses `ClickIntervalMs` (1s); every
  re-attempt after a failed click uses `ClickRetryMs` (10s default, ini
  `[AutoLogin] ClickRetryMs`, 3s–60s).

### Offsets & hooks used (all verified 7952)

| What | Address | Notes |
|---|---|---|
| `gpDlgShell` global (CMyShellApp) | `0x01A5A510` | `CDlgLogin` instance at `+0x39B948`; login-dialog HWND (m_hWnd) at `+0x20` |
| Login dialog usability | — | `IsDialogUsable(hwnd)`: true ONLY if `hwnd == *(gpDlgShell+0x39B948+0x20)` AND `IsWindowVisible`. The EnumWindows shape-fallback was REMOVED (it picked up in-game dialogs with Edit+Button children → false disconnect). |
| Login button handler | `0x008A8FCA` | `FUN_LoginButtonHandler` — reads account `dlg+0x13B88`, password `dlg+0x13BD0` (CEncryptData), sends via `FUN_0101CB78` mode 0. Reconnect gate virtual `(*(dlg+0xdc68)+0x80)()` + `FUN_0111a10b` (byte `obj+0x5428`) → QR path `FUN_008A965F` (mode 1, slots `0x13938`/`0x13980`). Poker path selects via `dlg+0x13620`. |
| Login packet sender | `0x0101CB78` | `login(account, pwd, serverName, mode, extra)` — MinHook target (`HookedLoginSend`), forced to log + pass-through; slots pre-filled by `WritePasswordBlob` (canonical X). |
| `CEncryptData::SetString` | `0x00EA20F0` | canonical-encoded X write into `dlg+0x13BD0` / `0x13980` / `editCEnc+0x30C`; raw text into `editCEnc+0x238`. |
| `CEncryptData::GetString` | `0x00EB3383` | debug decode. |
| Disconnect error key | `0x0165DFEC` | UTF-16 string KEY `STR_LOGIN_GAME_SERVER` (text "Disconnected with game server..." resolved at runtime by `CStringManagerW::GetStr` from game data — NOT in the binary). |
| Disconnect error key 2 | `0x0165DFCC` | UTF-16 `STR_CONNECT_BGP`. |
| `CStringManagerW::GetStr` | `0x01224260` | key → display text resolver. |
| Tip show chokepoint | `0x007FD29B` | `__thiscall(dialog, text)` — virtual call at `dialog+0x22D8` vtable+0xB4 shows the fgui/MFC error box. |
| `CDlgMsgBox` | RTTI `0x01A366DC` / COL `0x017DF850` / vftable `0x01694C38` | the error message box class. |
| `CMsgDisconnect` | RTTI `0x01A51CE4` / COL `0x01809BF0` / vftable `0x01746B60` / ctor `0x011D822F` / dtor `0x011DBC5C` | server-sent disconnect message; built by dispatcher `FUN_00f3874e` (case at `0x00f3b196`), processed by generic `FUN_010c99e4`. |
| MessageBoxA/W | user32 | MinHook — auto-return IDOK for disconnect-keyword text while `g_wasInGame` (box never appears). |
| Window scan | `EnumWindows` | `DismissDisconnectBox()` (400ms) finds the box by title/child text, BM_CLICKs its OK — fallback for fgui/MFC boxes the API hook can't catch. |

### Verified behavior (live log 2026-09-02)

```
REL | login screen appeared - arming auto login
FILL_ACCOUNT | account written (0x13938 cleared)
FILL_PASSWORD | canonical X=04 A4 CD 04 C7 CD CF 97
CLICK_LOGIN | method=0
HOOK_ENTRY | acct="halms" slot=dlg+0x13BD0 server="DuneWanderer" mode=0
(no further REL lines while in game)
```

### Gotchas (learned this round)

* `client+0x5385` is the AUTO-BATTLE byte (`8A 81 85 53 00 00 C3` getter
  `FUN_01116e10`), NOT an in-game flag — do NOT gate auto-login on it.
* `CUserAttribMgr` global `0x01A58FE0` and the login-success globals
  `0x01A5FC64/68/6C/70` are one-shot / persist after exit — unusable as
  persistent state.
* Only the exact CDlgLogin HWND + `IsWindowVisible` decides "at login screen".
* The DLL loads twice (proxy + injected) — hooks are idempotent, single-owner.


