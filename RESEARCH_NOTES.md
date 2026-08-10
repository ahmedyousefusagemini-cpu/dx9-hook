# Reverse Engineering Notes — Conquer.exe (client 7937)

Working state as of 2026-08-10 (PM update: toggle path fully resolved + ImGui integration shipped — see below).
Ghidra project: `private_client` (Conquer.exe + GameData.dll + Role3D.dll imported).
Access path: Ghidra MCP bridge via ngrok tunnel (ghidra-mcp, bridge on 8081, plugin on 8089).

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
+0x10  WORD state = 0x100 (256) at creation — manager writers (byte-scan exhaustive):
         - ctor FUN_00f26499 @ 00f264e2: 0x100 (default)
         - dtor FUN_00f2a150 @ 00f2a19c: 0x100 (reset on teardown)
         No immediate 0x101 write to the MANAGER exists. FUN_00c822eb's 0x101 write
         targets a different 0x14-byte item struct (see PM update below). The runtime
         0x100<->0x101 flip must be a byte write to +0x10 and/or server-ack driven.
+0x11  byte  — read by getter FUN_00f4761b; note: after ctor, word +0x10 = 0x100
         means byte +0x11 = 0x01 already — FUN_0111621f is effectively gated by the
         client auto-battle byte. Verify live with the overlay debug readouts.
+0x12  byte  — ctor sets 0; read by getter FUN_00f4761f; per-frame dispatcher FUN_0112ef9d checks it
+0x14  DWORD timestamp — written by FUN_00f2fcd5 (timeGetTime) when called with flag=0
+0x18..+0x2c assorted lists/flags (ctor zeroes)
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
- Dialog packet handlers cluster: 0x004c1641 ... 0x004c1bd9 (serialize dialog state to/from packets) — likely home of the 0x855 ack handler.
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
    state flip must be a byte write to +0x10 (`C6 4? 10 00/01` candidate lists were
    collected but untriaged) and/or arrive with the server ack of packet 0x855.

### Overlay integration (shipped in src/hooks/auto_hunt.cpp)

- **Decision (next-step 3): call the game's own toggle `FUN_00bd7355` directly** —
  no args, plain RET, goes through the legitimate CMsgHangUp/0x855 packet path
  (encryption/sequencing handled by FUN_010ce686). Rejected: calling the manager
  method by hand (more setup, same effect) and hand-crafting packet 0x855 (fragile).
- The ImGui button is state-aware ("Start Auto Hunt" / "Stop Auto Hunt") gated on a
  guarded replica of FUN_0111621f.
- Sanity guard: feature self-disables unless bytes at 0x00BD7355 are `6A 00 E8`
  (PUSH 0; CALL) — protects against running on a different client build.
- A collapsible "Auto Hunt Debug" tree dumps live client+0x5385 and
  mgr+0x10/+0x11/+0x12/+0x14 for the in-game verification (next-step 4).
- Calls run inside HookedEndScene (game thread on this client), the same context
  the dialog buttons execute in.

---

## Overlay/DLL work (separate repo state)

- D3DX9_43 proxy DLL, ImGui overlay (INSERT), memory scanner with background scans + unknown-value
  snapshot scans, input hooked on BOTH parent window (keyboard) and render window (mouse),
  window non-collapsible reverted to collapsible per user request, debug input counters added.
- Auto Hunt section added: Start/Stop button + status + debug state dump (auto_hunt.cpp).

## Next steps

1. ~~Decompile FUN_00c822eb~~ — done: hypothesis corrected (item-struct initializer, not the manager setter).
2. ~~Find the matching reset (0x100 write)~~ — done: exhaustive scan; no immediate stop-setter exists.
   Optional: triage `C6 4? 10 00/01` byte-write candidates to find the exact runtime writer.
3. ~~Decide overlay implementation~~ — done: call FUN_00bd7355 (shipped in auto_hunt.cpp).
4. Verify semantics in-game: click Start, confirm mgr+0x14 updates immediately (client-side),
   then watch client+0x5385 / mgr+0x10 / +0x11 / +0x12 for the server-ack transition.
5. Still open: find the writer of mgr+0x11 / the incoming 0x855 ack handler (dialog packet
   handler cluster 0x004c1641 ... 0x004c1bd9 is the likely home).
