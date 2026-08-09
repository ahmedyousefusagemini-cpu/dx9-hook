# Reverse Engineering Notes — Conquer.exe (client 7937)

Working state as of 2026-08-10. Ghidra project: `private_client` (Conquer.exe + GameData.dll + Role3D.dll imported).
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

### Manager object layout (size 0x44)

```
+0x00  vtable ptr
+0x04  dword = 0          (ctor)
+0x08  dword = 0x7fffffff (ctor)
+0x0c  dword = 0x7fffffff (ctor)
+0x10  WORD state = 0x100 (256) at creation — the only writers:
         - ctor: 0x100 (default)
         - FUN_00c822eb @ 0x00c822fc: `mov word ptr [ECX+0x10], 0x101` (257) — ONLY such write in the binary.
           Matches the memory-scan observation (256 while hunting, 257 state transition).
+0x11  byte  — read by getter FUN_00f4761b
+0x12  byte  — ctor sets 0; read by getter FUN_00f4761f; per-frame dispatcher FUN_0112ef9d checks it
+0x14  DWORD timestamp — written by FUN_00f2fcd5 (timeGetTime) when called with 0
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
| FUN_00f2fcd5 (0x00f2fcd5) | if arg==0: mgr+0x14 = timeGetTime(); calls FUN_00e6a590(arg), FUN_00e6179c() |
| FUN_00e6a590 (0x00e6a590) | PACKET BUILDER: writes [0]=0x16, [2]=0x855 (packet type 2133), [4]=(arg^1)*2+1 — the auto-hunt start/stop notification packet |

### Toggle chain (stop path found so far)

```
command 0x201/0x202 (dialog Begin/Stop button)
  -> FUN_00be7d0d  (dispatcher: if cmd in {0x201,0x202} -> ...)
      -> FUN_00bca328
          -> FUN_00bd7355  = accessor FUN_00482705() + FUN_00f2fcd5(0)
          -> FUN_00c25801(0)  (big CWnd show/hide: hides the dialog)
```

Handler table referencing FUN_00be7d0d: `0x016a9f70` (array of function pointers:
0x00be7d0d, 0x012625f4, 0x01262600, 0x01262606, 0x0126260c, ... — command-id -> handler table).

### Client-level auto-battle flag

- Client object (from FUN_0043e481 accessor, global `DAT_01a52960`) has a byte flag at `client+0x5385`
- Getter: `FUN_0111524b` (0x0111524b) — `return *(byte*)(client+0x5385)`
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

## Overlay/DLL work (separate repo state)

- D3DX9_43 proxy DLL, ImGui overlay (INSERT), memory scanner with background scans + unknown-value
  snapshot scans, input hooked on BOTH parent window (keyboard) and render window (mouse),
  window non-collapsible reverted to collapsible per user request, debug input counters added.

## Next steps

1. Decompile FUN_00c822eb (0x00c822eb) — the only writer of word 0x101 at +0x10; confirm it's the
   "start hunting" state setter; find its callers (button handler / hotkey path).
2. Find the matching reset (word 0x100 write) — the "stop hunting" setter.
3. Decide overlay implementation: call manager method directly (`this` = *(void**)0x01a531e0)
   vs call the dialog command path (FUN_00be7d0d with 0x201/0x202) vs send packet 0x855.
4. Verify semantics in-game: read mgr+0x10/+0x11/+0x12 before/after toggling from the overlay.
