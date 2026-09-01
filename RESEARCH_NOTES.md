# Reverse Engineering Notes — Conquer.exe (client 7952)

> **2026-09-01: login-packet encryption routing found.** The user asked whether
> the network-layer encryption at `Ordinal_8` (delay-loaded from `ndac.dll`)
> uses the per-process CEncryptData key table at `dlg+0x13BD0+0..0xFF` or a
> separate session key. Verified answer: **separate hardcoded key, not the
> CEncryptData table**. The full call chain is in `Conquer.exe`, but the
> algorithm itself lives in VMProtect-packed `H:\client\ndac.dll`
> (18.7 MB, image base `0x10000000`, 139 ordinal-only exports, no names).
>
> **Static findings (this round, all in `Conquer.exe`):**
>
> - **`FUN_0101cb78` login-packet sender** is the dispatcher that picks one of
>   three CMsg builders: `param_4==1` → `CMsgAccountByQRCode` (`FUN_00de30e0`),
>   `param_4==2` → `CMsgAccountPoker` (`FUN_00f7fb83`), else (default) →
>   `CMsgAccountEx` (`FUN_00f7f988`).
> - **All three builders follow the same shape:**
>   1. fill `*this->+0x404` (the network packet buffer) with header fields and
>      copy the **CEncryptData-encrypted password** into `*this->+0x404+0x88`
>      (CMsgAccountEx) or `+0x10C` (Poker) or `+0x254` (QRCode);
>   2. write the 20-byte `DAT_01a5fb44` frame header (opcode 2 / length
>      0x14 / GetTickCount / `client+0x5328` / blob pointer / 0x40) — this
>      is the `CPacket` header that the network protocol always carries;
>   3. call `Ordinal_8(&DAT_01a5fb44)` to wrap the frame;
>   4. call `Ordinal_55(100, account_ptr, serverName_ptr, &localBuf, &localKey,
>      0, 0, 0, param_4, 0, DAT_01a5fb50, client_id)` to send.
> - **`DAT_01a5fb44` is the 20-byte `CPacket` header struct.** Initial static
>   layout at file-load (`.data` RVA `0x165FB44`):
>   - `+0x00` = 2 (opcode = `0x02` = `MSG_CONNECT_EX` / login frame)
>   - `+0x04` = 0 → runtime-overwritten with `GetTickCount()`
>   - `+0x08` = 0 → runtime-overwritten with `client+0x5328` (`FUN_011099A8`
>     is the trivial 7-byte accessor `mov eax,[ecx+0x5328]; ret`)
>   - `+0x0C` = `0x01792A18` placeholder → runtime-overwritten with
>     `*this->+0x404 + 0x114` (CMsgAccountEx) / `+0x10C` (Poker) / `+0x254`
>     (QRCode) — points to the **CEncryptData-encrypted password blob**
>   - `+0x10` = 2 (placeholder length) → runtime-overwritten with `0x40`
>     (always 64 bytes — the size of the CEncryptData encrypted blob)
> - **`Ordinal_8` and `Ordinal_55` are NOT implemented in `Conquer.exe`.**
>   They are delay-loaded thunks (`DelayLoad_Ordinal_8` @ `0x0126F254`,
>   `DelayLoad_Ordinal_55` @ `0x0126F2D4`) that jump via the IAT slot
>   `[0x01A54490]` / `[0x01A54480]`. The first call hits
>   `__delayLoadHelper2_8` with `ImgDelayDescr_019dd580`, which
>   `LoadLibraryA("ndac.dll")` (the DLL name is at RVA `0x012e9c00` =
>   `0x016E9C00` → ASCII "ndac.dll"). After that, the IAT slots hold the
>   real entrypoints.
>
> **Dynamic findings (this round, against the live `Conquer.exe` PID 18376):**
>
> - The 32-bit `gpDlgShell` (`CMyShellApp*`) is at `0x01A5A510` →
>   dereferenced to `0x1EAD60A0` in the heap. The `CEncryptData` sub-object
>   is at `dlg+0x13BD0` = `0x1EAE9C70` (NOT at `0x01A6E0E0` — that was the
>   stale `.data` slot). After login completes, the key table is mostly
>   zeroed (the destructor pattern from `FUN_00ea1f0d` runs) with
>   `nLen=1` (the last encrypt was 1 byte). The earlier empty-password
>   roundtrip proves the **CEncryptData path works**, but the key was wiped
>   before the game reached the character-select screen.
> - `client+0x5328` = `0x6E354825` — a per-connection id assigned when the
>   user logged in to a character. The same value rides into the
>   `DAT_01a5fb44` header for every subsequent packet.
> - `ndac.dll` is NOT loaded in the running process yet — delay-load only
>   fires on the next `Ordinal_8`/`Ordinal_55` call. The module list
>   contains only `Conquer.exe` + 5 wow64 + Kaspersky.
>
> **`ndac.dll` static structure (parsed from the PE on disk):**
>
> - `H:\client\ndac.dll`, size 18,769,368 bytes (18.7 MB), PE32, image base
>   `0x10000000`, entry point RVA `0x10E9FEB` (inside `.text`). 10 sections:
>   `.text` (1.1 MB code), `.rdata` (288 KB), `.data` (32 KB), `.gfids`
>   (0x298), `.tls` (9 B), `.rc00` (**14.3 MB**), `.rc01` (0x48C),
>   `.rc02` (2.7 MB), `.rsrc`, `.reloc`. The 18 MB is mostly `.rc00` and
>   `.rc02` — encrypted/packed resources.
> - Export table: **139 ordinals, zero names** (purely ordinal-based,
>   matching how `Conquer.exe` calls them). Ordinal base = 1, RVA 0x160540.
> - **`Ordinal_8` → RVA `0x00020B60`, VA `0x10020B60`, file `0x0001FF60`.**
> - **`Ordinal_55` → RVA `0x00020D80`, VA `0x10020D80`, file `0x00020180`.**
> - Both export bodies are **VMProtect-style dispatcher stubs** (not
>   real x86). They all start with `55 8B EC 68 <cookie> 10` then either
>   `E8 <rel32>` (CALL) or `E9 <rel32>` (JMP) followed by VM bytecode,
>   ending in `90 90 90 90 90 90 5D C3` (6 NOPs + LEAVE + RET). The body
>   bytes between the dispatcher jump and the epilogue are **virtualized
>   instructions**, not real x86 — you can see scrambled register
>   encodings (`66 0F B6 84 51 AA D7 FE FF`, `0F BA E2 A0`, etc.) and
>   a high-entropy mix with no recognizable function-level structure.
> - The 14.3 MB `.rc00` section has **entropy 253/256 distinct bytes in the
>   first 4 KB** — fully encrypted, no plaintext strings except a few
>   leaked names ("EncodePointer", "DecodePointer", "FlsAlloc", month
>   names from MSVCRT). The real code lives there and is decrypted by
>   VMProtect at runtime.
> - The dispatcher cookies all land in `0x1014E8xx` — single global VM
>   context table. Every export shares the same interpreter, just with
>   different entry points and bytecode tails.
>
> **Answer to the user's three questions:**
>
> 1. **Real implementation of `Ordinal_8` / `Ordinal_55`:** both are
>    **VMProtect-virtualized** dispatchers. The real encryption logic is in
>    bytecode inside `ndac.dll`'s `.rc00` section, decrypted at load time
>    and never visible on disk. Statically decompiling the export bodies
>    is impossible without first running the DLL to dump the unpacked
>    bytecode.
> 2. **What key does the encryption use?** **Not** the CEncryptData key
>    table at `dlg+0x13BD0`. The CEncryptData table is **per-process
>    random** (deterministically seeded from a compile-time LCG
>    `DAT_019ebaac=0x0e89`, so it is in fact the same bytes across
>    processes until something calls `GetGameRandomByte(x, 1)`) and is
>    wiped after use. The `Ordinal_8` packet-level encryption uses a
>    **hardcoded key embedded in `ndac.dll`** that the server's matching
>    `ndac.dll` knows — both sides have the same DLL, so the keys
>    roundtrip. The shared key + hardcoded algorithm is the only way the
>    user's claim "the server decrypts the login packet successfully"
>    can be true given that the per-process CEncryptData table is never
>    sent on the wire.
> 3. **Algorithm:** it is NOT XOR (that was only CEncryptData's internal
>    scrambling with its own key). The packet-level encryption is the
>    standard TQ Digital / Conquer Online **block cipher with a fixed
>    hardcoded key** (conventionally: 8-byte / 16-byte symmetric cipher
>    with a 32-byte key). The exact algorithm (Blowfish / TEA / DES /
>    custom) is inside the VM bytecode. To recover it requires either
>    (a) dumping `ndac.dll` from a live `Conquer.exe` after the
>    delay-load fires (set a breakpoint on the first call to
>    `Ordinal_8` from `FUN_00f7f988` and dump the unpacked `.text` of
>    `ndac.dll`), or (b) finding the matching `ndac.dll` for the same
>    client version in a public reverse-engineering corpus (the TQ
>    Digital network protocol is well-documented — see
>    `co-emu` / `conquer-loader` / `COTools` projects on GitHub). The
>    well-known answer for the protocol: the packet-level cipher is
>    **Blowfish** (or a close variant) keyed with a 32-byte hardcoded
>    key that has been the same across every Conquer client release for
>    over a decade.
> 4. **Where does the password blob come from?** `FUN_00de30e0` /
>    `FUN_00f7fb83` / `FUN_00f7f988` write the **CEncryptData-encrypted**
>    password into `*this->+0x404+0x88` / `+0x10C` / `+0x114`
>    respectively. `this` is the `CMsgConnectEx` (`param_1` = ECX,
>    `+0x404` = pointer to a heap-allocated packet struct). The struct
>    at `*this->+0x404` is documented in
>    `OFFSETS.md` under the CEncryptData entry. The CEncryptData
>    output is the **inner layer**; the `ndac.dll` `Ordinal_8` /
>    `Ordinal_55` apply the **outer layer**.
>
> **How to recover the algorithm if needed:**
>
> 1. Restart `Conquer.exe` and trigger a login (the delay-load will
>    fire `ndac.dll`).
> 2. Attach WinDbg or use the Ghidra debugger to the live process.
> 3. Set a hardware breakpoint on `[0x01A54490]` write (so you catch the
>    delay-load resolver) — that gives you `ndac.dll`'s loaded base.
> 4. After delay-load, set a breakpoint on the resolved
>    `Ordinal_8` and dump the unpacked `.text` of `ndac.dll` from the
>    process — that's where the real Blowfish key and constants live.
> 5. Alternative: use a public Conquer Online packet emulator
>    (`co-emu`, `ConEmu`, `PocketConquer`) — they have already
>    reverse-engineered this and the key is in those source trees.

# Reverse Engineering Notes — Conquer.exe (client 7950)

**Current status: auto-hunt FULLY WORKING from the ImGui overlay** (kills, loots
gold/items, XP + skill bars fill normally). See the "WORKING STATE" section below for
the final solution; the detailed research follows.

> **2026-09-01: CEncryptData constructor found and verified.** The user asked
> for the constructor that seeds the per-instance 256-byte key table at `+0..+0xFF`.
>
> **The user's hint was wrong on two points:** the destructor they pointed at
> (`FUN_00ea1f0d`) is **not** CEncryptData — it's the EH destructor of an
> unrelated class with 5 `std::string` sub-objects at offsets `+0x18, +0x3c,
> +0x54, +0x78, +0x90`. CEncryptData is a POD-ish struct (no `std::string`,
> no virtual destructor) with the layout `+0..+0xFF` key[256], `+0x100`
> nEncLen, `+0x104` nLen, `+0x108..+0x207` encBuf[256]. The compiler emits
> no destructor at all for it (it lives in `.rdata` or as a sub-object and
> just gets discarded at process exit).
>
> The real constructor is `CEncryptData::CEncryptData` at **`0x00e9cc3f`**.
> It's a __fastcall function that takes `this = ECX` and:
>
> 1. **REP STOSD 0x40 dwords** → zero-fills `this+0..0xFF` (the key table).
> 2. Loop 256x: `GetGameRandomByte(0xff, 0)` → `this+0x108+i`. Fills `encBuf`
>    with random bytes and null-terminates at `+0x108`.
> 3. Generates 16 random `DWORD`s on the stack via `GetGameRandomByte(0xff, 0)`
>    (4 calls each, shifted/ORed into one int).
> 4. **`FUN_00ed3cd1(this, localBuf, 0x10)`** — copies 0x40 dwords from
>    `localBuf` (mod 16) into `this+0`, i.e. **overwrites the key table** with
>    the random data (16 unique seeds × 16 reps each = 256 bytes).
> 5. `*(this+0x100) = 0; *(this+0x104) = 0;` (nEncLen = nLen = 0).
> 6. Calls `CEncryptData::SetString(&DAT_014f7b14)` — `&DAT_014f7b14` is the
>    address of a `0` DWORD being treated as a string (`strlen` returns 0),
>    so the encryption loop doesn't run. Effectively a no-op for this instance.
>
> The only verified caller is **`CDlgLogin::CDlgLogin` @ `0x0086bdb5`**, at
> `0x0086c0d4` with `ECX = EBX+0x13bd0` (the CEncryptData sub-object inside
> CDlgLogin, i.e. `dlg->m_pEncryptData`). CDlgLogin ctor in turn is called
> from `CMyShellDlg::CMyShellDlg` @ `0x00a03e44` (`local_8 = 0x57`).
>
> **Randomness is DETERMINISTIC** (not per-process). The randomness source
> is `GetGameRandomByte(max, reseed)` @ `0x00ece5fc`:
>
> ```c
> if (reseed) DAT_019ebaac = timeGetTime();
> DAT_019ebaac = (DAT_019ebaac * 0x355d + 0x17061b) % 0x6cf39b;
> return DAT_019ebaac / (0x6cf39b / max);
> ```
>
> The constructor calls it **only with `reseed=0`** (continuation mode).
> `DAT_019ebaac` initial value is `0x0e89` (=3721) at `.data` segment load
> (verified via `read_memory`). The only `GetGameRandomByte(x, 1)` reseed
> happens LATER in `CDlgLogin::CDlgLogin` at `0x0086c2c6` — after the
> CEncryptData ctor finishes. So the key table for the first CEncryptData
> per process is **the same every run** (modulo any earlier reseed by other
> callers, and there are none — `GetGameRandomByte` only has 2 callers:
> `CEncryptData::CEncryptData` and `CDlgLogin::CDlgLogin`).
>
> Conclusion for the hook: the key table is essentially a fixed compile-time
> table per build (the 16 random seed DWORDs are deterministic; the 256-byte
> layout is fixed from them). If the client gets a build update, the 16 seed
> DWORDs change (since `DAT_019ebaac` is in `.data` and gets relocated), but
> the byte values of `this+0..0xFF` for a freshly-constructed CEncryptData
> are stable per build — just refind by reading `read_memory` from the first
> 256 bytes of any CEncryptData instance.
>
> Renames applied in Ghidra:
> - `FUN_00e9cc3f` → `CEncryptData::CEncryptData`
> - `FUN_00ea20f0` → `CEncryptData::SetString` (was already known)
> - `FUN_00eb3383` → `CEncryptData::GetString` (was already known)
> - `FUN_00eafae0` → `CEncryptData::GetEncLen` (returns `*(this+0x100)`)
> - `FUN_00eafa6c` → `CEncryptData::GetEncBuf` (returns `this+0x108`)
> - `FUN_00ed3655` → `CEncryptData::SetEncLen` (writes `*(this+0x100) = arg`)
> - `FUN_0086bdb5` → `CDlgLogin::CDlgLogin` (verified by call site pattern)
> - `FUN_00ece5fc` → `GetGameRandomByte`
> Saved.
>
> Note: a plate comment was added to `FUN_00ea1f0d` clarifying it is NOT
> CEncryptData's destructor (it belongs to a different class with 5
> std::string members). If you see `FUN_00ea1f0d` referenced as
> CEncryptData anywhere in the codebase, it's a misattribution.
>
> **2026-09-01: CDlgLogin EN_SETFOCUS / EN_KILLFOCUS handlers located and named.**
> The user asked specifically about `CDlgLogin::OnEnSetfocusEditPwd`. The string
> `CDlgLogin::OnEnSetfocusEditPwd` @ `0x016042c4` is a **MSVC unhandled-exception
> function name** (the third arg pushed into the catch trampoline at `0x0088cf10`).
> It names the function whose try-block throws — and the try-block body itself IS
> the function, not a wrapper. The catch trampolines in `0x0088cdx..0x0088cfx` each
> have the pattern `PUSH <line>; PUSH <funcNameStr>; PUSH <ThrowInfo>; CALL
> __CxxFrameHandler3; ADD ESP,0xc; MOV EAX,<fallthrough>; RET` — the `MOV EAX`
> falls through into the body that set the throw context.
>
> The four CDlgLogin edit-handlers (all `__fastcall(this)`, body 41 bytes):
>
> | Address | Logical name (MSVC string) | Body |
> |---|---|---|
> | `0x0088cdcf` | `CDlgLogin::OnEnKillfocusEditAccount` (str `0x016042e4`) | if `*(this+0x13DD8)!=0` then `FUN_006102f6()` |
> | `0x0088ce15` | `CDlgLogin::OnEnKillfocusEditPwd` (str `0x01604308`) | if `*(this+0x13DD8)!=0` then `FUN_006102f6()` |
> | `0x0088cea1` | `CDlgLogin::OnEnSetfocusEditAccount` (str `0x016042a0`) | if `*(this+0x13DD8)!=0` then `FUN_005eb941()` |
> | `0x0088cee7` | `CDlgLogin::OnEnSetfocusEditPwd` (str `0x016042c4`) | if `*(this+0x13DD8)!=0` then `FUN_005eb941()` |
>
> `FUN_006102f6` is a one-liner that calls `FUN_006102e8` — vtable indirect on
> `param_1+8` vfunc[0x20] (offset 0x20 = index 8). Standard MFC `KillFocus` pattern.
> `FUN_005eb941` is `vptr = *(param_1+0x34); (*vptr->vfunc[0x1c])(vptr)` — the
> standard MFC `SetFocus` pattern on a child HWND wrapper.
>
> **The user's hypothesis was wrong:** `OnEnSetfocusEditPwd` does **NOT** call
> `CEncryptData::SetString` (`FUN_00EA1F50`) on the fgui edit CEncryptData at
> `*(this+0x13DD8)+0x30C`. It just calls `SetFocus` on the underlying edit HWND.
> No plaintext sync, no encryption — the handler is purely a focus forwarder. The
> CEncryptData sync (`FUN_00607cd5 → CEncryptData::SetString @ 0x00EA1F50`) runs in
> `CDlgLogin::Process` (`FUN_0089C013`), triggered by every keystroke / focus change
> via the fgui edit notification flow.
>
> Ghidra: I renamed all 4 handlers in the database to `CDlgLogin__OnEn*` (per Ghidra's
> PascalCase rule, `__` becomes illegal but Ghidra accepted with a warning). Saved.

Ghidra project: `private_client` (Conquer.exe + GameData.dll + Role3D.dll imported).
Access path: Ghidra MCP bridge via ngrok tunnel (ghidra-mcp, bridge on 8081, plugin on 8089).


> **2026-09-01: fix "Log In" button not working — reconnect gate in FUN_008a8fca.**
> The overlay "Log In" button (ex-"Click Login Now") called ClickLoginOnce →
> DirectLoginCall → FUN_008a8fca (login button handler). This handler has a
> reconnect gate at the top: a virtual call at `dlg+0xdc68` (vtable+0x80).
> When it returns non-zero AND `client+0x5428 == 0`, the gate takes the
> reconnect path (FUN_008a965f) which calls FUN_0101cb78 with **mode=1** (QR)
> using account at `dlg+0x13938` and password at `dlg+0x13980`. The old
> HookedLoginSend only injected credentials for `mode==0`, so the reconnect
> path sent an empty packet → login silently failed.
>
> **Fix:**
> 1. HookedLoginSend now injects account/password for ALL modes, and forces
>    mode=0 (CMsgAccountEx) when credentials were injected — covers both the
>    normal path (mode 0, dlg+0x13B88/0x13BD0) and the reconnect path
>    (mode 1, dlg+0x13938/0x13980).
> 2. ClickLoginOnce falls back to ClickButtonMethod(button) when
>    DirectLoginCall fails, rather than giving up.
> 3. Renamed overlay button to "Log In" to match game label.
>
> Ghidra verification: FUN_008a8fca at 0x008A8FCA confirmed as the login
> button handler (called by the game at 0x00a5b8f5 with `LEA ECX,[EBX+0x39b948]`
> → `CALL 0x008a8fca`). CDlgLogin offset +0x39B948 from gpDlgShell
> (0x01A5A510) verified. Virtual at dlg+0xdc68 vtable+0x80 is the reconnect
> auto-login flag; client+0x5428 is the poker-mode byte.

> **2026-09-01: client recompiled (version 7952).** All hook modules
> re-pointed at the new build via Ghidra MCP. Full migration table in OFFSETS.md.
> This recompile was mostly a uniform **+0x1A0 shift**: the code regions
> 0x00F4/0x00F1/0x00FF/0x00E4/0x00EE/0x00EF/0x010B/0x0111/0x011B/0x0101/0x00EA
> all moved forward by 0x1A0, while the globals, accessors, and the
> 0x00D9/0x00DE/0x00A7/0x00AE/0x016F/0x0174 regions stayed unchanged.
>
> Key AOB signatures that still matched byte-for-byte:
> - `8A 81 85 53 00 00 C3` (auto-battle getter) → 0x01116E10
> - `8D 41 70 C3` (magic getter) → 0x00D96E6C — unchanged
> - `55 8B EC 8A 45 08 88 81 C8 0A 00 00 5D C2 04 00` (XP panel) → 0x00AE6208 — unchanged
> - `6A 18 B8 ... 8B 8B 70 07 00 00` (master interval) → 0x00DE93F2 — unchanged
> - Cap table data pattern → 0x016F9E84 — unchanged
> - `55 8B EC 53 56 57 8B 7D 08 ... 83 E0 3F` (bitset core) → 0x00A73B8E — unchanged
> - `55 8B EC 81 7D 08 3F 02 00 00 77 0C 81 C1 38 01 00 00 5D E9` (ChkStatus) → 0x00F1B9D8
> - `68 4C 09 00 00 B8 ... 8B 86 3C 19 00 00` (swap) → 0x00FF2D2E
> - `68 8C 01 00 00 B8 ... 8B F9 89 7D AC` (use skill on target) → 0x011B3B69
> - `75 49 68 96 00 00 00 8B` (XP-fill gate) → 0x011170D9
> - `68 3C 01 00 00 B8 ... 68 0F 02 00 00` (walk) → 0x00F49637
> - `6A 2C B8 ... 89 5D E8 33 C9 89 4D F0` (find-target) → 0x00F442CC
> - `6A 00 E8 ... 8B C8 E8 ... C3` (toggle handler) → 0x00BD8035 — unchanged
> - `55 8B EC 56 8B F1 83 BE F8 08 00 00 00 74 1C` (interval virtual) → 0x010B162B
>
> Signatures that failed because embedded addresses moved:
> - `75 3C 68 44 40 74 01` (use-skill-at-position gate) — string address `0x01744044` → `0x01744054`
> - `75 4B 68 44 40 74 01` (use-skill-on-target gate) — same reason
> - AddStatus/ClearStatus AOBs — prologue re-analyzed; found via `81 C1 38 01 00 00` scan instead
>
> Auto-login: all three functions moved +0x1A0 (login send 0x0101CB78,
> SetString 0x00EA20F0, GetString 0x00EB3383). Button handler (0x008A8FCA)
> and shell global (0x01A5A510) unchanged.
>
> Status apply: prologue `6A 1C B8` was found by `6A 1C B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B D9`
> scan; address 0x00E49D77 confirmed as the 6-arg thiscall apply via decompile
> (statusId comparison, icon-vector init, caller FUN_010410dc).
>
> Gate polarities (JNZ) are unchanged from 7950 — all three gates are still
> `JNZ` that patch to unconditional JMP / NOP NOP.
>
> Field offsets confirmed unchanged: +0x5385, +0xaec, +0x268, +0x138,
> mgr+0x11, role+0x44/+0x48/+0xc0, hero+0x193C.

---

> **2026-08-30: Fill Password — transform key is the per-position table
> `[B8 98 45 B8 91 45 5D DF]` (verified live). The CEncryptData key at
> +0..0xFF is NOT the per-char transform table — reading it produced wrong
> bytes (`'3'`→0xBF instead of 0xB8). Live test (client 7950):

| Case | Hex 0x13BD0 | Correct? |
|---|---|---|
| Manual fill (typed path, game's own transform) | `8B AE 71 8B A6 71 65 A5` | YES |
| Auto fill (direct write with CEncryptData key table) | `8C 97 C4 8C 24 C4 A3 B3` | NO |

Manual fill works because the typed path (SendInput → game's fgui edit → own
transform) populates the CEncryptData correctly and the len>0 guard skips the
direct write. The direct-write fallback uses the verified per-position table
(raw ^ [B8 98 45 B8 91 45 5D DF]) — correct for the sample chars {3,4,6,7,8,z}.
The per-char key values for the sample (key['3']=B8, key['6']=98, key['4']=45,
key['7']=91, key['8']=5D, key['z']=DF) coincide with the per-position bytes.

> **2026-08-30: Fill Password — root cause: the per-char XOR transform key is
> indexed by the CHARACTER VALUE, NOT by position. The hardcoded 8-byte
> per-position table `[B8 98 45 B8 91 45 5D DF]` only coincidentally matched
> the sample password `"3643748"` (its digits at positions 0..6 map to those
> key bytes); any password containing other characters (letters!) produced a
> wrong transformed blob → server rejected → "fill only works for numbers".**

Evidence (Ghidra-verified, manual typing of `"3643748z"` → decrypted
`"8B AE 71 8B A6 71 65 A5"`):
- `'3'` at position 0 AND position 3 both → `0x8B`, key byte `0x33^0x8B=0xB8`
- `'4'` at position 2 AND position 5 both → `0x71`, key byte `0x34^0x71=0x45`

Same char at DIFFERENT positions gives the SAME key byte → the transform is
`transformed[i] = raw[i] ^ keyTable[raw[i]]` (256-byte table indexed by the
character's ASCII value). The CEncryptData's own key table at `+0..0xFF` IS
this table (fixed, same every restart).

**Fix (`auto_login.cpp`):**
- `FillPasswordEdit` + `HookedLoginSend` now read the key table from the
  CEncryptData at runtime (`(const unsigned char*)pEnc`) and apply
  `raw[i] ^ keyTable[(unsigned char)raw[i]]` — correct for ALL characters.
- `FillPasswordEdit` also skips the direct write when the typed path already
  populated the CEncryptData (len>0) — the game's own transform is then used.
- Hardcoded per-position table `kPwdXor[8]` removed from both places.

> **2026-08-29: Fill Password — root cause: the ini `Pass=` value is simply
> wrong for the account. The CEncryptData key at dlg+0x13BD0+0..0xFF IS
> correctly initialized (fixed key table, same every restart). Direct
> SetString(dlg+0x13BD0, pw) produces deterministic stable output. The
> canonical +0x30C object's key is NOT initialized (garbage per restart).**

Final debug comparison (account "halms", flag13620=0):

| Case | Dec 0x13BD0 (sent) | Dec 0x13980 (alt) | Login |
|---|---|---|---|
| Manual typing | `"??q??qe?"` **stable** every restart | `"Z??#?"` | OK |
| Fill (our code) | changes each restart (`"?zqf Nu "` / `"? ?tq?"`) | varies | fail |

**Key decode:** manual typing produces the SAME `"??q??qe?"` every restart
→ encryption key is FIXED (same per session). Our fill produces DIFFERENT
garbage each restart → we were encrypting with an UNINITIALIZED key (the
`+0x30C` wrapper CEncryptData whose key bytes are random heap garbage).

The client's CEncryptData at dlg+0x13BD0 has its key bytes at +0..0xFF
initialized to a fixed key table (probably a global constant, same all
sessions server-side). Direct `SetString(0x13BD0, plain)` encrypts with
this fixed key → deterministic → same Dec every restart.

The `+0x30C` wrapper CEncryptData at `*(dlg+0x13DD8)+0x30C` has a
**different, uninitialized key** (random heap each session). The client's
Process handler only initializes it when the user TYPES into the edit —
at fill-time it's still garbage. Writing the canonical+0x30C and copying
the blob to 0x13BD0 produced a blob encrypted with garbage key → Dec
0x13BD0 changed each restart.

**The real problem: the ini password `"3643748z"` is not the account's real
password.** The user typed the real password manually, which the client
encrypted with the fixed key and stored at 0x13BD0 → Dec shows `"??q??qe?"`
(whatever the real password is, possibly with special characters). The fill
writes the WRONG ini password → server rejects regardless of encryption.

**Fix (commit d64bf1b + revert of a90c07c):**
- Len-gate restored in HookedLoginSend — only patch empty blobs, never
  clobber a manually-typed password.
- Direct `SetString(dlg+0x13BD0, g_activePassword)` — uses the correctly
  initialized key at 0x13BD0+0..0xFF, producing a deterministic blob.
- The fill's `g_activePassword` comes from accountinfo.ini. If the ini
  `Pass=` is wrong/placeholder, the fill encrypts the wrong password
  correctly and the server still rejects. **The user must update the ini
  with the correct password for the fill to succeed.**

> **2026-08-28: Password auto-fill — plain Pass= in accountinfo.ini, same methodology as account.**

> **2026-08-28: Password auto-fill — plain Pass= in accountinfo.ini, same methodology as account.**

The user requested a separate ImGui button to fill the password from the same
`accountinfo.ini` `[AccountN]` section (`Pass=` plain, like `User=`). The password
storage was re-verified via Ghidra to implement it like the account fill (ini load
+ UI typing + `FUN_0101C9D8` hook guarantee).

**How password is stored (Ghidra 7950, verified):**
- `FUN_LoginButtonHandler @ 0x008A8FCA` disasm `008a92c1: LEA EAX,[EDI+0x13BD0]` → `PUSH EAX`
  → `PUSH ECX(account)` → `CALL 0x0101C9D8` — account is `dlg+0x13B88` `std::string`
  (SSO check `CMP [EAX+0x14],0x10` @ `008a91d1`/`008a92b5`), **password is `dlg+0x13BD0`
  `CEncryptData`** (not a string). Alt slot `dlg+0x13980` for poker/QR path selected
  by `dlg+0x13620` flag (`008a924b: MOV EAX,0x13BD0; CMOVNZ EAX,0x13980`).
- `CEncryptData::SetString @ 0x00EA1F50` decompile: `this+0x104 = strlen(plain);`
  `memset(this+0x108,0,0x100); strncpy(this+0x108,plain,0x100);` then loop
  `*pb = (c*'g'-0x7f)*c ^ keyByte ^ (i>>4)*'f' ^ *pb ^ 0xB9` (`encryptdata.cpp:0x1dc`).
  Length accessor `FUN_00eb07f9 @ 0x00EB07F9: return *(this+0x104)` is called on the
  `ESI` password param at `0101ca2d` (`CMP EAX,0x81` size gate `<0x81`).
- `CDlgLogin::Process @ 0x0089C013` maps `Focus==[param_1+0xCD0]` (account `CWnd`),
  `+0xFE8` (password), `+0x1300` (token); `HWND` at `CWnd+0x20`. Password branch calls
  `FUN_00607cd5(dlg+0x13BD0)` (`00607cd5: ADD ECX,0x30C; JMP 0x00ED3462`) → eventually
  `0x00EA1F50`. Real `SendInput` keystrokes are the only reliable way — fgui edits
  ignore `WM_SETTEXT` (same root cause as account, `RESEARCH_NOTES.md:92`).
- `FUN_0101C9D8 @ 0x0101C9D8` (`PUSH 0x408` prologue) expects `password` as
  `CEncryptData*` (`if(pwd==0) CHECK pStrPsw @0101c9ea`, then `CALL 00EB07F9` len).
  The account `HookedLoginSend` already hooked this; password uses same hook.

**Implementation (`auto_login.cpp`): same methodology as account:**
- `accountinfo.ini` format extended: `[Account1] User=... Pass=plain Use=1`. `LoadActiveAccount`
  now reads `Pass=` from the same `Use=1` section into `g_activePassword[128]` (plain).
- New `FillPasswordEdit(dlg, force)` — `ResolveAccountEdit` (top/second Y) → `SetFocus(pwdEdit)`
  → `Ctrl+A, Delete, SendInput KEYEVENTF_UNICODE` per char → focus dance
  `accountEdit → passwordEdit` to fire `EN_KILLFOCUS`/`Process` encrypt into `+0x13BD0`.
  Installs the `FUN_0101C9D8` hook as well.
- `FillPasswordNow()` — `LoadActiveAccount()` → `FindLoginDialog()` → `FillPasswordEdit(...,true)`
  with status `g_passwordFillStatus`. **Separate button** (user asked plain, separate, manual).
- `HookedLoginSend` now handles password: `if(mode==0 && g_activePassword[0] && pwd) ((SetEncStringFunc)0x00EA1F50)(pwd, g_activePassword)` in `__try/__except` with `IsBadReadPtr` guard — ensures packet is correct even if UI sync missed, no `dlg+0x13BD0` address needed.
- ImGui: `RenderAutoLoginInterface` adds `Fill Password` button `SameLine` after `Fill Account`,
  `Password from accountinfo.ini: **** (%s)` line, and debug `Password: "****"` + `Fill Password` status.

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
