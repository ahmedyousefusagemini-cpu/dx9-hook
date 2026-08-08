# ConquerDX9.Hook

DirectX9 hooking for Conquer Online with ImGui overlay

![Preview](img/img.png)

## Info

- Tested on Conquer Online game versions (developed against 7937)
- Compile on Release & x86
- Uses MinHook for function hooking
- ImGui overlay (toggle with INSERT key)
- Features: Always Jump, Wireframe/Chams, String modification, Memory Scanner
- Loading: D3DX9_43.dll proxy (no injector needed)

## Memory Scanner

Because the DLL runs inside the game process, the scanner reads and writes
memory directly (no `OpenProcess`/`ReadProcessMemory` needed). It works like
a minimal Cheat Engine built into the overlay.

All scans run on a **background thread** with a progress bar, so the game
keeps running smoothly while scanning. Press **Cancel Scan** to abort.

### Known value

1. Open the overlay with INSERT and scroll to **Memory Scanner**.
2. Pick a value type (Int32, UInt32, Float, Double, Byte, Int16, Int64),
   type the current value (e.g. your HP), and press **First Scan**.
3. Change the value in-game (lose HP, spend gold, ...), enter the new value
   (or pick Changed/Increased/Decreased), and press **Next Scan**.
4. Repeat until few addresses remain, click one in the results list, enter a
   new value and press **Write** (or **Freeze** to rewrite it every frame).

### Unknown initial value

1. Press **Unknown Value** to take a snapshot of all writable memory.
2. Change the value in-game, pick a comparison (Changed, Increased,
   Decreased, ...) and press **Next Scan**.
3. Keep refining with Next Scan until few addresses remain.

Notes:

- Scans walk `MEM_COMMIT` regions with read/write access via `VirtualQuery`,
  at natural alignment (4 bytes for Int32/Float, etc.).
- Snapshots are capped at 512 MB (32-bit address space is shared with the
  game); exact-value scans are capped at 2,000,000 matches.
- Results list shows at most 2,000 rows to keep the UI responsive.
- Frozen values are re-applied every frame, even while the menu is closed.

## Building

1. Select Release configuration and x86 platform
2. Build the solution
3. Output: `Release/D3DX9_43.dll`

(MinHook: place a v143-built `libMinHook.x86.lib` in `ConquerDX9Hook/libs/minhook/`
if it is not already there.)

## Usage (D3DX9_43 Proxy Method)

1. In the game folder (next to `Conquer.exe`), rename the original
   `D3DX9_43.dll` to `D3DX9_43_org.dll`
2. Copy your compiled `D3DX9_43.dll` into the same folder
3. Launch the game - it loads our DLL automatically (no injector needed),
   and every D3DX call is forwarded to `D3DX9_43_org.dll`
4. The overlay appears automatically; press INSERT to hide/show it

### Notes

- All 319 named `D3DX9_43.dll` exports are forwarded in
  `src/hooks/proxy.cpp`. If the game ever fails to start with a missing
  entry-point error, check which export it wants and add one more
  `/export:` line there.
- The old `Chat.dll` proxy (game version 6609) was replaced by this method;
  see the git history if you need it back.
- For DLL injection instead of proxying, build with any output name and
  inject with your injector of choice.

## Credits

Based on examples and concepts from [co-stuff/posts](https://github.com/co-stuff/posts)

## Libraries

- [MinHook](https://github.com/TsudaKageyu/minhook) (static lib expected in `libs/minhook`)
- [ImGui](https://github.com/ocornut/imgui) (included)
