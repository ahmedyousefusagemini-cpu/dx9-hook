# ConquerDX9.Hook

DirectX9 hooking for Conquer Online with ImGui overlay

![Preview](img/img.png)

## Info

- Tested on Conquer Online game versions (developed against 7950)
- Compile on Release & x86
- Uses MinHook for function hooking
- ImGui overlay (toggle with INSERT key)
- Features: Always Jump, Wireframe/Chams, Speed control, Auto-hunt, Auto XP, Gear swap, Buffs
- Loading: D3DX9_43.dll proxy (no injector needed)

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
