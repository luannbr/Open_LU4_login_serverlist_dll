# LU4 Login / ServerList DLL + Launcher — LLM / agent reference

Dense, factual reference for an AI agent working on this repo. Human-readable docs:
[English](README.md) · [Português](README.pt-BR.md).

## 1. One-line purpose
Client-side DLL (`lu4authhook.dll`) + launcher that let the **LU4** game client
(`lu4-win64-shipping.exe`, Lineage 2–based, Unreal Engine 5.4, Windows x64) authenticate and
read a server list from a **private/emulator** server, by (a) validating UI-captured credentials
against a local TCP validator and (b) neutralizing the ServerList 32-byte MAC check.

## 2. Guardrails (do not drift)
- This is **private-server interoperability / emulation** tooling. It is **NOT** an anti-cheat or
  game-integrity bypass and must not become one. Do not add kernel-mode code, anti-cheat evasion,
  memory-scan hiding, or anything targeting official/commercial servers.
- Only two code sites in the client are modified (login call + 32-byte serverlist compare). Keep
  the blast radius minimal.
- Never commit secrets: real `lu4launcher.ini` (may hold `Login`/`Pass`), `lu4accounts.dat`,
  `*.log`. They are in `.gitignore`.

## 3. Components
| Binary | Source | Role |
|---|---|---|
| `lu4authhook.dll` | `src/lu4authhook.cpp` | injected hook: login validation + serverlist MAC bypass |
| `inject.exe` | `src/inject.cpp` | CLI injector: `inject.exe <pid> <dll>` via remote `LoadLibraryW` |
| `Inject-LU4.ps1` | — | finds game process, calls `inject.exe` |
| `lu4launcher.exe` | `src/lu4launcher.c` | console launcher |
| `lu4launcher_gui.exe` | `src/lu4launcher_gui.c` | Win32 GUI launcher (multi-account) |

## 4. Hook internals (`lu4authhook.cpp`)
Constants (build-specific; `base = GetModuleHandleW(NULL)`):
- `LOGIN_RVA = 0x4BB1850`, `LOGIN_COPY = 14` (bytes of prologue copied to trampoline).
- `CMP_RVA = 0xBFEEA0`.
- `VALID_HOST = "127.0.0.1"`, `VALID_PORT = 27110`.
- `MAGIC[32] = "LU4-MAGIC-SERVERLIST-MAC-BYPASS!"` (ASCII, no NUL; bytes `4C 55 34 2D 4D 41 47 49 43 2D 53 45 52 56 45 52 4C 49 53 54 2D 4D 41 43 2D 42 59 50 41 53 53 21`).

Install flow: `DllMain(DLL_PROCESS_ATTACH)` → `CreateThread(initThread)` → `Sleep(500)` →
`installAll()` → `validarDosArgs()`.

- **`installAll()`**: inline-hook login at `base+LOGIN_RVA` (14-byte `FF 25` abs `jmp` to
  `hkConnect`, orphan bytes `NOP`; trampoline = copied prologue + `jmp back`); full-replace
  `base+CMP_RVA` with `hkCompare` (14-byte `jmp`, no trampoline).
- **`hkConnect(this, FString* login /*rdx*/, FString* pass /*r8*/)`**: `FString = {wchar_t* Data@0,
  int32 Num@8, int32 Max@12}` UTF-16LE; string length `Num-1`. Reads both, calls `validar()`;
  allow → call original trampoline `oLogin`; deny → `MessageBoxW` + return (blocks).
- **`validar(login,pass)`**: TCP to `127.0.0.1:27110`, send `"AUTH\t"+utf8(login)+"\t"+utf8(pass)+"\n"`,
  read reply; prefix `OK`→allow, `FAIL`→deny. **Fail-open** (default `allow=true` if socket/validator
  fails). 3 s send/recv timeouts.
- **`hkCompare(a1 rcx, a2 rdx, len r8) -> __int64`**: returns `0` (equal) if `len==32` and
  (`a1==MAGIC` or `a2==MAGIC`); else real byte compare (`0` equal, `1` differ). `IsBadReadPtr`
  guarded.
- **`validarDosArgs()`**: parses `-ID <login> -PWD <pass>` from `GetCommandLineW()`; if both
  present, calls `validar()` at install time → populates server-side bridge without racing the
  client auto-login. If absent, relies on the live `hkConnect` hook (user types in UI).
- Logging: appends to `lu4authhook.log` next to the DLL.

## 5. Launcher internals
- Config `lu4launcher.ini` (flat `key=value`; keys: `GameExe HookDll GameArgs Login Pass LocalDev
  LoginIp LoginPort AuthPort`). Defaults: GameExe `lu4\binaries\win64\lu4-win64-shipping.exe`,
  HookDll `lu4authhook.dll`, GameArgs `LU4 -USEALLAVAILABLECORES`, LocalDev `1`,
  LoginIp `185.29.255.102`, LoginPort `2108`, AuthPort `2107`.
- Launch: if `LocalDev` and admin → `setupNetwork()` (3 `netsh` cmds: add loopback alias
  `LoginIp/255.255.255.255`; portproxy `0.0.0.0:LoginPort→127.0.0.1:AuthPort`; portproxy
  `LoginIp:LoginPort→127.0.0.1:AuthPort`). Then `CreateProcessA` with
  `"<GameExe>" <GameArgs> -ID <login> -PWD <pass>`, cwd = exe dir; `Sleep(1200)`; `injectDll` via
  remote `LoadLibraryW`.
- GUI: accounts in `lu4accounts.dat` (lines `login\t<xorhex(pass)>`), XOR key
  `"Lu4-Liberta-Ultimata-Key-2026"` then hex — **obfuscation, not encryption**. `MAX_ACC 64`.
- `Inject-LU4.ps1` selects the game process: `lu4-win64-shipping.exe` whose CommandLine lacks
  `--type=` (CEF children have it), tie-break by largest `WorkingSet64`.

## 6. Server-side contract (NOT in this repo)
A compatible emulator must provide:
1. **Validator** TCP `127.0.0.1:27110`: in `AUTH\t<login>\t<password>\n` → out `OK`/`FAIL` (prefix).
2. **AuthServer ServerList**: emit the 32-byte `MAGIC` where the real per-packet MAC goes, so
   Hook 2 accepts a dynamic list. (Reference implementation is an L2J/Lucera-style Java server:
   classes like `Lu4AuthValidator` (port 27110), `Lu4AuthBridge`, `Lu4ServerList`; not shipped here.)

## 7. Build (Windows x64, VS2022)
```
src\build_hook.bat        # cl /LD /O2 /EHsc /std:c++17 lu4authhook.cpp /Fe:lu4authhook.dll  (+ ws2_32 user32)
cl /nologo /O2 /EHsc src\inject.cpp /Fe:inject.exe
src\build_launcher.bat    # builds lu4launcher.exe (user32 advapi32 shell32) and
                          #        lu4launcher_gui.exe (+ gdi32 comctl32)
```
`build_*.bat` call a hardcoded `vcvars64.bat` path (VS2022 Community) — adjust per machine.

## 8. Rebasing to a new client build
RVAs are specific to one `lu4-win64-shipping.exe`. If it changes:
- Re-find login by prologue bytes `48 89 5C 24 08 57 48 83 EC 20 83 7A 08 01`; set `LOGIN_RVA`
  (and `LOGIN_COPY` if the copied prologue length changes).
- Re-find the small constant-time compare; set `CMP_RVA`.
- Rebuild. Verify via `lu4authhook.log` (`[hook] base=...`, `[login] ...`, `[serverlist] MAC MAGIC aceito #n`).

## 9. Known caveats
- Fail-open login (dead validator ⇒ login allowed). Change in `validar()` for fail-closed.
- Password is plaintext client→validator; fine on loopback, needs TLS for a remote validator.
- DLL injection / modded client can trigger anti-cheat on protected builds; intended for an
  unprotected dev/test client only.
- `LocalDev=1` network setup needs Administrator (uses `netsh`).
