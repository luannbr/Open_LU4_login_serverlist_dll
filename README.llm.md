# LU4 Loader (DLL-free login) — LLM / agent reference

Dense, factual reference for an AI agent working on this repo. Human-readable docs:
[English](README.md) · [Português](README.pt-BR.md).

Branch `Cliente-18-10-2026`: only `lu4loader` (for `lu4.bin`). `lu4authhook.dll`, `inject.exe`,
`Inject-LU4.ps1` and `lu4launcher` (for `lu4-win64-shipping.exe`) live on `main`.

## 1. One-line purpose
Console + GUI loader that lets the **LU4** game client `lu4.bin` (build of 18-10-2026, Lineage
2–based, Unreal Engine 5.4, Windows x64, VMProtect) log in to a **private/emulator** server
without any injected DLL, by (a) late-patching the ServerList 32-byte signature compare from
outside the process and (b) feeding login/password to the server's TCP credential validator.

## 2. Guardrails (do not drift)
- This is **private-server interoperability / emulation** tooling for the user's own client and
  server. Do not add kernel-mode code, anti-cheat evasion, memory-scan hiding, or anything
  targeting official/commercial servers.
- Only one code site in the client is modified (the 32-byte compare at `CMP_RVA`). Keep the blast
  radius minimal; non-MAGIC compares must behave exactly like the original.
- Never commit secrets: real `lu4loader.ini` (may hold `Login`/`Pass`), `lu4loader_accounts.dat`,
  `*.log` (also `lu4launcher.ini`, `lu4accounts.dat` from `main`). They are in `.gitignore`.

## 3. Components
| Binary | Source | Role |
|---|---|---|
| `lu4loader.exe` | `src/lu4loader.c` | console loader: args/ini/prompt credentials, network setup, launch, cave patch, validator bridge |
| `lu4loader_gui.exe` | `src/lu4loader_gui.c` | same flow in a Win32 GUI (multi-account, dark theme), work in a thread |
| `lu4loader.ini.example` | — | config template |
| — | `src/build_lu4loader.bat` | builds both |

## 4. Loader internals (`lu4loader.c`; GUI is the same logic)
Constants (build-specific; `base` = first module of the client process via `EnumProcessModules`):
- `CMP_RVA = 0xBFEEA0`.
- `ORIG[6] = 48 31 C0 4D 31 D2` (`xor rax,rax; xor r10,r10`) — prologue once VMProtect has
  decrypted the page; patching only happens when it matches.
- `CAVE[63]` (position-independent): `if (r8 == 32 && (*(u64*)rdx == 'LU4-MAGI' || *(u64*)rcx ==
  'LU4-MAGI')) return 0;` else byte loop: `0` equal, `1` differ (also `0` when `r8 == 0`).
- MAGIC (server side, 32 bytes, ASCII, no NUL): `LU4-MAGIC-SERVERLIST-MAC-BYPASS!`; the cave only
  checks the first 8 bytes `4C 55 34 2D 4D 41 47 49`.
- Defaults: `GameExe lu4\binaries\win64\lu4.bin`, `GameArgs LU4 -USEALLAVAILABLECORES`,
  `LoginIp 185.29.255.102`, `LoginPort 2108`, `AuthPort 2107`, `ValidatorHost 127.0.0.1`,
  `ValidatorPort 27110`, `LocalDev 1`, `AutoFillLogin 1`, `WaitMB 1500`.

Flow (`main`):
1. `loadConfig()` from `lu4loader.ini` next to the exe (flat `key=value`, `#`/`;` comments, paths
   relative to the exe dir unless absolute).
2. Credentials: `--id`/`--pwd` args → ini `Login`/`Pass` → prompt (password masked). Both are
   required (abort if empty): the server cannot decrypt the client's credential block.
3. `LocalDev` and elevated → `setupNetwork()`: `netsh` add loopback alias
   `LoginIp/255.255.255.255`; portproxy `0.0.0.0:LoginPort→127.0.0.1:AuthPort`; portproxy
   `LoginIp:LoginPort→127.0.0.1:AuthPort`. Not elevated → warning, skipped.
4. `CreateProcessA("<GameExe>" <GameArgs> [-ID <login> -PWD <pass>])`, cwd = client exe dir. The
   official launcher (`lu4.exe`, which loads `clmods64.dll`) is not used.
5. Wait up to 120 s for working set ≥ `WaitMB` (late patch: writing `.text` early trips the
   VMProtect integrity check; `0xBFEEA0` is not covered by it, `0x600b020` is).
6. Loop every 300 ms until the client exits:
   - not installed → `patchCave()`: read 6 bytes at `base+CMP_RVA`, require `ORIG`;
     `VirtualAllocEx(0x400, RWX)`; write `CAVE`; `VirtualProtectEx` + write 14-byte
     `FF 25 00 00 00 00 <cave u64>`; then `sendBridge()`.
   - installed → `reapplyJmp()` if the first 2 bytes are `ORIG` again; `sendBridge()` every 120 s.
7. `sendBridge(host, port, login, pass)`: TCP connect, send `"AUTH\t<login>\t<pass>\n"`, read one
   reply; prefix `OK` → accepted, else rejected (logged). No retry on connect failure beyond the
   120 s refresh.

GUI specifics (`lu4loader_gui.c`):
- Accounts in `lu4loader_accounts.dat` (lines `login\t<xorhex(pass)>`), XOR key
  `"Lu4-Liberta-Ultimata-Key-2026"` then hex — **obfuscation, not encryption**. `MAX_ACC 64`.
- Common Controls v6 manifest embedded via `#pragma comment(linker, "/manifestdependency:...")`.

## 5. Server-side contract (NOT in this repo)
Reference: Open_LU4_L2OFF, branch `Cliente-18-10-2026`
(https://github.com/luannbr/Open_LU4_L2OFF/tree/Cliente-18-10-2026).
1. **Init for `lu4.bin`**: 37-byte message (layout relative to the opcode: `[0]` op `00`,
   `[1..16]` prefix, `[17..20]` session id echoed in login bytes `1..4`, `[21..36]` session
   Blowfish key). L2OFF: `kInitHex` in `AuthGateD/src/Lu4Login.cpp`; key `BC AF 64 50 71 3E 25 CF
   E1 72 C2 F4 BE BE 39 B2` (standard Blowfish, BE key read, LE block load, ECB) = the expanded
   table in `AuthGateD/etc/lu4_auth_key.bin`. Without this Init the login decrypts to garbage
   (opcode 255) regardless of the loader.
2. **ServerList**: the 32-byte MAGIC where the Ed25519 signature goes (the real signature uses the
   official server's private key; public key `8a65264f…c3b1b5` is pinned in the client).
3. **Validator** TCP `27110`: in `AUTH\t<login>\t<password>\n` → out `OK`/`FAIL` (prefix). Keeps the
   pair per source IP; AuthGateD forwards the login with a `\x7fLU4` marker and AuthD swaps in the
   stored pair. L2OFF: AuthD `Lu4Mode=true`, `Lu4ValidatorPort=27110`, `Lu4Validator.cpp`
   `TakeCredentials` keeps the pair for its whole TTL (re-login without restarting the client).
4. **LU4 login port**: AuthGateD `lu4Port` (default 2107) reachable from `LoginIp:LoginPort`.
   (AuthGateD `serverPort`, e.g. 2206, is the non-LU4 listener; the game port, e.g. 7778, is
   post-login and not touched by the loader.)

## 6. Build (Windows x64, VS2022)
```
src\build_lu4loader.bat
# cl /nologo /O2 /W3 /D_CRT_SECURE_NO_WARNINGS lu4loader.c     /Fe:lu4loader.exe     (+ user32 advapi32 shell32 psapi ws2_32)
# cl /nologo /O2 /W3 /D_CRT_SECURE_NO_WARNINGS lu4loader_gui.c /Fe:lu4loader_gui.exe (+ gdi32 comctl32)
```
`build_lu4loader.bat` calls a hardcoded `vcvars64.bat` path (VS2022 Community) — adjust per
machine.

## 7. Rebasing to a new client build
`CMP_RVA` is specific to one `lu4.bin`. If it changes:
- Re-find the small constant-time compare (`__int64 __fastcall(rcx, rdx, r8)`, `0` = equal) used
  on the 32-byte ServerList signature; set `CMP_RVA` and, if needed, `ORIG` in both sources.
- Make sure the new site is outside the VMProtect integrity-checked region (patch late).
- Rebuild. Verify from the console output: `[OK] cave @ ...; compare 0xBFEEA0 redirecionado.`,
  `[bridge] validator ... -> 'OK'`.

## 8. Known caveats / status
- Verified end to end with the Python prototype (`loader_cave.py` + `lu4_cred_bridge.py`, not in
  this repo); the C loaders are a port with the same bytes and message.
- Password travels in plaintext to the validator and sits on the client's command line with
  `AutoFillLogin=1`; fine on loopback, needs TLS for a remote validator.
- Patching a client in memory can trigger anti-cheat on protected setups; intended for the
  user's own client and server.
- `LocalDev=1` network setup needs Administrator (uses `netsh`).
