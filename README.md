# LU4 Login / ServerList DLL + Launcher

**Languages:** **English** · [Português](README.pt-BR.md) · [LLM / agent reference](README.llm.md)

> **Branch `Cliente-18-10-2026`:** for the `lu4.bin` client, which logs in with the DLL-free
> loader (see [DLL-free loader](#dll-free-loader-lu4loader-client-of-18-10-2026)). This branch no
> longer ships `lu4authhook.dll`, `inject.exe` or `Inject-LU4.ps1`; the hook and injection
> sections below describe the `main` branch, where they still are. `lu4launcher` needs the DLL
> and only works with the files from `main`.

Client-side tooling that lets the **LU4** game client (a *Lineage 2*–based title on Unreal
Engine 5.4) log in to a **private / emulator server** instead of the official auth servers.

It ships two things:

1. **`lu4authhook.dll`** — a DLL injected into the game process that
   - **validates login/password against your own server** by reading the credentials in
     plaintext from the UI (before they are encrypted), and
   - **bypasses the ServerList MAC check** so your AuthServer can send a dynamic server list.
2. **A launcher** (GUI + console) that creates/stores accounts, starts the client and injects
   the hook in one click.

> ⚠️ **Scope & disclaimer.** This is **interoperability / server-emulation tooling for
> private servers you own and operate**, in the spirit of the long-standing L2 free-shard
> community. It is **not** an anti-cheat bypass and does **not** defeat game-integrity
> protection — it only touches the login handshake and the server-list signature. Use it
> **only** with your own servers and your own client install, for learning, preservation and
> development. Do **not** use it against official/commercial servers or to violate anyone's
> Terms of Service or local law. You are responsible for how you use it.

---

## Why this exists

The LU4 client encrypts the login packet with a static Blowfish key that is **virtualized by
VMProtect** — it cannot be extracted, so an emulator cannot verify passwords the "normal" way
(the login handshake ends up being a packet replay that accepts any password). On top of that,
every ServerList packet from the auth server carries a **32-byte MAC** signed with a secret the
emulator doesn't have, so a home-made server list is rejected.

This project solves both **on the client side**, surgically:

| Problem | Solution in `lu4authhook.dll` |
|---|---|
| Can't verify the password server-side | Capture login/password **in the UI** and ask your server `OK/FAIL` |
| ServerList MAC can't be forged | Replace the compare so a known **MAGIC** value counts as a valid MAC |

Blast radius is tiny: only the login call and the 32-byte server-list compare are touched; every
other comparison in the client runs byte-for-byte as before.

---

## How it works

### Hook 1 — login capture & validation
- **Hook point:** `ConnectToLoginServer` at RVA `0x4BB1850`,
  signature `void __fastcall(this, FString* login /*rdx*/, FString* password /*r8*/)`.
  An `FString` is `{ TCHAR* Data; int32 Num; int32 Max }` in UTF-16LE.
- The hook reads the two strings, then opens a TCP socket to the **validator** and sends:
  ```
  AUTH\t<login>\t<password>\n
  ```
  and expects `OK` (allow) or `FAIL` (deny). On allow it calls the original function (login
  proceeds for that account); on deny it shows *"Login ou senha incorretos."* and blocks.
- **Fail-open:** if the validator is unreachable, the hook **allows** the login (so the client
  never hangs on a dead validator). Flip the default in `validar()` for fail-closed.
- To avoid a race with the launcher's auto-login (the client can auto-log *before* the hook is
  installed), the DLL also reads `-ID`/`-PWD` from its own command line at install time and
  validates from there.

### Hook 2 — ServerList MAC bypass
- **Hook point:** a constant-time compare at RVA `0xBFEEA0`,
  `__int64 __fastcall(buf1 rcx, buf2 rdx, len r8)` → `0` when equal.
- It is fully replaced by a version that does the **same** byte compare, except: when
  `len == 32` and one buffer equals the MAGIC
  `LU4-MAGIC-SERVERLIST-MAC-BYPASS!`, it returns `0` (equal). Your AuthServer puts that MAGIC
  where the real 32-byte MAC would go, and the client accepts your dynamic server list.

### Launcher
- **`lu4launcher_gui.exe`** — dark-themed Win32 window: pick/save/remove accounts, hit **JOGAR**.
  Accounts are stored in `lu4accounts.dat` next to the exe (password XOR-obfuscated — light
  obfuscation, **not** security).
- **`lu4launcher.exe`** — console version (prompts for login/password, or reads them from args/ini).
- On launch both: (optionally, local-dev) set up the loopback + portproxy, start the client with
  `LU4 -USEALLAVAILABLECORES -ID <login> -PWD <password>`, wait ~1.2 s, then inject
  `lu4authhook.dll` via a remote `LoadLibraryW`.

### DLL-free loader (`lu4loader`, client of 18-10-2026)
For the **`lu4.bin`** client build. Nothing is injected, and the official launcher (with the
`clmods64` module it loads) is not used.
- **`lu4loader_gui.exe`** — window with saved accounts (`lu4loader_accounts.dat`, password
  XOR-obfuscated, **not** security). **`lu4loader.exe`** — console version.
- What it does: takes login/password (`--id`/`--pwd`, `lu4loader.ini`, or asks); in local dev sets up
  the loopback + portproxy; starts `lu4.bin` directly with `LU4 -USEALLAVAILABLECORES` (plus
  `-ID`/`-PWD` when `AutoFillLogin=1`); waits until the client has loaded (working set above
  `WaitMB`); redirects the 32-byte serverlist compare to a small code cave that accepts the server's
  MAC marker; sends `AUTH	<login>	<password>
` to the server's credential validator
  (port 27110) and keeps refreshing it while the window is open.
- **Needs a matching server.** The server must send the 37-byte Init for `lu4.bin`, which makes the
  client install the session Blowfish key the server expects (AuthGateD `kInitHex` in
  [Open_LU4_L2OFF, branch `Cliente-18-10-2026`](https://github.com/luannbr/Open_LU4_L2OFF/tree/Cliente-18-10-2026),
  `AuthGateD/src/Lu4Login.cpp`). Without it the login decrypts to garbage, loader or not. The
  server also needs AuthD `Lu4Mode=true` with the validator on 27110 (credentials reusable within
  their TTL, so the client can log in again without restarting) and its LU4 login port (2107)
  reachable from `LoginIp:LoginPort`.
- Config: copy `dist/lu4loader.ini.example` to `lu4loader.ini` next to the exe. Never commit it.
- Build: `src/build_lu4loader.bat` (both versions).
- Status: login verified end to end with the Python prototype of this loader; the C version is a
  port of it with the same patch bytes and validator message.

---

## Requirements

- **Windows x64.**
- A matching **LU4 client build** — the RVAs above are specific to one
  `lu4-win64-shipping.exe` build (see [RVAs](#rvas-are-build-specific)).
- **Your server side** must implement the contract below (this repo is client-side only).
- To **build from source:** Visual Studio 2022 (C/C++, x64 — `vcvars64.bat`).
- **Admin** is only needed for the local-dev network setup (`LocalDev=1`).

---

## Server-side contract (what your emulator must provide)

This repo does **not** contain the server. Any compatible auth/game emulator (e.g. an
L2J/Lucera-style server) must provide:

1. **A validator** listening on `127.0.0.1:27110` (configurable) that speaks the line protocol:
   - receives `AUTH\t<login>\t<password>\n`
   - replies `OK` (or `OK ...`) to allow, `FAIL` (or `FAIL ...`) to deny.
   - (Typical impl: whirlpool2 hash compared against the `accounts` table, auto-create optional.)
2. **An AuthServer server list** that writes the 32-byte MAGIC
   `LU4-MAGIC-SERVERLIST-MAC-BYPASS!` in place of the real per-packet MAC. The DLL's Hook 2 then
   accepts it, so you can serve a dynamic list of **your** servers with real names.

---

## Install & use (end user)

1. Put `lu4launcher_gui.exe` (and `lu4launcher.exe`), `lu4authhook.dll`, `inject.exe` and
   `Inject-LU4.ps1` from **`dist/`** into your client folder (next to the `lu4\` directory).
2. Copy `lu4launcher.ini.example` to `lu4launcher.ini` and edit it (server IP/ports, or just the
   defaults for local dev). **Never commit your real `lu4launcher.ini`.**
3. Make sure your **server + validator** are running.
4. Run `lu4launcher_gui.exe`, add an account, and click **JOGAR**.
   - For `LocalDev=1`, run the launcher **as Administrator** the first time (it adds the loopback
     alias + portproxy with `netsh`).

### Manual injection (without the launcher)
Start the client, stay on the login screen, then:
```powershell
powershell -ExecutionPolicy Bypass -File dist\Inject-LU4.ps1
```
`Inject-LU4.ps1` finds the **game** process (`lu4-win64-shipping.exe` without `--type=`, largest
working set — i.e. not the CEF UI children) and runs `inject.exe <pid> lu4authhook.dll`.

---

## Configuration (`lu4launcher.ini`)

| Key | Default | Meaning |
|---|---|---|
| `GameExe` | `lu4\binaries\win64\lu4-win64-shipping.exe` | client executable (relative or absolute) |
| `HookDll` | `lu4authhook.dll` | hook DLL path |
| `GameArgs` | `LU4 -USEALLAVAILABLECORES` | args passed to the client |
| `Login` / `Pass` | *(empty)* | optional; if set, console launcher won't prompt (**don't commit**) |
| `LocalDev` | `1` | `1` = set up loopback+portproxy (needs Admin); `0` = connect straight to a real IP |
| `LoginIp` | `185.29.255.102` | IP the client connects to (a loopback alias in dev) |
| `LoginPort` | `2108` | client port |
| `AuthPort` | `2107` | your AuthServer port (portproxy target in dev) |

---

## Build from source

```bat
:: hook DLL (x64)
src\build_hook.bat
:: or directly:
cl /nologo /LD /O2 /EHsc /std:c++17 src\lu4authhook.cpp /Fe:lu4authhook.dll ^
   /link ws2_32.lib user32.lib

:: injector
cl /nologo /O2 /EHsc src\inject.cpp /Fe:inject.exe

:: launcher (console + GUI)
src\build_launcher.bat
```
The `build_*.bat` files call `vcvars64.bat` from a default VS2022 path — adjust it to your install.

---

## RVAs are build-specific

The offsets are tied to **one** `lu4-win64-shipping.exe` build. If the client updates, re-locate
them before using the DLL:

- **Login** `0x4BB1850` — expected prologue:
  `48 89 5C 24 08 57 48 83 EC 20 83 7A 08 01`
- **ServerList compare** `0xBFEEA0` — a small, self-contained constant-time `memcmp`-style
  function.

Edit `LOGIN_RVA` / `CMP_RVA` in `src/lu4authhook.cpp` and rebuild.

---

## Files

```
dist/
  lu4launcher_gui.exe     GUI launcher (accounts, one-click play)
  lu4launcher.exe         console launcher
  lu4launcher.ini.example config template (copy to lu4launcher.ini)
  lu4loader_gui.exe       DLL-free loader for lu4.bin, GUI (client of 18-10-2026)
  lu4loader.exe           DLL-free loader, console
  lu4loader.ini.example   loader config template (copy to lu4loader.ini)
src/
  lu4launcher.c           console launcher source
  lu4launcher_gui.c       GUI launcher source
  build_launcher.bat      builds both launchers
  lu4loader.c             DLL-free loader source, console
  lu4loader_gui.c         DLL-free loader source, GUI
  build_lu4loader.bat     builds both loader versions
```

## Security notes

- The password is read in plaintext in the client and sent to the validator. On the same machine
  it stays on `127.0.0.1`. For a **remote** server the validator would listen on a public IP and
  the password would travel in clear — add TLS before doing that.
- `lu4accounts.dat` uses trivial XOR obfuscation, not encryption. Treat it as plaintext.
- Injecting a DLL and running a modded client can trip anti-cheat on protected builds. Only use
  this on an unprotected development/test client.

## License

No license is set yet — until one is added, default copyright (all rights reserved) applies.
Add a `LICENSE` file (e.g. MIT) if you want others to reuse it freely.
