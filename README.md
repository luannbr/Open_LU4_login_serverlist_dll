# LU4 Loader — DLL-free login (client of 18-10-2026)

**Languages:** **English** · [Português](README.pt-BR.md) · [LLM / agent reference](README.llm.md)

> **Branch `Cliente-18-10-2026`.** This branch holds only **`lu4loader`**, the DLL-free loader for
> the **`lu4.bin`** client. The previous system for `lu4-win64-shipping.exe` (`lu4authhook.dll`, the
> injector and `lu4launcher`) is on the
> [`main`](https://github.com/luannbr/Open_LU4_login_serverlist_dll/tree/main) branch.

Client-side tooling that lets the **LU4** game client (a *Lineage 2*–based title on Unreal
Engine 5.4) log in to a **private / emulator server** instead of the official auth servers —
**without injecting any DLL** into the game.

It ships one tool in two versions:

1. **`lu4loader_gui.exe`** — a window with saved accounts: pick an account and click **JOGAR**.
2. **`lu4loader.exe`** — the same loader as a console program (args, ini or prompt).

Both start the client, apply one small patch from outside the process (the ServerList signature
check) and hand the account to your server's credential validator.

> ⚠️ **Scope & disclaimer.** This is **interoperability / server-emulation tooling for private
> servers you own and operate**, in the spirit of the long-standing L2 free-shard community. Use
> it **only** with your own servers and your own client install, for learning, preservation and
> development. Do **not** use it against official/commercial servers or to violate anyone's Terms
> of Service or local law. You are responsible for how you use it.

---

## Why this exists

Two things stop the LU4 client from logging in to an emulator:

- Every reply from the auth server carries a **32-byte Ed25519 signature** made with the official
  server's private key. An emulator cannot produce it, so a home-made server list is rejected.
- The login packet is encrypted with a **session Blowfish key** the client takes from the server's
  Init packet, and the account block inside it cannot be read by the server.

The `main` branch solved this with a DLL injected into `lu4-win64-shipping.exe`. The `lu4.bin`
client of 18-10-2026 is handled without any DLL:

| Problem | Solution |
|---|---|
| ServerList signature can't be forged | The loader points the 32-byte compare to a code cave that accepts a known **MAGIC** marker |
| The server can't read the account from the login packet | The loader sends login/password to your server's validator itself |
| Session Blowfish key | Server side: a 37-byte Init that makes `lu4.bin` install the key the server expects |

The patch touches only the 32-byte compare; every other comparison in the client runs byte for
byte as before.

---

## How it works

### 1. Start the client
- Login/password come from `--id`/`--pwd`, else from `lu4loader.ini`, else the loader asks (the
  GUI uses its saved accounts). They are required: the server needs them from the loader.
- With `LocalDev=1` (and Admin) it sets up the local network with `netsh`: loopback alias
  `LoginIp/255.255.255.255`, portproxy `0.0.0.0:LoginPort → 127.0.0.1:AuthPort` and
  `LoginIp:LoginPort → 127.0.0.1:AuthPort`.
- Starts `lu4.bin` **directly** (not through the official launcher, which also loads the
  `clmods64` module) with `GameArgs` (`LU4 -USEALLAVAILABLECORES`), plus `-ID <login> -PWD
  <password>` when `AutoFillLogin=1` so the client fills its login form.

### 2. ServerList signature gate (late patch)
- Waits until the client has loaded (working set above `WaitMB`, default 1500 MB, up to 2 min),
  then resolves the module base.
- The compare at RVA **`0xBFEEA0`** (`__int64 __fastcall(buf1 rcx, buf2 rdx, len r8)`, `0` when
  equal) only becomes readable after the protector decrypts its page. The loader waits until its
  prologue is `48 31 C0 4D 31 D2`, then:
  - allocates a 63-byte code cave in the client (`VirtualAllocEx`, RWX);
  - writes a 14-byte `jmp [rip+0]` at the compare pointing to the cave.
- The cave returns *equal* when `len == 32` and one buffer starts with `LU4-MAGI` (the marker
  `LU4-MAGIC-SERVERLIST-MAC-BYPASS!` your server writes instead of the signature); otherwise it
  compares byte by byte (`0` equal, `1` differ), exactly like the original.
- While the client runs, the loader re-applies the `jmp` if the original prologue comes back.

### 3. Credential bridge
- Right after the patch it opens a TCP connection to the validator (`ValidatorHost:ValidatorPort`,
  default `127.0.0.1:27110`) and sends:
  ```
  AUTH\t<login>\t<password>\n
  ```
  A reply starting with `OK` means accepted; anything else is shown as rejected.
- The server keeps that pair for the client's IP and uses it when the login arrives. The loader
  sends it again every 2 minutes while its window is open, so the pair never expires.
- Keep the loader window open during the login.

### 4. DisconnectGuard — idle-drop fix (optional, `DisconnectGuard=1`)
- **Symptom:** after a few minutes standing still (even on localhost, with a healthy server), the
  `lu4.bin` client **drops its own connection**. It isn't the server — the packet ring stays clean
  and the ping is answered to the very end. It's an internal routine (a watchdog) in this client
  build that calls its own `Disconnect`.
- **That same watchdog is also the path for real drops:** when the server dies/resets, the tick
  notices the dead socket and calls the SAME `Disconnect`. So filtering by call-site alone would
  also kill "server offline / reconnect". The decision must be by **liveness**.
- With `DisconnectGuard=1`, on world entry the loader installs — from outside, no DLL and no remote
  thread — a **liveness-aware** filter on `Disconnect` (`base+0x4ce8c60`):
  - it redirects the prologue to a trampoline (via `VirtualAllocEx`) that reads an "alive" flag in
    the cave itself;
  - it swallows the disconnect only when the call comes from the watchdog call-site
    (`base+0x915b3f3`), with `notify!=0`, **and the "alive" flag is 1** (connection live). Any other
    caller (relog/logout), or the flag at 0, passes through;
  - the **loader maintains the flag** from its TCP-table poll: it's 1 while the game connection is
    established and it clears it the moment the connection drops — then the next disconnect goes
    through and the client shows "disconnected". During healthy play it keeps **no open handle**: it
    only reopens for one byte when the connection drops.
- **Safety:** before touching anything it checks a build fingerprint (getter `base+0x4d01a90`) and
  the expected `Disconnect` prologue; on a different build it **does not install** and logs why
  (nothing is corrupted). The RVAs are specific to this `lu4.bin`.
- **Limitation:** covers server offline / reset / FIN (the TCP state changes). A silent freeze with
  no FIN keeps the TCP established and only drops via the OS keepalive. Result in `lu4loader.log`
  (`DISCONNECT_GUARD ... result=1`, `GUARD: connection dropped -> alive=0`) and the GUI status.
  Byte-level details in `src/lu4_disconnect_guard.h`. Liveness-aware improvements by **Maxicroma**.

---

## Requirements

- **Windows x64.**
- The **`lu4.bin`** client build of 18-10-2026 — the RVA is specific to it (see
  [RVAs](#rvas-are-build-specific)).
- **A server that implements the contract below** — this repo is client-side only.
- To **build from source:** Visual Studio 2022 (C, x64 — `vcvars64.bat`).
- **Admin** is only needed for the local-dev network setup (`LocalDev=1`).

---

## Server-side contract (what your emulator must provide)

This repo does **not** contain the server. The reference server is
[Open_LU4_L2OFF, branch `Cliente-18-10-2026`](https://github.com/luannbr/Open_LU4_L2OFF/tree/Cliente-18-10-2026).
Any server used with this loader must provide:

1. **The 37-byte Init for `lu4.bin`** (in Open_LU4_L2OFF: `kInitHex` in
   `AuthGateD/src/Lu4Login.cpp`). `lu4.bin` reads the session Blowfish key at bytes 21..36 of that
   message; the server must then decrypt with the same key. **Without it the login decrypts to
   garbage, with or without the loader.**
2. **A ServerList with the MAGIC marker** — the 32 bytes `LU4-MAGIC-SERVERLIST-MAC-BYPASS!` where
   the real signature goes, so the patched compare accepts your list.
3. **A credential validator** on TCP `27110` (configurable) that speaks the line protocol:
   - receives `AUTH\t<login>\t<password>\n`;
   - replies `OK` (or `OK ...`) to accept, anything else to reject;
   - keeps the accepted pair for the sender's IP and hands it to the login from that IP. In
     Open_LU4_L2OFF this is AuthD with `Lu4Mode=true`; the pair stays valid for its whole TTL, so
     the client can log in again without restarting.
4. **The LU4 login port** (AuthGateD `lu4Port`, default `2107`) reachable from
   `LoginIp:LoginPort` — through the portproxy in local dev, or directly in production.

---

## Install & use (end user)

1. Put `lu4loader_gui.exe` (and/or `lu4loader.exe`) from **`dist/`** into your client folder (next
   to the `lu4\` directory).
2. Copy `lu4loader.ini.example` to `lu4loader.ini` and edit it (server IP/ports, or just the
   defaults for local dev). **Never commit your real `lu4loader.ini`.**
3. Make sure your **server + validator** are running.
4. Run `lu4loader_gui.exe`, add an account, and click **JOGAR**.
   - For `LocalDev=1`, run the loader **as Administrator** (it adds the loopback alias +
     portproxy with `netsh`).
   - Console instead: `lu4loader.exe` or `lu4loader.exe --id <login> --pwd <password>`.
5. Keep the loader window open until you are in the game.

---

## Configuration (`lu4loader.ini`)

| Key | Default | Meaning |
|---|---|---|
| `GameExe` | `lu4\binaries\win64\lu4.bin` | client executable (relative to the loader, or absolute) |
| `GameArgs` | `LU4 -USEALLAVAILABLECORES` | args passed to the client |
| `Login` / `Pass` | *(empty)* | optional; if set, the console loader won't prompt (**don't commit**) |
| `AutoFillLogin` | `1` | `1` = pass `-ID`/`-PWD` so the client fills its login form; `0` = type it in the game |
| `LocalDev` | `1` | `1` = set up loopback+portproxy (needs Admin); `0` = connect straight to a real IP |
| `LoginIp` | `185.29.255.102` | IP the client connects to (a loopback alias in dev) |
| `LoginPort` | `2108` | client port |
| `AuthPort` | `2107` | your AuthGateD LU4 port (portproxy target in dev) |
| `ValidatorHost` | `127.0.0.1` | credential validator host |
| `ValidatorPort` | `27110` | credential validator port |
| `GamePort` | `7778` | GameServer port; an established TCP connection to it means "in-world" |
| `DisconnectGuard` | `0` | `1` = install the idle-drop filter on world entry (see section 4) |
| `WaitMB` | `1500` | client working set (MB) to wait for before patching |

The GUI stores its accounts in `lu4loader_accounts.dat` next to the exe (one `login<TAB>password`
line each, password XOR-obfuscated — **not** security).

---

## Build from source

```bat
:: console + GUI
src\build_lu4loader.bat
:: or directly:
cl /nologo /O2 /W3 /D_CRT_SECURE_NO_WARNINGS src\lu4loader.c /Fe:lu4loader.exe ^
   /link user32.lib advapi32.lib shell32.lib psapi.lib ws2_32.lib iphlpapi.lib
cl /nologo /O2 /W3 /D_CRT_SECURE_NO_WARNINGS src\lu4loader_gui.c /Fe:lu4loader_gui.exe ^
   /link user32.lib gdi32.lib advapi32.lib shell32.lib comctl32.lib psapi.lib ws2_32.lib iphlpapi.lib
```
`build_lu4loader.bat` calls `vcvars64.bat` from a default VS2022 path — adjust it to your install.
The GUI's Common Controls manifest is embedded with a `#pragma`, so no `.manifest` file is needed.

---

## RVAs are build-specific

The offset is tied to **one** `lu4.bin` build. If the client updates, re-locate it before using
the loader:

- **ServerList compare** `0xBFEEA0` — a small, self-contained constant-time `memcmp`-style
  function; expected prologue once decrypted: `48 31 C0 4D 31 D2` (`xor rax,rax; xor r10,r10`).
- **DisconnectGuard** (`src/lu4_disconnect_guard.h`): `Disconnect` `0x4CE8C60`, watchdog call-site
  `0x915B3F3`, build fingerprint getter `0x4D01A90`. All verified at runtime before patching — a
  mismatch just aborts the install (returns a negative code, logged), it never corrupts the client.

Edit `CMP_RVA` (and `ORIG` if the prologue changes) in **both** `src/lu4loader.c` and
`src/lu4loader_gui.c`, then rebuild. The DisconnectGuard offsets live in
`src/lu4_disconnect_guard.h`.

---

## Status

The login was verified end to end with the Python prototype of this loader. The C versions are a
port of it with the same patch bytes and the same validator message.

---

## Files

```
dist/
  lu4loader_gui.exe       GUI loader (accounts, one-click play)
  lu4loader.exe           console loader
  lu4loader.ini.example   config template (copy to lu4loader.ini)
src/
  lu4loader.c             console loader source
  lu4loader_gui.c         GUI loader source
  lu4_disconnect_guard.h  idle-drop filter (DisconnectGuard; included by both)
  build_lu4loader.bat     builds both
```

## Security notes

- The password is sent to the validator in plaintext. On the same machine it stays on
  `127.0.0.1`. For a **remote** server the validator would listen on a public IP and the password
  would travel in clear — add TLS before doing that.
- `-ID`/`-PWD` put the password on the client's command line, visible to other local processes.
  Use `AutoFillLogin=0` if that matters.
- `lu4loader_accounts.dat` uses trivial XOR obfuscation, not encryption. Treat it as plaintext.
- Never commit `lu4loader.ini` or `lu4loader_accounts.dat` (both are in `.gitignore`).
- Patching a client's memory can trip anti-cheat on protected setups. Use this only with your own
  client and your own server.

## License

See [LICENSE](LICENSE).
