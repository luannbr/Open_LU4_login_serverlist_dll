/*
 * lu4loader.c  --  Launcher do LU4 SEM DLL injetada e SEM clmods (anti-cheat).
 *
 * Porto em C do loader_cave.py. Faz tudo de FORA do cliente, num passo so':
 *   1. Pega login/senha (args --id/--pwd, senao lu4loader.ini, senao pergunta).
 *   2. (dev local) garante loopback 185.29.255.102 + portproxy 2108->2107 via netsh.
 *   3. Lanca o lu4.bin DIRETO (sem o launcher oficial -> sem clmods/AAC), com
 *      "LU4 -USEALLAVAILABLECORES" e, se AutoFillLogin=1, -ID <login> -PWD <senha>.
 *   4. Espera o cliente carregar (WorkingSet > WaitMB) -- patch TARDE, pra passar da
 *      checagem de integridade do VMProtect.
 *   5. Aplica o "cave" do MAC: aloca um code cave (VirtualAllocEx) com a logica do
 *      hkCompare e redireciona o compare 0xBFEEA0 (jmp). Aceita o marcador MAGIC que
 *      o AuthServer poe no lugar da assinatura Ed25519. (Mesmo alvo do hook, de fora.)
 *   6. Popula o bridge de credenciais do AuthD (Lu4Validator em 127.0.0.1:27110):
 *      manda "AUTH\t<login>\t<senha>\n"; o AuthD casa por IP quando o AuthGateD
 *      encaminha o login (marcador \x7fLU4). Faz o papel do hook, sem injetar nada.
 *   7. Mantem o jmp e re-popula o bridge enquanto a janela ficar aberta.
 *
 * Config opcional: lu4loader.ini ao lado do exe (ver defaults abaixo).
 *
 * Compilar:  build_lu4loader.bat
 *   cl /nologo /O2 /W3 lu4loader.c /Fe:lu4loader.exe /link user32.lib advapi32.lib shell32.lib psapi.lib ws2_32.lib
 */

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <conio.h>

/* ---- defaults (relativos ao diretorio do launcher) ---- */
static const char *DEF_GAME_REL   = "lu4\\binaries\\win64\\lu4.bin";
static const char *DEF_GAME_ARGS  = "LU4 -USEALLAVAILABLECORES";
static const char *DEF_LOGIN_IP   = "185.29.255.102"; /* IP que o cliente conecta (alias loopback no dev) */
static const char *DEF_LOGIN_PORT = "2108";           /* porta do cliente */
static const char *DEF_AUTH_PORT  = "2107";           /* porta do nosso AuthGateD (portproxy destino) */
static const char *DEF_VAL_HOST   = "127.0.0.1";      /* Lu4Validator do AuthD */
static const char *DEF_VAL_PORT   = "27110";

/* ---- o gate do MAC ---- */
#define CMP_RVA 0xBFEEA0ULL
/* prologo real do compare (so' aparece depois do VMProtect descriptografar a pagina) */
static const unsigned char ORIG[6] = { 0x48,0x31,0xC0,0x4D,0x31,0xD2 }; /* xor rax,rax; xor r10,r10 */
/* hkCompare(rcx=a1, rdx=a2, r8=len): 0 se iguais; se len==32 e um buffer comeca com
 * "LU4-MAGI" -> 0 (IGUAL); senao memcmp real. (63 bytes, PIC.) */
static const unsigned char CAVE[] = {
    0x49,0x83,0xF8,0x20,                               /* cmp r8,0x20              */
    0x75,0x14,                                         /* jne real                 */
    0x48,0xB8,0x4C,0x55,0x34,0x2D,0x4D,0x41,0x47,0x49, /* movabs rax,'LU4-MAGI'    */
    0x48,0x39,0x02,                                    /* cmp [rdx],rax            */
    0x74,0x27,                                         /* je equal                 */
    0x48,0x39,0x01,                                    /* cmp [rcx],rax            */
    0x74,0x22,                                         /* je equal                 */
    0x31,0xC0,                                         /* real: xor eax,eax        */
    0x4D,0x85,0xC0,                                    /* test r8,r8               */
    0x74,0x1A,                                         /* jz done                  */
    0x44,0x8A,0x09,                                    /* loop: mov r9b,[rcx]      */
    0x44,0x3A,0x0A,                                    /* cmp r9b,[rdx]            */
    0x75,0x0D,                                         /* jne diff                 */
    0x48,0xFF,0xC1,                                    /* inc rcx                  */
    0x48,0xFF,0xC2,                                    /* inc rdx                  */
    0x49,0xFF,0xC8,                                    /* dec r8                   */
    0x75,0xED,                                         /* jnz loop                 */
    0xEB,0x05,                                         /* jmp done                 */
    0xB8,0x01,0x00,0x00,0x00,                          /* diff: mov eax,1          */
    0xC3,                                              /* done: ret                */
    0x31,0xC0,                                         /* equal: xor eax,eax       */
    0xC3                                               /* ret                      */
};

/* ---- config efetiva ---- */
static char g_dir[MAX_PATH];
static char g_game[MAX_PATH];
static char g_gameArgs[512];
static char g_loginIp[64], g_loginPort[16], g_authPort[16];
static char g_valHost[64], g_valPort[16];
static int  g_localDev = 1;
static int  g_autoFill = 1;   /* passa -ID/-PWD pro cliente (preenche o form) */
static int  g_waitMb  = 1500; /* espera carregar (passar do init) antes de patchar */

static void launcherDir(void) {
    GetModuleFileNameA(NULL, g_dir, MAX_PATH);
    char *s = strrchr(g_dir, '\\'); if (s) *s = 0;
}
static void joinPath(char *out, const char *dir, const char *rel) {
    if (rel[0] && (rel[1] == ':' || rel[0] == '\\')) { strcpy(out, rel); return; }
    snprintf(out, MAX_PATH, "%s\\%s", dir, rel);
}
static void iniGet(const char *ini, const char *key, char *out, size_t outsz, const char *def) {
    strncpy(out, def, outsz); out[outsz-1] = 0;
    FILE *f = fopen(ini, "r"); if (!f) return;
    char line[1024]; size_t klen = strlen(key);
    while (fgets(line, sizeof(line), f)) {
        char *p = line; while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == ';') continue;
        if (_strnicmp(p, key, klen) == 0 && (p[klen]=='='||p[klen]==' '||p[klen]=='\t')) {
            char *eq = strchr(p, '=');
            if (eq) {
                char *v = eq + 1; while (*v == ' ' || *v == '\t') v++;
                char *e = v + strlen(v); while (e > v && (e[-1]=='\n'||e[-1]=='\r'||e[-1]==' '||e[-1]=='\t')) *--e = 0;
                strncpy(out, v, outsz); out[outsz-1] = 0; break;
            }
        }
    }
    fclose(f);
}
static void loadConfig(void) {
    char ini[MAX_PATH], tmp[MAX_PATH], buf[64];
    joinPath(ini, g_dir, "lu4loader.ini");
    iniGet(ini, "GameExe", tmp, sizeof(tmp), DEF_GAME_REL); joinPath(g_game, g_dir, tmp);
    iniGet(ini, "GameArgs", g_gameArgs, sizeof(g_gameArgs), DEF_GAME_ARGS);
    iniGet(ini, "LoginIp", g_loginIp, sizeof(g_loginIp), DEF_LOGIN_IP);
    iniGet(ini, "LoginPort", g_loginPort, sizeof(g_loginPort), DEF_LOGIN_PORT);
    iniGet(ini, "AuthPort", g_authPort, sizeof(g_authPort), DEF_AUTH_PORT);
    iniGet(ini, "ValidatorHost", g_valHost, sizeof(g_valHost), DEF_VAL_HOST);
    iniGet(ini, "ValidatorPort", g_valPort, sizeof(g_valPort), DEF_VAL_PORT);
    iniGet(ini, "LocalDev", buf, sizeof(buf), "1"); g_localDev = (buf[0]=='1'||buf[0]=='t'||buf[0]=='T');
    iniGet(ini, "AutoFillLogin", buf, sizeof(buf), "1"); g_autoFill = (buf[0]=='1'||buf[0]=='t'||buf[0]=='T');
    iniGet(ini, "WaitMB", buf, sizeof(buf), "1500"); g_waitMb = atoi(buf); if (g_waitMb < 1) g_waitMb = 1500;
}

static int isAdmin(void) {
    BOOL admin = FALSE; HANDLE tok = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
        TOKEN_ELEVATION el; DWORD cb = sizeof(el);
        if (GetTokenInformation(tok, TokenElevation, &el, sizeof(el), &cb)) admin = el.TokenIsElevated;
        CloseHandle(tok);
    }
    return admin;
}
static void runHidden(const char *cmd) {
    char full[1024]; snprintf(full, sizeof(full), "cmd /c %s >nul 2>&1", cmd);
    STARTUPINFOA si; PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
    if (CreateProcessA(NULL, full, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 8000);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    }
}
static void setupNetwork(void) {
    char cmd[512];
    printf("[*] Rede local (loopback %s + portproxy %s->%s)...\n", g_loginIp, g_loginPort, g_authPort);
    snprintf(cmd, sizeof(cmd),
        "netsh interface ipv4 add address \"Loopback Pseudo-Interface 1\" %s 255.255.255.255", g_loginIp);
    runHidden(cmd);
    snprintf(cmd, sizeof(cmd),
        "netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=%s connectaddress=127.0.0.1 connectport=%s",
        g_loginPort, g_authPort);
    runHidden(cmd);
    snprintf(cmd, sizeof(cmd),
        "netsh interface portproxy add v4tov4 listenaddress=%s listenport=%s connectaddress=127.0.0.1 connectport=%s",
        g_loginIp, g_loginPort, g_authPort);
    runHidden(cmd);
}
static void readMasked(char *out, size_t outsz) {
    size_t n = 0; int c;
    while ((c = _getch()) != '\r' && c != '\n') {
        if (c == 3) exit(1);
        if (c == '\b') { if (n > 0) { n--; printf("\b \b"); } continue; }
        if (c == 0 || c == 224) { _getch(); continue; }
        if (n < outsz - 1) { out[n++] = (char)c; printf("*"); }
    }
    out[n] = 0; printf("\n");
}
static void readLine(char *out, size_t outsz) {
    if (fgets(out, (int)outsz, stdin)) {
        char *e = out + strlen(out); while (e > out && (e[-1]=='\n'||e[-1]=='\r')) *--e = 0;
    } else out[0] = 0;
}

/* base do modulo principal (o 1o modulo e' sempre o exe) */
static unsigned long long resolveBase(HANDLE hProc) {
    HMODULE mods[256]; DWORD needed = 0;
    if (EnumProcessModules(hProc, mods, sizeof(mods), &needed) && needed >= sizeof(HMODULE))
        return (unsigned long long)(uintptr_t)mods[0];
    return 0;
}
static size_t wsMb(HANDLE hProc) {
    PROCESS_MEMORY_COUNTERS pmc; pmc.cb = sizeof(pmc);
    if (GetProcessMemoryInfo(hProc, &pmc, sizeof(pmc))) return pmc.WorkingSetSize / (1024*1024);
    return 0;
}

/* aplica o cave + jmp no compare. retorna 1 e preenche *caveOut no sucesso.
 * so' patcha quando a pagina ja foi descriptografada (prologo == ORIG). */
static int patchCave(HANDLE hProc, unsigned long long cmp, unsigned long long *caveOut) {
    unsigned char cur[6]; SIZE_T got = 0;
    if (!ReadProcessMemory(hProc,(LPCVOID)cmp,cur,6,&got) || got != 6) return 0;
    if (memcmp(cur, ORIG, 6) != 0) return 0;
    LPVOID cave = VirtualAllocEx(hProc, NULL, 0x400, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!cave) { printf("[!] VirtualAllocEx: %lu\n", GetLastError()); return 0; }
    if (!WriteProcessMemory(hProc, cave, CAVE, sizeof(CAVE), NULL)) { printf("[!] WPM(cave): %lu\n", GetLastError()); return 0; }
    unsigned char jmp[14] = { 0xFF,0x25,0,0,0,0 };     /* jmp qword ptr [rip+0] */
    memcpy(jmp+6, &cave, 8);
    DWORD old = 0;
    if (!VirtualProtectEx(hProc,(LPVOID)cmp,16,PAGE_EXECUTE_READWRITE,&old)) { printf("[!] VPE: %lu\n", GetLastError()); return 0; }
    int ok = WriteProcessMemory(hProc,(LPVOID)cmp,jmp,sizeof(jmp),NULL) ? 1 : 0;
    VirtualProtectEx(hProc,(LPVOID)cmp,16,old,&old);
    if (ok) *caveOut = (unsigned long long)(uintptr_t)cave;
    return ok;
}
static void reapplyJmp(HANDLE hProc, unsigned long long cmp, unsigned long long cave) {
    unsigned char cur[2]; SIZE_T got = 0;
    if (ReadProcessMemory(hProc,(LPCVOID)cmp,cur,2,&got) && got==2 && cur[0]==ORIG[0] && cur[1]==ORIG[1]) {
        unsigned char jmp[14] = { 0xFF,0x25,0,0,0,0 }; memcpy(jmp+6,&cave,8);
        DWORD old = 0; VirtualProtectEx(hProc,(LPVOID)cmp,16,PAGE_EXECUTE_READWRITE,&old);
        WriteProcessMemory(hProc,(LPVOID)cmp,jmp,sizeof(jmp),NULL);
        VirtualProtectEx(hProc,(LPVOID)cmp,16,old,&old);
        printf("[i] jmp re-aplicado\n");
    }
}

/* AUTH\t<login>\t<senha>\n pro Lu4Validator. retorna 1 se reply "OK". */
static int sendBridge(const char *host, const char *port, const char *login, const char *pass) {
    struct addrinfo hints, *res = NULL; int ok = 0;
    ZeroMemory(&hints, sizeof(hints)); hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0 || !res) return 0;
    SOCKET s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s != INVALID_SOCKET) {
        if (connect(s, res->ai_addr, (int)res->ai_addrlen) == 0) {
            char msg[256]; int n = snprintf(msg, sizeof(msg), "AUTH\t%s\t%s\n", login, pass);
            send(s, msg, n, 0);
            char buf[64]; int r = recv(s, buf, sizeof(buf)-1, 0);
            if (r > 0) {
                while (r > 0 && (buf[r-1]=='\n'||buf[r-1]=='\r')) r--;
                buf[r] = 0; ok = (strncmp(buf, "OK", 2) == 0);
                printf("[bridge] validator %s:%s -> '%s'%s\n", host, port, buf, ok ? "" : "  (REJEITADO)");
            }
        } else {
            printf("[bridge] nao conectou no validator %s:%s (AuthD com Lu4Mode?)\n", host, port);
        }
        closesocket(s);
    }
    freeaddrinfo(res);
    return ok;
}

int main(int argc, char **argv) {
    char login[64] = "", senha[128] = "";
    launcherDir(); loadConfig();

    printf("==============================================\n");
    printf("  Liberta Ultimata 4 - Loader (sem DLL/clmods)\n");
    printf("==============================================\n\n");

    for (int i = 1; i + 1 < argc; i++) {
        if (!_stricmp(argv[i], "--id"))  strncpy(login, argv[i+1], sizeof(login)-1);
        if (!_stricmp(argv[i], "--pwd")) strncpy(senha, argv[i+1], sizeof(senha)-1);
    }
    if (!login[0]) {
        char ini[MAX_PATH]; joinPath(ini, g_dir, "lu4loader.ini");
        iniGet(ini, "Login", login, sizeof(login), "");
        iniGet(ini, "Pass",  senha, sizeof(senha), "");
    }
    if (!login[0]) { printf("Login: "); readLine(login, sizeof(login)); }
    if (!senha[0]) { printf("Senha: "); readMasked(senha, sizeof(senha)); }
    /* credenciais sao OBRIGATORIAS: o bridge precisa delas (o servidor nao decifra as do cliente) */
    if (!login[0] || !senha[0]) { printf("\n[!] Login/senha vazios (o bridge precisa deles). Abortando.\n"); return 1; }

    if (GetFileAttributesA(g_game) == INVALID_FILE_ATTRIBUTES) {
        printf("\n[!] Cliente nao encontrado:\n    %s\n", g_game); return 2;
    }

    if (g_localDev) {
        if (isAdmin()) setupNetwork();
        else printf("[AVISO] sem admin: pulei o setup de rede (rode como Admin se o login falhar).\n");
    }

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) { printf("[!] WSAStartup falhou\n"); return 3; }

    char cwd[MAX_PATH]; strcpy(cwd, g_game);
    { char *s = strrchr(cwd, '\\'); if (s) *s = 0; }

    char cmd[1024];
    if (g_autoFill)
        snprintf(cmd, sizeof(cmd), "\"%s\" %s -ID %s -PWD %s", g_game, g_gameArgs, login, senha);
    else
        snprintf(cmd, sizeof(cmd), "\"%s\" %s", g_game, g_gameArgs);

    printf("\n[*] Lancando o cliente (sem launcher oficial -> sem clmods)...\n");
    STARTUPINFOA si; PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, cwd, &si, &pi)) {
        printf("[!] CreateProcess falhou: %lu\n", GetLastError()); WSACleanup(); return 3;
    }
    CloseHandle(pi.hThread);
    HANDLE h = pi.hProcess;
    printf("[*] Cliente PID %lu. Esperando carregar (WS > %d MB) p/ patchar TARDE...\n", pi.dwProcessId, g_waitMb);

    /* espera carregar (passar da checagem de integridade do init) */
    DWORD code = STILL_ACTIVE; ULONGLONG t0 = GetTickCount64();
    while (GetTickCount64() - t0 < 120000) {
        if (GetExitCodeProcess(h, &code) && code != STILL_ACTIVE) {
            printf("[i] processo saiu antes de carregar (exit %#lx).\n", code); WSACleanup(); return 0;
        }
        if (wsMb(h) >= (size_t)g_waitMb) break;
        Sleep(500);
    }
    unsigned long long base = 0; t0 = GetTickCount64();
    while (!base && GetTickCount64() - t0 < 10000) { base = resolveBase(h); if (!base) Sleep(200); }
    if (!base) { printf("[!] nao resolvi a base do modulo.\n"); WSACleanup(); return 4; }
    unsigned long long cmp = base + CMP_RVA;
    printf("[i] base=%#llx  compare @ %#llx. Instalando o cave...\n", base, cmp);

    unsigned long long cave = 0; int installed = 0; ULONGLONG bridgeT = 0;
    while (1) {
        if (GetExitCodeProcess(h, &code) && code != STILL_ACTIVE) {
            printf("[i] cliente saiu (exit %#lx). Encerrando.\n", code); break;
        }
        if (!installed) {
            if (patchCave(h, cmp, &cave)) {
                installed = 1;
                printf("[OK] cave @ %#llx; compare 0xBFEEA0 redirecionado.\n", cave);
                if (sendBridge(g_valHost, g_valPort, login, senha))
                    printf("[OK] credencial no bridge. Faca o login no jogo.\n");
                bridgeT = GetTickCount64();
                printf("[*] Mantenha esta janela aberta durante o login.\n");
            }
        } else {
            reapplyJmp(h, cmp, cave);
            if (GetTickCount64() - bridgeT > 120000) { sendBridge(g_valHost, g_valPort, login, senha); bridgeT = GetTickCount64(); }
        }
        Sleep(300);
    }
    WSACleanup();
    return 0;
}
