/*
 * lu4launcher.c  --  Launcher proprio do LU4 (emulador).
 *
 * Faz o "abrir o jogo pro emulador" num passo so':
 *   1. Pede login/senha no console (sem site; conta nova e' auto-criada no server).
 *   2. (dev local) garante loopback 185.29.255.102 + portproxy 2108->2107 via netsh.
 *   3. Lanca o lu4-win64-shipping.exe com  LU4 -USEALLAVAILABLECORES -ID <login> -PWD <senha>.
 *   4. Injeta o lu4authhook.dll (LoadLibraryW remoto). O hook valida login/senha pelos
 *      proprios args no install (validarDosArgs) -> popula o Lu4AuthBridge sem race de timing,
 *      e aplica o bypass do MAC da serverlist.
 *
 * Config opcional: lu4launcher.ini ao lado do exe (ver defaults abaixo).
 *
 * Compilar:  build_launcher.bat   (chama vcvars64 do VS2022 + cl)
 *   cl /nologo /O2 /W3 lu4launcher.c /Fe:lu4launcher.exe /link user32.lib advapi32.lib shell32.lib
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <stdio.h>
#include <string.h>
#include <conio.h>

/* ---- defaults (relativos ao diretorio do launcher) ---- */
static const char *DEF_GAME_REL = "lu4\\binaries\\win64\\lu4-win64-shipping.exe";
static const char *DEF_DLL_REL  = "lu4authhook.dll";
static const char *DEF_GAME_ARGS = "LU4 -USEALLAVAILABLECORES";
static const char *DEF_LOGIN_IP  = "185.29.255.102";  /* IP que o cliente conecta (alias loopback no dev) */
static const char *DEF_LOGIN_PORT = "2108";            /* porta do cliente */
static const char *DEF_AUTH_PORT = "2107";             /* porta do nosso AuthServer (portproxy destino) */

/* ---- config efetiva ---- */
static char g_dir[MAX_PATH];
static char g_game[MAX_PATH];
static char g_dll[MAX_PATH];
static char g_gameArgs[512];
static char g_loginIp[64];
static char g_loginPort[16];
static char g_authPort[16];
static int  g_localDev = 1;   /* 1 = monta loopback+portproxy (dev); 0 = conecta direto (producao) */

static void launcherDir(void) {
    GetModuleFileNameA(NULL, g_dir, MAX_PATH);
    char *s = strrchr(g_dir, '\\');
    if (s) *s = 0;
}

static void joinPath(char *out, const char *dir, const char *rel) {
    if (rel[0] && (rel[1] == ':' || rel[0] == '\\')) { strcpy(out, rel); return; } /* ja absoluto */
    snprintf(out, MAX_PATH, "%s\\%s", dir, rel);
}

/* le "chave=valor" simples do ini (sem secoes) */
static void iniGet(const char *ini, const char *key, char *out, size_t outsz, const char *def) {
    strncpy(out, def, outsz); out[outsz-1] = 0;
    FILE *f = fopen(ini, "r");
    if (!f) return;
    char line[1024];
    size_t klen = strlen(key);
    while (fgets(line, sizeof(line), f)) {
        char *p = line; while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == ';') continue;
        if (_strnicmp(p, key, klen) == 0) {
            char *eq = strchr(p, '=');
            if (eq) {
                char *v = eq + 1; while (*v == ' ' || *v == '\t') v++;
                char *e = v + strlen(v); while (e > v && (e[-1]=='\n'||e[-1]=='\r'||e[-1]==' '||e[-1]=='\t')) *--e = 0;
                strncpy(out, v, outsz); out[outsz-1] = 0;
                break;
            }
        }
    }
    fclose(f);
}

static void loadConfig(void) {
    char ini[MAX_PATH], tmp[MAX_PATH], buf[64];
    joinPath(ini, g_dir, "lu4launcher.ini");
    iniGet(ini, "GameExe", tmp, sizeof(tmp), DEF_GAME_REL);  joinPath(g_game, g_dir, tmp);
    iniGet(ini, "HookDll", tmp, sizeof(tmp), DEF_DLL_REL);   joinPath(g_dll,  g_dir, tmp);
    iniGet(ini, "GameArgs", g_gameArgs, sizeof(g_gameArgs), DEF_GAME_ARGS);
    iniGet(ini, "LoginIp", g_loginIp, sizeof(g_loginIp), DEF_LOGIN_IP);
    iniGet(ini, "LoginPort", g_loginPort, sizeof(g_loginPort), DEF_LOGIN_PORT);
    iniGet(ini, "AuthPort", g_authPort, sizeof(g_authPort), DEF_AUTH_PORT);
    iniGet(ini, "LocalDev", buf, sizeof(buf), "1"); g_localDev = (buf[0]=='1'||buf[0]=='t'||buf[0]=='T');
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

/* roda um comando netsh escondido e espera */
static void runHidden(const char *cmd) {
    char full[1024];
    snprintf(full, sizeof(full), "cmd /c %s >nul 2>&1", cmd);
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
    printf("[*] Configurando rede local (loopback %s + portproxy %s->%s)...\n",
           g_loginIp, g_loginPort, g_authPort);
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

/* le senha mascarada (*) do console */
static void readMasked(char *out, size_t outsz) {
    size_t n = 0; int c;
    while ((c = _getch()) != '\r' && c != '\n') {
        if (c == 3) { exit(1); }                 /* Ctrl+C */
        if (c == '\b') { if (n > 0) { n--; printf("\b \b"); } continue; }
        if (c == 0 || c == 224) { _getch(); continue; } /* teclas especiais */
        if (n < outsz - 1) { out[n++] = (char)c; printf("*"); }
    }
    out[n] = 0; printf("\n");
}

static void readLine(char *out, size_t outsz) {
    if (fgets(out, (int)outsz, stdin)) {
        char *e = out + strlen(out);
        while (e > out && (e[-1]=='\n'||e[-1]=='\r')) *--e = 0;
    } else out[0] = 0;
}

/* injeta a DLL via LoadLibraryW remoto; retorna 1 ok */
static int injectDll(HANDLE hProc, const char *dllPath) {
    wchar_t wpath[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, dllPath, -1, wpath, MAX_PATH);
    SIZE_T bytes = (wcslen(wpath) + 1) * sizeof(wchar_t);
    LPVOID remote = VirtualAllocEx(hProc, NULL, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) { printf("[!] VirtualAllocEx falhou: %lu\n", GetLastError()); return 0; }
    if (!WriteProcessMemory(hProc, remote, wpath, bytes, NULL)) {
        printf("[!] WriteProcessMemory falhou: %lu\n", GetLastError());
        VirtualFreeEx(hProc, remote, 0, MEM_RELEASE); return 0;
    }
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    LPTHREAD_START_ROUTINE loadLib = (LPTHREAD_START_ROUTINE)GetProcAddress(k32, "LoadLibraryW");
    HANDLE th = CreateRemoteThread(hProc, NULL, 0, loadLib, remote, 0, NULL);
    if (!th) { printf("[!] CreateRemoteThread falhou: %lu\n", GetLastError()); VirtualFreeEx(hProc, remote, 0, MEM_RELEASE); return 0; }
    WaitForSingleObject(th, 15000);
    DWORD exit = 0; GetExitCodeThread(th, &exit);
    CloseHandle(th);
    VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
    if (!exit) { printf("[!] LoadLibraryW remoto retornou 0 (DLL nao carregou)\n"); return 0; }
    return 1;
}

int main(int argc, char **argv) {
    char login[64] = "", senha[128] = "";
    launcherDir();
    loadConfig();

    printf("==============================================\n");
    printf("  Liberta Ultimata 4 - Launcher (emulador)\n");
    printf("==============================================\n\n");

    /* credenciais: 1) args --id/--pwd  2) ini  3) prompt */
    for (int i = 1; i + 1 < argc; i++) {
        if (!_stricmp(argv[i], "--id"))  { strncpy(login, argv[i+1], sizeof(login)-1); }
        if (!_stricmp(argv[i], "--pwd")) { strncpy(senha, argv[i+1], sizeof(senha)-1); }
    }
    if (!login[0]) {
        char ini[MAX_PATH]; joinPath(ini, g_dir, "lu4launcher.ini");
        iniGet(ini, "Login", login, sizeof(login), "");
        iniGet(ini, "Pass",  senha, sizeof(senha), "");
    }
    if (!login[0]) { printf("Login: "); readLine(login, sizeof(login)); }
    if (!senha[0]) { printf("Senha: "); readMasked(senha, sizeof(senha)); }
    if (!login[0] || !senha[0]) { printf("\n[!] Login/senha vazios. Abortando.\n"); return 1; }

    if (GetFileAttributesA(g_game) == INVALID_FILE_ATTRIBUTES) {
        printf("\n[!] Cliente nao encontrado:\n    %s\n", g_game); return 2;
    }
    if (GetFileAttributesA(g_dll) == INVALID_FILE_ATTRIBUTES) {
        printf("\n[!] Hook nao encontrado:\n    %s\n", g_dll); return 2;
    }

    if (g_localDev) {
        if (isAdmin()) setupNetwork();
        else printf("[AVISO] sem admin: pulei o setup de rede (rode como Admin se o login falhar).\n");
    }

    /* cwd = pasta do exe (o UE acha o content por caminho relativo) */
    char cwd[MAX_PATH]; strcpy(cwd, g_game);
    char *s = strrchr(cwd, '\\'); if (s) *s = 0;

    /* linha de comando: "<exe>" <GameArgs> -ID <login> -PWD <senha> */
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "\"%s\" %s -ID %s -PWD %s", g_game, g_gameArgs, login, senha);

    printf("\n[*] Iniciando cliente como '%s'...\n", login);
    STARTUPINFOA si; PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, cwd, &si, &pi)) {
        printf("[!] CreateProcess falhou: %lu\n", GetLastError()); return 3;
    }
    printf("[*] Cliente PID %lu. Aguardando inicializacao para injetar o hook...\n", pi.dwProcessId);

    /* espera o loader inicializar (seguro p/ LoadLibrary remoto); o auto-login do UE
       demora bem mais, entao injetamos muito antes dele. */
    Sleep(1200);
    if (injectDll(pi.hProcess, g_dll))
        printf("[+] Hook injetado (lu4authhook.dll). Login validado pelos args no install.\n");
    else
        printf("[!] Falha ao injetar o hook. O cliente vai abrir, mas sem login/serverlist do emulador.\n");

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    printf("\n[OK] Pronto. Bom jogo!\n");
    Sleep(1500);
    return 0;
}
