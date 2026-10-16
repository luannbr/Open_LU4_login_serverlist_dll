// lu4authhook.cpp -- DLL unica injetada no cliente LU4 (processo do jogo, nao o CEF).
// Dois hooks:
//
//  (1) LOGIN -- ConnectToLoginServer (RVA 0x4BB1850):
//        void __fastcall(this, FString* login /*rdx*/, FString* senha /*r8*/)
//        FString = { TCHAR* Data(0), int32 Num(8), int32 Max(12) } (UTF-16LE)
//        Captura login/senha em texto puro na UI (antes da cifra) e valida no nosso
//        validador local (whirlpool2, porta 27110). OK -> chama a original; FAIL ->
//        bloqueia + MessageBox. Hook inline com trampolim (prologo + jmp de volta).
//
//  (2) SERVERLIST MAC -- constant-time compare (RVA 0xBFEEA0):
//        __fastcall(buf1 rcx, buf2 rdx, len r8) -> 0 se iguais (gate do MAC de 32B
//        de cada pacote S2C do login). Substituimos a funcao inteira (ela e' pequena
//        e autocontida) por uma versao que faz o MESMO memcmp, mas retorna 0 (IGUAL)
//        quando len==32 e um dos buffers == MAGIC. Assim o AuthServer pode mandar uma
//        ServerList dinamica (so' os nossos servidores) com MAGIC no lugar do MAC real.
//        Blast radius = SO' os nossos pacotes; qualquer outro compare roda identico.
//
// (O antigo hook de rename da lista em 0x4CA02A0 foi removido: a lista agora e' gerada
//  dinamicamente no servidor com nomes reais, e aquela funcao nao dispara no fluxo real.)
//
// Compilar (x64):
//   cl /LD /O2 /EHsc /std:c++17 lu4authhook.cpp /Fe:lu4authhook.dll /link ws2_32.lib user32.lib

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <string>
#include <shellapi.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")

// ----------------------------------------------------------------------------
// Configuracao (RVAs do build atual do lu4-win64-shipping.exe)
// ----------------------------------------------------------------------------
static const uintptr_t LOGIN_RVA = 0x4BB1850;   // ConnectToLoginServer (hook inline + trampolim)
static const int       LOGIN_COPY = 14;         // prologo copiado: mov;push;sub;cmp
static const uintptr_t CMP_RVA   = 0xBFEEA0;    // constant-time compare (substituicao total)

static const char*     VALID_HOST = "127.0.0.1";
static const uint16_t  VALID_PORT = 27110;

// MAC de 32B que o AuthServer poe no lugar do MAC real da ServerList:
// "LU4-MAGIC-SERVERLIST-MAC-BYPASS!"
static const unsigned char MAGIC[32] = {
    0x4C,0x55,0x34,0x2D,0x4D,0x41,0x47,0x49,0x43,0x2D,0x53,0x45,0x52,0x56,0x45,0x52,
    0x4C,0x49,0x53,0x54,0x2D,0x4D,0x41,0x43,0x2D,0x42,0x59,0x50,0x41,0x53,0x53,0x21 };

// ----------------------------------------------------------------------------
// Estado
// ----------------------------------------------------------------------------
typedef void(__fastcall* ConnectFn)(void* thisObj, void* loginStr, void* senhaStr);
static ConnectFn oLogin = nullptr;   // trampolim do login

extern "C" IMAGE_DOS_HEADER __ImageBase;

// ----------------------------------------------------------------------------
// Utilitarios
// ----------------------------------------------------------------------------
static std::string dllDir()
{
    char path[MAX_PATH];
    GetModuleFileNameA((HMODULE)&__ImageBase, path, MAX_PATH);
    std::string p(path);
    size_t s = p.find_last_of("\\/");
    return (s == std::string::npos) ? "." : p.substr(0, s);
}

static void logLine(const std::string& msg)
{
    std::string lf = dllDir() + "\\lu4authhook.log";
    HANDLE h = CreateFileA(lf.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, nullptr,
                           OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        std::string line = msg + "\r\n"; DWORD w;
        WriteFile(h, line.data(), (DWORD)line.size(), &w, nullptr);
        CloseHandle(h);
    }
}

static std::wstring readFString(void* fstr)
{
    if (!fstr) return L"";
    uint8_t* p = (uint8_t*)fstr;
    wchar_t* data = *(wchar_t**)(p + 0);
    int32_t  num  = *(int32_t*)(p + 8);
    if (!data || num <= 1) return L"";
    if (IsBadReadPtr(data, (size_t)num * 2)) return L"";
    return std::wstring(data, num - 1);
}

static std::string toUtf8(const std::wstring& w)
{
    if (w.empty()) return "";
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], n, nullptr, nullptr);
    return s;
}

// ----------------------------------------------------------------------------
// Validacao de senha (login) via socket ao validador local
// ----------------------------------------------------------------------------
static bool validar(const std::wstring& login, const std::wstring& senha)
{
    bool allow = true;   // fail-open (nao trava login se validador estiver fora)
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return allow;
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) { WSACleanup(); return allow; }
    DWORD tmo = 3000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&tmo, sizeof(tmo));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (char*)&tmo, sizeof(tmo));
    sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_port = htons(VALID_PORT);
    inet_pton(AF_INET, VALID_HOST, &addr.sin_addr);
    if (connect(s, (sockaddr*)&addr, sizeof(addr)) == 0) {
        std::string payload = "AUTH\t" + toUtf8(login) + "\t" + toUtf8(senha) + "\n";
        send(s, payload.data(), (int)payload.size(), 0);
        char buf[64] = {0};
        int r = recv(s, buf, sizeof(buf) - 1, 0);
        if (r > 0) {
            std::string resp(buf, r);
            if (resp.rfind("OK", 0) == 0)        allow = true;
            else if (resp.rfind("FAIL", 0) == 0) allow = false;
        }
    }
    closesocket(s); WSACleanup();
    return allow;
}

// Valida direto dos args -ID/-PWD da linha de comando (auto-login do launcher), no
// momento do install. Popula o Lu4AuthBridge SEM depender de capturar o
// ConnectToLoginServer -- que e' racy: com cache quente o cliente auto-loga ANTES
// do hook instalar, e ai a validacao era perdida -> bridge vazio -> game rejeita ->
// LoginFail -> "fatal error". Com login digitado no cliente (sem -PWD nos args), cai
// no hook de ConnectToLoginServer normalmente (ai nao ha race: o usuario digita).
static void validarDosArgs()
{
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv) return;
    std::wstring login, senha;
    for (int i = 0; i + 1 < argc; i++) {
        if (_wcsicmp(argv[i], L"-ID") == 0)        login = argv[i + 1];
        else if (_wcsicmp(argv[i], L"-PWD") == 0)  senha = argv[i + 1];
    }
    LocalFree(argv);
    if (login.empty() || senha.empty()) {
        logLine("[login-args] sem -ID/-PWD nos args (login digitado no cliente) -- usando o hook de ConnectToLoginServer");
        return;
    }
    bool ok = validar(login, senha);
    logLine("[login-args] validado dos args: login='" + toUtf8(login) + "' -> " + (ok ? "OK (bridge populado)" : "FAIL"));
}

// ----------------------------------------------------------------------------
// Hooks
// ----------------------------------------------------------------------------
static void __fastcall hkConnect(void* thisObj, void* loginStr, void* senhaStr)
{
    std::wstring login = readFString(loginStr);
    std::wstring senha = readFString(senhaStr);
    logLine("[login] login='" + toUtf8(login) + "' senha_len=" + std::to_string(senha.size()));
    if (login.empty() || senha.empty()) { if (oLogin) oLogin(thisObj, loginStr, senhaStr); return; }
    if (!validar(login, senha)) {
        MessageBoxW(nullptr, L"Login ou senha incorretos.", L"Liberta Ultimata 4",
                    MB_OK | MB_ICONERROR | MB_TOPMOST);
        return;
    }
    if (oLogin) oLogin(thisObj, loginStr, senhaStr);
}

// Substituicao total de 0xBFEEA0 (sem trampolim -- a original nunca e' re-executada).
static volatile LONG g_bypassHits = 0;
extern "C" __int64 __fastcall hkCompare(const unsigned char* a1, const unsigned char* a2, uint64_t len)
{
    if (len == 32) {
        bool m1 = !IsBadReadPtr((void*)a1, 32) && memcmp(a1, MAGIC, 32) == 0;
        bool m2 = !IsBadReadPtr((void*)a2, 32) && memcmp(a2, MAGIC, 32) == 0;
        if (m1 || m2) {
            LONG n = InterlockedIncrement(&g_bypassHits);
            logLine("[serverlist] MAC MAGIC aceito (#" + std::to_string(n) + ")");
            return 0;   // iguais -> aceita
        }
    }
    __int64 diff = 0;
    if (len) {
        for (uint64_t i = 0; i < len; i++) { if (a1[i] != a2[i]) { diff = 1; break; } }
    }
    return diff;
}

// ----------------------------------------------------------------------------
// Instaladores de hook
// ----------------------------------------------------------------------------
// Hook inline com trampolim: retorna o trampolim (prologo original + jmp de volta).
static void* installInlineHook(uint8_t* func, int copyLen, void* hookFn, const char* tag)
{
    uint8_t* tramp = (uint8_t*)VirtualAlloc(nullptr, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!tramp) { logLine(std::string("[") + tag + "] VirtualAlloc falhou"); return nullptr; }
    memcpy(tramp, func, copyLen);
    tramp[copyLen+0]=0xFF; tramp[copyLen+1]=0x25; tramp[copyLen+2]=0; tramp[copyLen+3]=0; tramp[copyLen+4]=0; tramp[copyLen+5]=0;
    *(uint64_t*)(tramp + copyLen + 6) = (uint64_t)(func + copyLen);

    DWORD old;
    if (!VirtualProtect(func, copyLen, PAGE_EXECUTE_READWRITE, &old)) {
        logLine(std::string("[") + tag + "] VirtualProtect falhou"); return nullptr;
    }
    uint8_t patch[32];
    patch[0]=0xFF; patch[1]=0x25; patch[2]=0; patch[3]=0; patch[4]=0; patch[5]=0;
    *(uint64_t*)(patch + 6) = (uint64_t)hookFn;             // jmp -> hook (14 bytes)
    for (int i = 14; i < copyLen; i++) patch[i] = 0x90;     // NOP nos bytes orfaos
    memcpy(func, patch, copyLen);
    VirtualProtect(func, copyLen, old, &old);
    FlushInstructionCache(GetCurrentProcess(), func, copyLen);
    logLine(std::string("[") + tag + "] instalado @ " + std::to_string((uintptr_t)func));
    return tramp;
}

// Substituicao total (14B jmp, sem trampolim) -- pra funcoes que reimplementamos inteiras.
static void installJmp(uint8_t* at, void* target, const char* tag)
{
    DWORD old;
    if (!VirtualProtect(at, 14, PAGE_EXECUTE_READWRITE, &old)) {
        logLine(std::string("[") + tag + "] VirtualProtect falhou"); return;
    }
    at[0] = 0xFF; at[1] = 0x25; *(uint32_t*)(at + 2) = 0;
    *(uint64_t*)(at + 6) = (uint64_t)target;
    VirtualProtect(at, 14, old, &old);
    FlushInstructionCache(GetCurrentProcess(), at, 14);
    logLine(std::string("[") + tag + "] instalado @ " + std::to_string((uintptr_t)at));
}

static void installAll()
{
    uint8_t* base = (uint8_t*)GetModuleHandleW(nullptr);
    if (!base) { logLine("[hook] GetModuleHandle(NULL) falhou"); return; }
    logLine("[hook] base=" + std::to_string((uintptr_t)base));

    oLogin = (ConnectFn)installInlineHook(base + LOGIN_RVA, LOGIN_COPY, (void*)&hkConnect, "login");
    installJmp(base + CMP_RVA, (void*)&hkCompare, "serverlist-mac");
}

static DWORD WINAPI initThread(LPVOID)
{
    Sleep(500);
    installAll();
    validarDosArgs();   // popula o bridge dos args -ID/-PWD, imune ao race do auto-login
    return 0;
}

BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        CreateThread(nullptr, 0, initThread, nullptr, 0, nullptr);
    }
    return TRUE;
}
