/*
 * lu4launcher_gui.c  --  Launcher do LU4 (emulador) com interface grafica (Win32).
 *
 * Tema escuro/fantasia no estilo do jogo. Gerencia MULTIPLAS CONTAS (lista + login/senha),
 * salva/remove, e no "JOGAR": monta rede (dev), lanca o cliente e injeta o hook
 * (que valida login/senha pelos args -> popula o Lu4AuthBridge, sem race).
 *
 * Contas salvas em lu4accounts.dat (ao lado do exe), senha com XOR (ofuscacao leve).
 * Config em lu4launcher.ini (mesmas chaves do launcher console).
 *
 * Compilar: build_launcher.bat  (compila console E gui)
 *   cl /nologo /O2 /W3 lu4launcher_gui.c /Fe:lu4launcher_gui.exe ^
 *      /link user32.lib gdi32.lib advapi32.lib shell32.lib comctl32.lib
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <commctrl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "comctl32.lib")
/* controles modernos (tema) + cue banners */
#pragma comment(linker,"\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

/* ------------------------- config (igual ao console) ------------------------- */
static const char *DEF_GAME_REL = "lu4\\binaries\\win64\\lu4-win64-shipping.exe";
static const char *DEF_DLL_REL  = "lu4authhook.dll";
static const char *DEF_GAME_ARGS = "LU4 -USEALLAVAILABLECORES";
static const char *DEF_LOGIN_IP  = "185.29.255.102";
static const char *DEF_LOGIN_PORT = "2108";
static const char *DEF_AUTH_PORT = "2107";

static char g_dir[MAX_PATH], g_game[MAX_PATH], g_dll[MAX_PATH];
static char g_gameArgs[512], g_loginIp[64], g_loginPort[16], g_authPort[16];
static int  g_localDev = 1;

/* ------------------------- contas ------------------------- */
#define MAX_ACC 64
typedef struct { char login[64]; char pass[128]; } Account;
static Account g_acc[MAX_ACC];
static int g_nacc = 0;

static const char *XORKEY = "Lu4-Liberta-Ultimata-Key-2026";

/* ------------------------- cores / tema ------------------------- */
#define COL_BG      RGB(18, 16, 14)
#define COL_PANEL   RGB(30, 26, 22)
#define COL_EDIT    RGB(40, 35, 30)
#define COL_GOLD    RGB(206, 170, 94)
#define COL_TEXT    RGB(220, 210, 195)
#define COL_DIM     RGB(150, 140, 125)
#define COL_RED     RGB(150, 40, 36)
#define COL_REDHI   RGB(190, 60, 52)

/* ------------------------- controles ------------------------- */
#define ID_COMBO   1001
#define ID_LOGIN   1002
#define ID_PASS    1003
#define ID_SAVE    1004
#define ID_DEL     1005
#define ID_PLAY    1006
#define ID_CLOSE   1007

static HWND hCombo, hLogin, hPass, hBtnSave, hBtnDel, hBtnPlay, hBtnClose, hStatus;
static HBRUSH hbrBg, hbrEdit, hbrPanel;
static HFONT hFontBig, hFontMid, hFontSmall, hFontTitle;

/* ------------------------- utils de config ------------------------- */
static void launcherDir(void){ GetModuleFileNameA(NULL,g_dir,MAX_PATH); char*s=strrchr(g_dir,'\\'); if(s)*s=0; }
static void joinPath(char*out,const char*dir,const char*rel){
    if(rel[0] && (rel[1]==':'||rel[0]=='\\')){ strcpy(out,rel); return; }
    snprintf(out,MAX_PATH,"%s\\%s",dir,rel);
}
static void iniGet(const char*ini,const char*key,char*out,size_t outsz,const char*def){
    strncpy(out,def,outsz); out[outsz-1]=0;
    FILE*f=fopen(ini,"r"); if(!f) return;
    char line[1024]; size_t klen=strlen(key);
    while(fgets(line,sizeof(line),f)){
        char*p=line; while(*p==' '||*p=='\t')p++;
        if(*p=='#'||*p==';')continue;
        if(_strnicmp(p,key,klen)==0){
            char*eq=strchr(p,'='); if(eq){ char*v=eq+1; while(*v==' '||*v=='\t')v++;
                char*e=v+strlen(v); while(e>v&&(e[-1]=='\n'||e[-1]=='\r'||e[-1]==' '||e[-1]=='\t'))*--e=0;
                strncpy(out,v,outsz); out[outsz-1]=0; break; } }
    }
    fclose(f);
}
static void loadConfig(void){
    char ini[MAX_PATH],tmp[MAX_PATH],buf[64];
    joinPath(ini,g_dir,"lu4launcher.ini");
    iniGet(ini,"GameExe",tmp,sizeof(tmp),DEF_GAME_REL); joinPath(g_game,g_dir,tmp);
    iniGet(ini,"HookDll",tmp,sizeof(tmp),DEF_DLL_REL);  joinPath(g_dll,g_dir,tmp);
    iniGet(ini,"GameArgs",g_gameArgs,sizeof(g_gameArgs),DEF_GAME_ARGS);
    iniGet(ini,"LoginIp",g_loginIp,sizeof(g_loginIp),DEF_LOGIN_IP);
    iniGet(ini,"LoginPort",g_loginPort,sizeof(g_loginPort),DEF_LOGIN_PORT);
    iniGet(ini,"AuthPort",g_authPort,sizeof(g_authPort),DEF_AUTH_PORT);
    iniGet(ini,"LocalDev",buf,sizeof(buf),"1"); g_localDev=(buf[0]=='1'||buf[0]=='t'||buf[0]=='T');
}

/* ------------------------- contas: XOR+hex, load/save ------------------------- */
static void xorHexEnc(const char*in,char*out){
    size_t kl=strlen(XORKEY); char*o=out;
    for(size_t i=0;in[i];i++){ unsigned char c=(unsigned char)in[i]^(unsigned char)XORKEY[i%kl];
        o+=sprintf(o,"%02x",c); }
    *o=0;
}
static void xorHexDec(const char*in,char*out){
    size_t kl=strlen(XORKEY),j=0;
    for(size_t i=0;in[i]&&in[i+1];i+=2,j++){
        unsigned v; sscanf(in+i,"%2x",&v);
        out[j]=(char)((unsigned char)v^(unsigned char)XORKEY[j%kl]);
    }
    out[j]=0;
}
static void accPath(char*out){ joinPath(out,g_dir,"lu4accounts.dat"); }
static void accLoad(void){
    g_nacc=0; char p[MAX_PATH]; accPath(p);
    FILE*f=fopen(p,"r"); if(!f) return;
    char line[512];
    while(fgets(line,sizeof(line),f) && g_nacc<MAX_ACC){
        char*e=line+strlen(line); while(e>line&&(e[-1]=='\n'||e[-1]=='\r'))*--e=0;
        char*tab=strchr(line,'\t'); if(!tab)continue; *tab=0;
        strncpy(g_acc[g_nacc].login,line,63); g_acc[g_nacc].login[63]=0;
        xorHexDec(tab+1,g_acc[g_nacc].pass);
        g_nacc++;
    }
    fclose(f);
}
static void accSave(void){
    char p[MAX_PATH]; accPath(p);
    FILE*f=fopen(p,"w"); if(!f) return;
    for(int i=0;i<g_nacc;i++){ char enc[300]; xorHexEnc(g_acc[i].pass,enc);
        fprintf(f,"%s\t%s\n",g_acc[i].login,enc); }
    fclose(f);
}
static int accFind(const char*login){ for(int i=0;i<g_nacc;i++) if(!_stricmp(g_acc[i].login,login)) return i; return -1; }

/* ------------------------- admin / rede / launch / inject ------------------------- */
static int isAdmin(void){
    BOOL a=FALSE; HANDLE t=NULL;
    if(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&t)){ TOKEN_ELEVATION e; DWORD cb=sizeof(e);
        if(GetTokenInformation(t,TokenElevation,&e,sizeof(e),&cb)) a=e.TokenIsElevated; CloseHandle(t);} return a;
}
static void runHidden(const char*cmd){
    char full[1024]; snprintf(full,sizeof(full),"cmd /c %s >nul 2>&1",cmd);
    STARTUPINFOA si; PROCESS_INFORMATION pi; ZeroMemory(&si,sizeof(si)); si.cb=sizeof(si);
    si.dwFlags=STARTF_USESHOWWINDOW; si.wShowWindow=SW_HIDE;
    if(CreateProcessA(NULL,full,NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,NULL,&si,&pi)){
        WaitForSingleObject(pi.hProcess,8000); CloseHandle(pi.hThread); CloseHandle(pi.hProcess);} }
static void setupNetwork(void){
    char c[512];
    snprintf(c,sizeof(c),"netsh interface ipv4 add address \"Loopback Pseudo-Interface 1\" %s 255.255.255.255",g_loginIp); runHidden(c);
    snprintf(c,sizeof(c),"netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=%s connectaddress=127.0.0.1 connectport=%s",g_loginPort,g_authPort); runHidden(c);
    snprintf(c,sizeof(c),"netsh interface portproxy add v4tov4 listenaddress=%s listenport=%s connectaddress=127.0.0.1 connectport=%s",g_loginIp,g_loginPort,g_authPort); runHidden(c);
}
static int injectDll(HANDLE hProc,const char*dllPath){
    wchar_t w[MAX_PATH]; MultiByteToWideChar(CP_ACP,0,dllPath,-1,w,MAX_PATH);
    SIZE_T n=(wcslen(w)+1)*sizeof(wchar_t);
    LPVOID rem=VirtualAllocEx(hProc,NULL,n,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE); if(!rem)return 0;
    if(!WriteProcessMemory(hProc,rem,w,n,NULL)){ VirtualFreeEx(hProc,rem,0,MEM_RELEASE); return 0; }
    LPTHREAD_START_ROUTINE ll=(LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleW(L"kernel32.dll"),"LoadLibraryW");
    HANDLE th=CreateRemoteThread(hProc,NULL,0,ll,rem,0,NULL); if(!th){ VirtualFreeEx(hProc,rem,0,MEM_RELEASE); return 0; }
    WaitForSingleObject(th,15000); DWORD ec=0; GetExitCodeThread(th,&ec);
    CloseHandle(th); VirtualFreeEx(hProc,rem,0,MEM_RELEASE); return ec!=0;
}

/* thread de launch pra nao travar a UI */
typedef struct { char login[64]; char pass[128]; } LaunchArgs;
static void setStatus(const char*s){ SetWindowTextA(hStatus,s); }
static DWORD WINAPI launchThread(LPVOID p){
    LaunchArgs*a=(LaunchArgs*)p;
    if(GetFileAttributesA(g_game)==INVALID_FILE_ATTRIBUTES){ setStatus("Erro: cliente nao encontrado (veja lu4launcher.ini)"); free(a); return 1; }
    if(GetFileAttributesA(g_dll)==INVALID_FILE_ATTRIBUTES){ setStatus("Erro: hook (lu4authhook.dll) nao encontrado"); free(a); return 1; }
    if(g_localDev){ if(isAdmin()){ setStatus("Configurando rede local..."); setupNetwork(); }
        else setStatus("Sem Admin: pulei setup de rede (ok se ja configurado)"); }
    char cwd[MAX_PATH]; strcpy(cwd,g_game); char*s=strrchr(cwd,'\\'); if(s)*s=0;
    char cmd[1024]; snprintf(cmd,sizeof(cmd),"\"%s\" %s -ID %s -PWD %s",g_game,g_gameArgs,a->login,a->pass);
    setStatus("Iniciando cliente...");
    STARTUPINFOA si; PROCESS_INFORMATION pi; ZeroMemory(&si,sizeof(si)); si.cb=sizeof(si);
    if(!CreateProcessA(NULL,cmd,NULL,NULL,FALSE,0,NULL,cwd,&si,&pi)){ setStatus("Erro: falha ao iniciar o cliente"); free(a); return 1; }
    Sleep(1200);
    setStatus("Injetando protecao do emulador...");
    int ok=injectDll(pi.hProcess,g_dll);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    setStatus(ok? "Pronto! Cliente aberto. Bom jogo!" : "Cliente aberto, mas a injecao do hook FALHOU.");
    free(a);
    return 0;
}

/* ------------------------- UI helpers ------------------------- */
static void fillCombo(void){
    SendMessageA(hCombo,CB_RESETCONTENT,0,0);
    for(int i=0;i<g_nacc;i++) SendMessageA(hCombo,CB_ADDSTRING,0,(LPARAM)g_acc[i].login);
}
static void onComboSel(void){
    int idx=(int)SendMessageA(hCombo,CB_GETCURSEL,0,0);
    if(idx>=0 && idx<g_nacc){ SetWindowTextA(hLogin,g_acc[idx].login); SetWindowTextA(hPass,g_acc[idx].pass); }
}
static void getField(HWND h,char*out,int sz){ GetWindowTextA(h,out,sz); }

static void onSave(void){
    char l[64],p[128]; getField(hLogin,l,sizeof(l)); getField(hPass,p,sizeof(p));
    if(!l[0]){ setStatus("Informe o login para salvar."); return; }
    int i=accFind(l);
    if(i<0){ if(g_nacc>=MAX_ACC){ setStatus("Limite de contas atingido."); return; } i=g_nacc++; }
    strncpy(g_acc[i].login,l,63); g_acc[i].login[63]=0;
    strncpy(g_acc[i].pass,p,127); g_acc[i].pass[127]=0;
    accSave(); fillCombo();
    SendMessageA(hCombo,CB_SETCURSEL,(WPARAM)i,0);
    setStatus("Conta salva.");
}
static void onDel(void){
    int idx=(int)SendMessageA(hCombo,CB_GETCURSEL,0,0);
    if(idx<0||idx>=g_nacc){ setStatus("Selecione uma conta para remover."); return; }
    for(int j=idx;j<g_nacc-1;j++) g_acc[j]=g_acc[j+1];
    g_nacc--; accSave(); fillCombo();
    SetWindowTextA(hLogin,""); SetWindowTextA(hPass,"");
    setStatus("Conta removida.");
}
static void onPlay(void){
    char l[64],p[128]; getField(hLogin,l,sizeof(l)); getField(hPass,p,sizeof(p));
    if(!l[0]||!p[0]){ setStatus("Preencha login e senha."); return; }
    LaunchArgs*a=(LaunchArgs*)malloc(sizeof(LaunchArgs));
    strncpy(a->login,l,63); a->login[63]=0; strncpy(a->pass,p,127); a->pass[127]=0;
    CreateThread(NULL,0,launchThread,a,0,NULL);
}

/* desenha botao JOGAR (owner-draw) */
static void drawPlay(LPDRAWITEMSTRUCT d){
    int hot=(d->itemState&ODS_SELECTED)!=0;
    HBRUSH b=CreateSolidBrush(hot?COL_REDHI:COL_RED);
    FillRect(d->hDC,&d->rcItem,b); DeleteObject(b);
    FrameRect(d->hDC,&d->rcItem,(HBRUSH)GetStockObject(BLACK_BRUSH));
    HPEN pen=CreatePen(PS_SOLID,1,COL_GOLD); HGDIOBJ op=SelectObject(d->hDC,pen);
    SelectObject(d->hDC,GetStockObject(NULL_BRUSH));
    Rectangle(d->hDC,d->rcItem.left+2,d->rcItem.top+2,d->rcItem.right-2,d->rcItem.bottom-2);
    SelectObject(d->hDC,op); DeleteObject(pen);
    SetBkMode(d->hDC,TRANSPARENT); SetTextColor(d->hDC,COL_GOLD);
    SelectObject(d->hDC,hFontBig);
    DrawTextA(d->hDC,"JOGAR",-1,&d->rcItem,DT_CENTER|DT_VCENTER|DT_SINGLELINE);
}
static void drawClose(LPDRAWITEMSTRUCT d){
    int hot=(d->itemState&ODS_SELECTED)!=0;
    SetBkMode(d->hDC,TRANSPARENT); SetTextColor(d->hDC,hot?COL_REDHI:COL_DIM);
    SelectObject(d->hDC,hFontMid);
    DrawTextA(d->hDC,"X",-1,&d->rcItem,DT_CENTER|DT_VCENTER|DT_SINGLELINE);
}

/* ------------------------- WndProc ------------------------- */
static LRESULT CALLBACK WndProc(HWND hwnd,UINT msg,WPARAM wp,LPARAM lp){
    switch(msg){
    case WM_CREATE: {
        hFontTitle=CreateFontA(30,0,0,0,FW_BOLD,0,0,0,DEFAULT_CHARSET,0,0,CLEARTYPE_QUALITY,0,"Georgia");
        hFontBig  =CreateFontA(22,0,0,0,FW_BOLD,0,0,0,DEFAULT_CHARSET,0,0,CLEARTYPE_QUALITY,0,"Georgia");
        hFontMid  =CreateFontA(18,0,0,0,FW_BOLD,0,0,0,DEFAULT_CHARSET,0,0,CLEARTYPE_QUALITY,0,"Segoe UI");
        hFontSmall=CreateFontA(15,0,0,0,FW_NORMAL,0,0,0,DEFAULT_CHARSET,0,0,CLEARTYPE_QUALITY,0,"Segoe UI");
        int x=40,w=360;
        hCombo=CreateWindowA("COMBOBOX","",WS_CHILD|WS_VISIBLE|CBS_DROPDOWNLIST|WS_VSCROLL,x,150,w,200,hwnd,(HMENU)ID_COMBO,NULL,NULL);
        hLogin=CreateWindowA("EDIT","",WS_CHILD|WS_VISIBLE|ES_AUTOHSCROLL,x,218,w,30,hwnd,(HMENU)ID_LOGIN,NULL,NULL);
        hPass =CreateWindowA("EDIT","",WS_CHILD|WS_VISIBLE|ES_AUTOHSCROLL|ES_PASSWORD,x,278,w,30,hwnd,(HMENU)ID_PASS,NULL,NULL);
        hBtnSave=CreateWindowA("BUTTON","Salvar conta",WS_CHILD|WS_VISIBLE,x,320,175,30,hwnd,(HMENU)ID_SAVE,NULL,NULL);
        hBtnDel =CreateWindowA("BUTTON","Remover",WS_CHILD|WS_VISIBLE,x+185,320,175,30,hwnd,(HMENU)ID_DEL,NULL,NULL);
        hBtnPlay=CreateWindowA("BUTTON","JOGAR",WS_CHILD|WS_VISIBLE|BS_OWNERDRAW,x,375,w,52,hwnd,(HMENU)ID_PLAY,NULL,NULL);
        hStatus=CreateWindowA("STATIC","Pronto.",WS_CHILD|WS_VISIBLE|SS_CENTER,x,440,w,22,hwnd,(HMENU)0,NULL,NULL);
        hBtnClose=CreateWindowA("BUTTON","X",WS_CHILD|WS_VISIBLE|BS_OWNERDRAW,400,8,32,28,hwnd,(HMENU)ID_CLOSE,NULL,NULL);
        SendMessageA(hLogin,WM_SETFONT,(WPARAM)hFontMid,1);
        SendMessageA(hPass,WM_SETFONT,(WPARAM)hFontMid,1);
        SendMessageA(hCombo,WM_SETFONT,(WPARAM)hFontMid,1);
        SendMessageA(hBtnSave,WM_SETFONT,(WPARAM)hFontSmall,1);
        SendMessageA(hBtnDel,WM_SETFONT,(WPARAM)hFontSmall,1);
        SendMessageA(hStatus,WM_SETFONT,(WPARAM)hFontSmall,1);
        SendMessageA(hLogin,EM_SETCUEBANNER,1,(LPARAM)L"Login");
        SendMessageA(hPass,EM_SETCUEBANNER,1,(LPARAM)L"Senha");
        accLoad(); fillCombo();
        if(g_nacc>0){ SendMessageA(hCombo,CB_SETCURSEL,0,0); onComboSel(); }
        return 0;
    }
    case WM_CTLCOLOREDIT: case WM_CTLCOLORLISTBOX: {
        HDC dc=(HDC)wp; SetBkColor(dc,COL_EDIT); SetTextColor(dc,COL_TEXT); return (LRESULT)hbrEdit; }
    case WM_CTLCOLORSTATIC: {
        HDC dc=(HDC)wp; SetBkMode(dc,TRANSPARENT); SetTextColor(dc,COL_DIM); return (LRESULT)hbrBg; }
    case WM_CTLCOLORBTN: { return (LRESULT)hbrBg; }
    case WM_ERASEBKGND: {
        HDC dc=(HDC)wp; RECT rc; GetClientRect(hwnd,&rc);
        FillRect(dc,&rc,hbrBg);
        /* header */
        RECT h=rc; h.bottom=120; FillRect(dc,&h,hbrPanel);
        HPEN pen=CreatePen(PS_SOLID,2,COL_GOLD); HGDIOBJ op=SelectObject(dc,pen);
        MoveToEx(dc,0,120,NULL); LineTo(dc,rc.right,120); SelectObject(dc,op); DeleteObject(pen);
        SetBkMode(dc,TRANSPARENT);
        SelectObject(dc,hFontTitle); SetTextColor(dc,COL_GOLD);
        RECT t=h; t.top=28; DrawTextA(dc,"LIBERTA ULTIMATA 4",-1,&t,DT_CENTER|DT_TOP|DT_SINGLELINE);
        SelectObject(dc,hFontSmall); SetTextColor(dc,COL_DIM);
        RECT s=h; s.top=72; DrawTextA(dc,"Launcher do Emulador",-1,&s,DT_CENTER|DT_TOP|DT_SINGLELINE);
        return 1;
    }
    case WM_LBUTTONDOWN: {
        POINTS pt=MAKEPOINTS(lp); if(pt.y<120){ ReleaseCapture(); SendMessageA(hwnd,WM_NCLBUTTONDOWN,HTCAPTION,0); }
        return 0;
    }
    case WM_DRAWITEM: {
        LPDRAWITEMSTRUCT d=(LPDRAWITEMSTRUCT)lp;
        if(d->CtlID==ID_PLAY) drawPlay(d); else if(d->CtlID==ID_CLOSE) drawClose(d);
        return TRUE;
    }
    case WM_COMMAND: {
        int id=LOWORD(wp), code=HIWORD(wp);
        if(id==ID_COMBO && code==CBN_SELCHANGE) onComboSel();
        else if(id==ID_SAVE) onSave();
        else if(id==ID_DEL) onDel();
        else if(id==ID_PLAY) onPlay();
        else if(id==ID_CLOSE) PostQuitMessage(0);
        return 0;
    }
    case WM_DESTROY: PostQuitMessage(0); return 0;
    }
    return DefWindowProcA(hwnd,msg,wp,lp);
}

int WINAPI WinMain(HINSTANCE hInst,HINSTANCE hPrev,LPSTR cmd,int show){
    (void)hPrev;(void)cmd;(void)show;
    launcherDir(); loadConfig();
    INITCOMMONCONTROLSEX icc={sizeof(icc),ICC_STANDARD_CLASSES}; InitCommonControlsEx(&icc);
    hbrBg=CreateSolidBrush(COL_BG); hbrEdit=CreateSolidBrush(COL_EDIT); hbrPanel=CreateSolidBrush(COL_PANEL);
    WNDCLASSA wc; ZeroMemory(&wc,sizeof(wc));
    wc.lpfnWndProc=WndProc; wc.hInstance=hInst; wc.hCursor=LoadCursor(NULL,IDC_ARROW);
    wc.lpszClassName="LU4LauncherWnd"; wc.hbrBackground=hbrBg;
    RegisterClassA(&wc);
    int W=440,H=500;
    int sx=(GetSystemMetrics(SM_CXSCREEN)-W)/2, sy=(GetSystemMetrics(SM_CYSCREEN)-H)/2;
    HWND hwnd=CreateWindowExA(WS_EX_APPWINDOW,"LU4LauncherWnd","Liberta Ultimata 4",
        WS_POPUP|WS_VISIBLE,sx,sy,W,H,NULL,NULL,hInst,NULL);
    /* borda dourada fina */
    SetWindowLongA(hwnd,GWL_STYLE,WS_POPUP|WS_VISIBLE);
    ShowWindow(hwnd,SW_SHOW); UpdateWindow(hwnd);
    /* traz pra frente sem ficar topmost permanente */
    SetWindowPos(hwnd,HWND_TOPMOST,0,0,0,0,SWP_NOMOVE|SWP_NOSIZE);
    SetWindowPos(hwnd,HWND_NOTOPMOST,0,0,0,0,SWP_NOMOVE|SWP_NOSIZE);
    SetForegroundWindow(hwnd);
    MSG m; while(GetMessageA(&m,NULL,0,0)){ TranslateMessage(&m); DispatchMessageA(&m); }
    return 0;
}
