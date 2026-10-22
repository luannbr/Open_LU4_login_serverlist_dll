/*
 * lu4_disconnect_guard.h  --  Filtro liveness-aware de desconexao do lu4.bin (DisconnectGuard).
 *
 * ================================ O QUE RESOLVE ================================
 * O cliente lu4.bin (UE5, VMProtect) derruba a propria conexao depois de alguns
 * minutos PARADO, mesmo em localhost e com o servidor 100% saudavel. A queda nao
 * vem do servidor: eh uma rotina interna (watchdog) que, num tick do jogo, chama
 * o NetManager::Disconnect e encerra a thread de rede -> FIN. O servidor nunca
 * pediu desconexao; o ring de pacotes fica limpo ate o fim e o ping (S2C 0xd9 /
 * C2S 0x03) eh respondido ate o ultimo segundo.
 *
 * ESSE MESMO watchdog (call-site base+0x915B3F3) tambem eh o caminho das quedas
 * REAIS: quando o servidor cai / reseta, o tick percebe o socket morto e chama o
 * MESMO Disconnect. Por isso um filtro "cego" (que engole tudo que vem desse
 * call-site) mata a queda por ociosidade MAS tambem impede o cliente de perceber
 * server offline / reset / reconnect. A discriminacao tem que ser por LIVENESS:
 * engolir a desconexao automatica SO' enquanto a conexao esta viva; se ela caiu
 * de verdade, deixar passar.
 *
 * ========================= COMO FUNCIONA (liveness-aware) =====================
 * Tudo de FORA do processo (VirtualAllocEx/WriteProcessMemory), sem DLL e sem
 * thread remota -- no mesmo espirito do "cave" do MAC do loader. A novidade eh
 * uma flag "alive" lida pelo trampolim e mantida pelo loader (que ja faz poll da
 * tabela TCP): a flag vale 1 enquanto a conexao do jogo esta estabelecida e o
 * loader a zera no instante em que ela cai.
 *
 *  1. Fingerprint do build (abortar se nao casar):
 *     - 8 bytes em base+0x4d01a90 devem ser o getter conhecido
 *       (48 8b 05 89 75 6c 03 c3). Se diferir -> -1, nao toca em nada.
 *     - os 15 bytes do prologo do Disconnect (base+0x4ce8c60) devem casar -> senao -2.
 *
 *  2. Aloca 2 paginas (8 KiB): pagina 0 (RX) = trampolim; pagina 1 (RW, +4096) =
 *     contador u64 (+0) e a flag "alive" de 1 byte (+8). A flag nasce 1 (viva).
 *
 *  3. Trampolim (PIC):
 *        mov  rax,[rsp]             ; rax = retorno do chamador do Disconnect
 *        movabs r11,<caller>        ; caller = base+0x915B3F3 (call-site do watchdog)
 *        cmp  rax,r11
 *        jne  .passa                ; outro chamador (relog/logout/quit) -> intacto
 *        test dl,dl                 ; notify (2o arg); ==0 nao eh a desconexao automatica
 *        je   .passa
 *        movabs r11,<aliveFlag>
 *        cmp  byte [r11],0          ; conexao viva?
 *        je   .passa                ; alive==0 (caiu de verdade / ainda nao sabemos) -> deixa cair
 *        movabs r11,<counter>       ; alive==1: ociosidade com conexao viva ->
 *        lock inc qword [r11]       ;   conta...
 *        ret                        ;   ...e RETORNA ja', engolindo a queda inutil.
 *      .passa:
 *        <15 bytes originais do prologo>
 *        jmp  [rip+0] -> <resume>   ; resume = Disconnect+15, segue a funcao de verdade
 *
 *     Chave do "por chamador": o Disconnect eh alcancado por JMP (nao CALL), entao
 *     [rsp] no topo ainda eh o retorno de quem chamou o Disconnect. So' rax e r11
 *     sao usados (volateis); rcx(mgr)/rdx(notify) e o resto ficam intactos pro
 *     caminho .passa.
 *
 *  4. Reescreve o prologo do Disconnect com jmp de 15 bytes
 *     (FF 25 <rip+0> <remote u64>; nop), com verificacao e restauro em caso de falha.
 *
 *  5. A alocacao NAO eh liberada enquanto o cliente viver (uma chamada pode estar
 *     em voo). A flag fica na pagina RW e eh escrita pelo loader de fora.
 *
 * ====================== CONTRATO DA FLAG (lado loader) ========================
 * O loader recebe o endereco da flag em *aliveOut e:
 *   - a mantem 1 enquanto a conexao TCP do jogo (GamePort) esta estabelecida;
 *   - a zera (1 byte = 0) assim que a conexao cai -> a proxima desconexao
 *     automatica eh deixada passar e o cliente mostra "disconnected";
 *   - a re-arma (=1) ao reentrar no mundo (relog).
 * Durante o jogo saudavel o loader NAO precisa manter handle aberto nem escrever
 * nada (a flag ja nasce 1): so' reabre o handle pra 1 byte quando a conexao cai.
 * Limitacao: isso cobre server offline / reset / FIN (muda o estado TCP); um
 * "freeze" silencioso sem FIN mantem o TCP estabelecido e so' cai pelo keepalive
 * do SO -- aceitavel e muito melhor que o filtro cego.
 *
 * ============================== VALORES DE RETORNO ============================
 *   1  = instalado; *counterOut = contador, *aliveOut = flag "alive" (ambos no cliente).
 *  -1  = fingerprint do getter nao casou (build diferente): nada feito.
 *  -2  = prologo do Disconnect inesperado (ja patchado / build diferente): nada.
 *  -3  = VirtualAllocEx falhou.   -4 = escrita/protect/flush do trampolim falhou.
 *  -5  = VirtualProtectEx do alvo falhou.   -6 = escrita do alvo nao confirmou.
 *  -7  = instalado, mas nao devolveu a protecao original da pagina.
 *  -8  = FlushInstructionCache do alvo falhou.
 *
 * Offsets (base-relativos) sao ESPECIFICOS deste build do lu4.bin; o fingerprint
 * do passo 1 impede aplica-los no cliente errado. Gate pelo ini (DisconnectGuard=1).
 *
 * Melhorias liveness-aware (flag alive + discriminacao por estado da conexao):
 * credito a Maxicroma. Base original do filtro: projeto Open_LU4_login_serverlist_dll.
 *
 * Experimental, build-specific Disconnect caller filter. No remote thread.
 * Keep allocation until client exit, including after a failed target write:
 * an in-flight call may already reference it.
 */
#ifndef LU4_DISCONNECT_GUARD_H
#define LU4_DISCONNECT_GUARD_H
static int installDisconnectGuard(HANDLE process, unsigned long long base,
                                 unsigned long long *counterOut,
                                 unsigned long long *aliveOut) {
    /* prologo esperado do NetManager::Disconnect (base+0x4ce8c60), 15 bytes:
     * mov [rsp+8],rbx ; mov [rsp+18h],rbp ; mov [rsp+20h],rsi */
    static const unsigned char original[15] = {
        0x48,0x89,0x5c,0x24,0x08,0x48,0x89,0x6c,0x24,0x18,0x48,0x89,0x74,0x24,0x20
    };
    /* fingerprint do build em base+0x4d01a90: mov rax,[rip+0x36c7589]; ret */
    static const unsigned char getter[8] = {0x48,0x8b,0x05,0x89,0x75,0x6c,0x03,0xc3};
    /* trampolim (83 B). imm64 em +6 (caller), +25 (aliveFlag), +41 (counter);
     * 15 bytes originais em +54; ponteiro de resume em +75. jne/je saltam p/ +54 (.passa):
     *   mov rax,[rsp]; movabs r11,caller; cmp; jne .passa; test dl,dl; je .passa;
     *   movabs r11,alive; cmp byte[r11],0; je .passa; movabs r11,counter;
     *   lock inc [r11]; ret; .passa: <orig15>; jmp [resume] */
    unsigned char current[15], check[15], code[83] = {
        0x48,0x8b,0x04,0x24,                                /*  0 mov rax,[rsp]       */
        0x49,0xbb,0,0,0,0,0,0,0,0,                           /*  4 movabs r11,caller   */
        0x4c,0x39,0xd8,                                      /* 14 cmp rax,r11         */
        0x75,0x23,                                           /* 17 jne .passa (+0x23)  */
        0x84,0xd2,                                           /* 19 test dl,dl          */
        0x74,0x1f,                                           /* 21 je  .passa (+0x1f)  */
        0x49,0xbb,0,0,0,0,0,0,0,0,                           /* 23 movabs r11,alive    */
        0x41,0x80,0x3b,0x00,                                 /* 33 cmp byte [r11],0    */
        0x74,0x0f,                                           /* 37 je  .passa (+0x0f)  */
        0x49,0xbb,0,0,0,0,0,0,0,0,                           /* 39 movabs r11,counter  */
        0xf0,0x49,0xff,0x03,                                 /* 49 lock inc qword[r11] */
        0xc3,                                                /* 53 ret                 */
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,                       /* 54 .passa: orig 15 B   */
        0xff,0x25,0,0,0,0,                                   /* 69 jmp qword [rip+0]   */
        0,0,0,0,0,0,0,0                                      /* 75 resume (imm64)      */
    };
    /* desvio de 15 B no alvo: jmp qword ptr [rip+0]; <remote>; nop (preenche 15) */
    unsigned char patch[15] = {0xff,0x25,0,0,0,0};
    unsigned long long target=base+0x4ce8c60ULL, caller=base+0x915b3f3ULL;
    unsigned long long resume=target+15, remoteAddress, counter, alive;
    unsigned char one=1;
    SIZE_T count=0; DWORD old=0, unused=0; BOOL ok, restored;
    LPVOID remote;
    *counterOut=0; *aliveOut=0;
    /* passo 1: so' prossegue se for EXATAMENTE este build (getter + prologo) */
    if (!ReadProcessMemory(process,(LPCVOID)(uintptr_t)(base+0x4d01a90),check,8,&count) ||
        count!=8 || memcmp(check,getter,8)) return -1;
    if (!ReadProcessMemory(process,(LPCVOID)(uintptr_t)target,current,15,&count) ||
        count!=15 || memcmp(current,original,15)) return -2;
    /* passo 2: pagina 0 = trampolim (RX depois); pagina 1 (+4096) = contador(+0) + alive(+8) */
    remote=VirtualAllocEx(process,NULL,8192,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    if (!remote) return -3;
    remoteAddress=(unsigned long long)(uintptr_t)remote;
    counter=remoteAddress+4096;
    alive=remoteAddress+4096+8;
    /* passo 3: preenche os enderecos absolutos do trampolim */
    memcpy(code+6,&caller,8); memcpy(code+25,&alive,8); memcpy(code+41,&counter,8);
    memcpy(code+54,original,15);
    memcpy(code+75,&resume,8);            /* -> Disconnect+15 (segue a funcao) */
    if (!WriteProcessMemory(process,remote,code,sizeof(code),&count) || count!=sizeof(code) ||
        !VirtualProtectEx(process,remote,4096,PAGE_EXECUTE_READ,&unused) ||
        !FlushInstructionCache(process,remote,sizeof(code))) {
        VirtualFreeEx(process,remote,0,MEM_RELEASE);return -4;
    }
    /* a flag nasce 1 (viva): se o watchdog disparar antes do loader gerencia-la,
     * trata como viva (evita uma desconexao espuria na entrada do mundo). */
    WriteProcessMemory(process,(LPVOID)(uintptr_t)alive,&one,1,&count);
    /* passo 4: desvia o prologo do Disconnect p/ o trampolim (com verificacao) */
    memcpy(patch+6,&remoteAddress,8);patch[14]=0x90;
    if (!VirtualProtectEx(process,(LPVOID)(uintptr_t)target,15,PAGE_EXECUTE_READWRITE,&old)) {
        VirtualFreeEx(process,remote,0,MEM_RELEASE);return -5;
    }
    ok=WriteProcessMemory(process,(LPVOID)(uintptr_t)target,patch,15,&count) && count==15;
    if (ok) ok=ReadProcessMemory(process,(LPCVOID)(uintptr_t)target,check,15,&count) &&
               count==15 && !memcmp(check,patch,15);
    if (!ok) WriteProcessMemory(process,(LPVOID)(uintptr_t)target,original,15,NULL);
    restored=VirtualProtectEx(process,(LPVOID)(uintptr_t)target,15,old,&unused);
    if (!FlushInstructionCache(process,(LPCVOID)(uintptr_t)target,15)) return -8;
    if (!ok) return -6;
    if (!restored) return -7;
    /* passo 5: alocacao viva ate o cliente sair; flag gerenciada pelo loader */
    *counterOut=counter; *aliveOut=alive; return 1;
}
#endif
