/*
 * lu4_disconnect_guard.h  --  Filtro seletivo de desconexao do lu4.bin (DisconnectGuard).
 *
 * ================================ O QUE RESOLVE ================================
 * O cliente lu4.bin (UE5, VMProtect) derruba a propria conexao depois de alguns
 * minutos PARADO, mesmo em localhost e com o servidor 100% saudavel. A queda nao
 * vem do servidor: eh uma rotina interna do cliente (instrumentacao do autor do
 * build) que, num tick do jogo, chama o NetManager::Disconnect e encerra a thread
 * de rede -> FIN. O servidor nunca pediu desconexao; o ring de pacotes fica limpo
 * ate o fim e o ping (S2C 0xd9 / C2S 0x03) eh respondido ate o ultimo segundo.
 *
 * Como esse Disconnect eh o MESMO usado por relog/logout legitimos, nao da pra
 * simplesmente NOP-ar o prologo da funcao -- isso quebraria sair do jogo. A saida
 * eh filtrar POR CHAMADOR: so' engolir a desconexao quando ela parte do call-site
 * do watchdog interno; qualquer outra origem (relog, logout, sair do mundo) passa
 * intacta.
 *
 * ============================ COMO FUNCIONA (de fora) =========================
 * Tudo eh feito de FORA do processo (VirtualAllocEx/WriteProcessMemory), sem DLL
 * injetada e sem thread remota, no mesmo espirito do "cave" do MAC do loader.
 *
 *  1. Fingerprint do build (abortar se nao casar):
 *     - le 8 bytes em base+0x4d01a90 e exige o getter conhecido
 *       (48 8b 05 89 75 6c 03 c3 = "mov rax,[rip+0x36c7589]; ret"). Se diferir,
 *       NAO eh este build -> retorna -1 e nao toca em nada. Isso impede aplicar
 *       os offsets num cliente diferente (onde escreveriam lixo).
 *     - le os 15 bytes do prologo do Disconnect (base+0x4ce8c60) e exige o
 *       original conhecido. Se diferir (ja patchado, ou build diferente) -> -2.
 *
 *  2. Aloca 2 paginas (8 KiB) no cliente:
 *     - pagina 0 (RX apos escrever): o trampolim (63 bytes).
 *     - pagina 1 (+4096): um contador qword de quantas desconexoes do watchdog
 *       foram engolidas (so' diagnostico; exposto via *counterOut p/ logar).
 *
 *  3. Monta o trampolim (PIC, enderecos absolutos preenchidos em runtime):
 *
 *        mov  rax, [rsp]            ; rax = endereco de retorno do chamador do Disconnect
 *        movabs r11, <caller>      ; caller = base+0x915b3f3 (call-site do watchdog)
 *        cmp  rax, r11
 *        jnz  .passa               ; chamador != watchdog -> deixa desconectar normal
 *        movabs r11, <counter>     ; chamador == watchdog:
 *        lock inc qword [r11]      ;   conta a tentativa...
 *        ret                       ;   ...e RETORNA JA' p/ o watchdog, pulando TODO
 *                                  ;   o corpo do Disconnect -> a queda eh engolida.
 *      .passa:                     ; (destino do jnz, 0x0f adiante)
 *        <15 bytes originais do prologo do Disconnect>
 *        jmp  [rip+0] -> <resume>  ; resume = Disconnect+15, segue a funcao de verdade
 *
 *     Chave do "seletivo": o Disconnect eh alcancado por um JMP (nao um CALL),
 *     entao [rsp] no topo ainda eh o retorno de QUEM chamou o Disconnect. Ao
 *     comparar esse retorno com o call-site do watchdog, distinguimos a chamada
 *     do kill-switch das chamadas legitimas sem olhar mais nada.
 *
 *  4. Reescreve o prologo do Disconnect com um desvio de 15 bytes:
 *        jmp qword ptr [rip+0]; <remote>   (6 bytes FF 25 00000000 + 8 do ponteiro)
 *        nop                                (1 byte, completa 15 e nao deixa meio-opcode)
 *     Com verificacao: le de volta e confere que gravou; se falhar, restaura o
 *     original. A protecao da pagina eh devolvida ao estado anterior e o
 *     InstructionCache eh invalidado nos dois lados.
 *
 *  5. A alocacao remota NAO eh liberada enquanto o cliente viver (nem em caso de
 *     escrita falha do alvo): uma chamada ao Disconnect pode ja estar "em voo"
 *     dentro do trampolim, e liberar derrubaria o processo. Sai tudo quando o
 *     cliente fecha.
 *
 * Observe que, ao contrario do patch do MAC (que o loader REMOVE ao entrar no
 * mundo p/ nao deixar rastro RWX), este guard eh instalado UMA vez na entrada do
 * mundo e MANTIDO ate o cliente sair -- eh ele que impede a queda durante o jogo.
 * O jmp fica num prologo de .text (nao numa pagina RWX orfã) e a pagina do
 * trampolim eh RX (nao RWX), reduzindo o que um anti-tamper veria.
 *
 * ============================== VALORES DE RETORNO ============================
 *   1  = instalado; *counterOut = endereco do contador no cliente.
 *  -1  = fingerprint do getter nao casou (build diferente): nao fez nada.
 *  -2  = prologo do Disconnect inesperado (ja patchado / build diferente): nada.
 *  -3  = VirtualAllocEx falhou.
 *  -4  = falha ao escrever/proteger/flush do trampolim (alocacao liberada).
 *  -5  = VirtualProtectEx do alvo falhou (alocacao liberada).
 *  -6  = escrita do alvo nao confirmou (restaurado o original).
 *  -7  = instalado, mas nao consegui devolver a protecao original da pagina.
 *  -8  = FlushInstructionCache do alvo falhou.
 *
 * Offsets (base-relativos) sao ESPECIFICOS deste build do lu4.bin; o fingerprint
 * do passo 1 eh o que impede aplica-los no cliente errado. Gate pelo ini
 * (DisconnectGuard=1); default 0.
 *
 * Experimental, build-specific Disconnect caller filter. No remote thread.
 * Keep allocation until client exit, including after a failed target write:
 * an in-flight call may already reference it.
 */
#ifndef LU4_DISCONNECT_GUARD_H
#define LU4_DISCONNECT_GUARD_H
static int installDisconnectGuard(HANDLE process, unsigned long long base,
                                 unsigned long long *counterOut) {
    /* prologo esperado do NetManager::Disconnect (base+0x4ce8c60), 15 bytes:
     * mov [rsp+8],rbx ; mov [rsp+18h],rbp ; mov [rsp+20h],rsi */
    static const unsigned char original[15] = {
        0x48,0x89,0x5c,0x24,0x08,0x48,0x89,0x6c,0x24,0x18,0x48,0x89,0x74,0x24,0x20
    };
    /* fingerprint do build em base+0x4d01a90: mov rax,[rip+0x36c7589]; ret */
    static const unsigned char getter[8] = {0x48,0x8b,0x05,0x89,0x75,0x6c,0x03,0xc3};
    /* trampolim (63 B). Os imm64 em +6 (caller) e +21 (counter), os 15 bytes
     * originais em +34 e o ponteiro de resume em +55 sao preenchidos abaixo:
     *   mov rax,[rsp]; movabs r11,caller; cmp rax,r11; jnz +0x0f(.passa);
     *   movabs r11,counter; lock inc [r11]; ret; .passa: <orig15>; jmp [resume] */
    unsigned char current[15], check[15], code[63] = {
        0x48,0x8b,0x04,0x24,0x49,0xbb,0,0,0,0,0,0,0,0,
        0x4c,0x39,0xd8,0x75,0x0f,0x49,0xbb,0,0,0,0,0,0,0,0,
        0xf0,0x49,0xff,0x03,0xc3
    };
    /* desvio de 15 B no alvo: jmp qword ptr [rip+0]; <remote>; nop (preenche 15) */
    unsigned char patch[15] = {0xff,0x25,0,0,0,0};
    unsigned long long target=base+0x4ce8c60ULL, caller=base+0x915b3f3ULL;
    unsigned long long resume=target+15, remoteAddress, counter;
    SIZE_T count=0; DWORD old=0, unused=0; BOOL ok, restored;
    LPVOID remote;
    *counterOut=0;
    /* passo 1: so' prossegue se for EXATAMENTE este build (getter + prologo) */
    if (!ReadProcessMemory(process,(LPCVOID)(uintptr_t)(base+0x4d01a90),check,8,&count) ||
        count!=8 || memcmp(check,getter,8)) return -1;
    if (!ReadProcessMemory(process,(LPCVOID)(uintptr_t)target,current,15,&count) ||
        count!=15 || memcmp(current,original,15)) return -2;
    /* passo 2: pagina 0 = trampolim (RX depois), pagina 1 (+4096) = contador */
    remote=VirtualAllocEx(process,NULL,8192,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    if (!remote) return -3;
    remoteAddress=(unsigned long long)(uintptr_t)remote;
    counter=remoteAddress+4096;
    /* passo 3: preenche os enderecos absolutos do trampolim */
    memcpy(code+6,&caller,8); memcpy(code+21,&counter,8);
    memcpy(code+34,original,15);
    code[49]=0xff;code[50]=0x25;          /* jmp qword ptr [rip+0] */
    memcpy(code+55,&resume,8);            /* -> Disconnect+15 (segue a funcao) */
    if (!WriteProcessMemory(process,remote,code,sizeof(code),&count) || count!=sizeof(code) ||
        !VirtualProtectEx(process,remote,4096,PAGE_EXECUTE_READ,&unused) ||
        !FlushInstructionCache(process,remote,sizeof(code))) {
        VirtualFreeEx(process,remote,0,MEM_RELEASE);return -4;
    }
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
    /* passo 5: a alocacao fica viva ate o cliente sair (chamada pode estar em voo) */
    *counterOut=counter;return 1;
}
#endif
