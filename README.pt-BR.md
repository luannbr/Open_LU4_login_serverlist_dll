# LU4 Loader — login sem DLL (cliente de 18-10-2026)

**Idiomas:** [English](README.md) · **Português** · [Referência p/ LLM / agente](README.llm.md)

> **Branch `Cliente-18-10-2026`.** Este branch tem só o **`lu4loader`**, o loader sem DLL para o
> cliente **`lu4.bin`**. O sistema anterior para o `lu4-win64-shipping.exe` (`lu4authhook.dll`, o
> injetor e o `lu4launcher`) está no branch
> [`main`](https://github.com/luannbr/Open_LU4_login_serverlist_dll/tree/main).

Ferramentas do **lado cliente** que permitem ao cliente do jogo **LU4** (um título baseado em
*Lineage 2* rodando na Unreal Engine 5.4) logar num **servidor privado / emulador** em vez dos
servidores de autenticação oficiais — **sem injetar nenhuma DLL** no jogo.

Inclui uma ferramenta em duas versões:

1. **`lu4loader_gui.exe`** — janela com contas salvas: escolha a conta e clique em **JOGAR**.
2. **`lu4loader.exe`** — o mesmo loader como programa de console (args, ini ou pergunta).

As duas iniciam o cliente, aplicam um pequeno patch de fora do processo (a checagem da assinatura
da ServerList) e entregam a conta ao validador de credenciais do seu servidor.

> ⚠️ **Escopo e aviso.** Isto é **ferramenta de interoperabilidade / emulação para servidores
> privados que você mesmo opera**, no espírito da antiga comunidade de free-shards de L2. Use
> **só** com os seus servidores e a sua instalação do cliente, para estudo, preservação e
> desenvolvimento. **Não** use contra servidores oficiais/comerciais nem para violar Termos de
> Serviço ou leis. O uso é responsabilidade sua.

---

## Por que isso existe

Duas coisas impedem o cliente LU4 de logar num emulador:

- Toda resposta do servidor de login leva uma **assinatura Ed25519 de 32 bytes**, feita com a chave
  privada do servidor oficial. Um emulador não consegue gerá-la, então uma lista de servidores
  própria é rejeitada.
- O pacote de login é cifrado com uma **chave Blowfish de sessão** que o cliente tira do pacote
  Init do servidor, e o bloco da conta dentro dele não pode ser lido pelo servidor.

O branch `main` resolvia isso com uma DLL injetada no `lu4-win64-shipping.exe`. O cliente
`lu4.bin` de 18-10-2026 é atendido sem DLL nenhuma:

| Problema | Solução |
|---|---|
| A assinatura da ServerList não pode ser forjada | O loader desvia a comparação de 32 bytes para um code cave que aceita um marcador **MAGIC** conhecido |
| O servidor não lê a conta no pacote de login | O próprio loader manda login/senha ao validador do seu servidor |
| Chave Blowfish de sessão | Lado servidor: um Init de 37 bytes que faz o `lu4.bin` instalar a chave que o servidor espera |

O patch mexe só na comparação de 32 bytes; todas as outras comparações do cliente seguem byte a
byte como antes.

---

## Como funciona

### 1. Iniciar o cliente
- Login/senha vêm de `--id`/`--pwd`, senão do `lu4loader.ini`, senão o loader pergunta (o GUI usa
  as contas salvas). São obrigatórios: o servidor precisa recebê-los do loader.
- Com `LocalDev=1` (e Admin) ele monta a rede local com `netsh`: alias de loopback
  `LoginIp/255.255.255.255`, portproxy `0.0.0.0:LoginPort → 127.0.0.1:AuthPort` e
  `LoginIp:LoginPort → 127.0.0.1:AuthPort`.
- Inicia o `lu4.bin` **direto** (não pelo launcher oficial, que também carrega o módulo
  `clmods64`) com `GameArgs` (`LU4 -USEALLAVAILABLECORES`), mais `-ID <login> -PWD <senha>` quando
  `AutoFillLogin=1`, para o cliente preencher o formulário de login.

### 2. Validação da assinatura da ServerList (patch tardio)
- Espera o cliente carregar (working set acima de `WaitMB`, padrão 1500 MB, até 2 min) e pega a
  base do módulo.
- A comparação no RVA **`0xBFEEA0`** (`__int64 __fastcall(buf1 rcx, buf2 rdx, len r8)`, `0` quando
  iguais) só fica legível depois que o protetor decifra a página dela. O loader espera o prólogo
  ser `48 31 C0 4D 31 D2` e então:
  - aloca um code cave de 63 bytes no cliente (`VirtualAllocEx`, RWX);
  - escreve um `jmp [rip+0]` de 14 bytes na comparação, apontando para o cave.
- O cave devolve *igual* quando `len == 32` e um dos buffers começa com `LU4-MAGI` (o marcador
  `LU4-MAGIC-SERVERLIST-MAC-BYPASS!` que o seu servidor escreve no lugar da assinatura); fora isso
  compara byte a byte (`0` iguais, `1` diferentes), exatamente como a original.
- Enquanto o cliente roda, o loader reaplica o `jmp` se o prólogo original voltar.

### 3. Ponte de credenciais
- Logo depois do patch ele abre uma conexão TCP com o validador (`ValidatorHost:ValidatorPort`,
  padrão `127.0.0.1:27110`) e manda:
  ```
  AUTH\t<login>\t<senha>\n
  ```
  Resposta começando com `OK` = aceito; qualquer outra aparece como rejeitada.
- O servidor guarda esse par para o IP do cliente e usa quando o login chega. O loader manda de
  novo a cada 2 minutos enquanto a janela dele estiver aberta, então o par não expira.
- Deixe a janela do loader aberta durante o login.

### 4. DisconnectGuard — anti-queda por ociosidade (opcional, `DisconnectGuard=1`)
- **Sintoma:** parado alguns minutos (mesmo em localhost, com o servidor saudável), o `lu4.bin`
  **derruba a própria conexão**. Não é o servidor — o ring de pacotes fica limpo e o ping é
  respondido até o fim. É uma rotina interna (watchdog) do build do cliente que chama o próprio
  `Disconnect`.
- Como o mesmo `Disconnect` é usado por relog/logout legítimos, não dá pra NOP-ar a função. Com
  `DisconnectGuard=1`, ao entrar no mundo o loader instala de fora um **filtro seletivo** no
  `Disconnect` do cliente (`base+0x4ce8c60`), sem DLL e sem thread remota:
  - desvia o prólogo pra um pequeno trampolim (alocado com `VirtualAllocEx`);
  - o trampolim compara o endereço de retorno (`[rsp]`) com o call-site do watchdog
    (`base+0x915b3f3`): se **for** o watchdog, conta e faz `ret` imediato — a desconexão é
    engolida; se for **qualquer outra** origem (relog, logout), executa o prólogo original e segue
    normal.
- **Segurança:** antes de tocar em nada ele confere um *fingerprint* do build (um getter em
  `base+0x4d01a90`) e o prólogo esperado do `Disconnect`; em outro build ele **não instala** e loga
  o motivo (não corrompe nada). Os RVAs são específicos deste `lu4.bin`.
- Ao contrário do patch do MAC (removido ao entrar no mundo), o guard é **mantido** enquanto o
  cliente roda — é ele que segura a conexão. O resultado vai pro `lu4loader.log`
  (`DISCONNECT_GUARD ... result=1`) e, no GUI, pro status da janela. Detalhes byte a byte em
  `src/lu4_disconnect_guard.h`.

---

## Requisitos

- **Windows x64.**
- O build **`lu4.bin`** do cliente de 18-10-2026 — o RVA é específico dele (veja
  [RVAs](#os-rvas-são-específicos-do-build)).
- **Um servidor que implemente o contrato abaixo** — este repo é só do lado cliente.
- Para **compilar do fonte:** Visual Studio 2022 (C, x64 — `vcvars64.bat`).
- **Admin** só é necessário para o setup de rede do dev local (`LocalDev=1`).

---

## Contrato do lado servidor (o que o seu emulador precisa oferecer)

Este repo **não** contém o servidor. O servidor de referência é o
[Open_LU4_L2OFF, branch `Cliente-18-10-2026`](https://github.com/luannbr/Open_LU4_L2OFF/tree/Cliente-18-10-2026).
Qualquer servidor usado com este loader precisa oferecer:

1. **O Init de 37 bytes do `lu4.bin`** (no Open_LU4_L2OFF: `kInitHex` em
   `AuthGateD/src/Lu4Login.cpp`). O `lu4.bin` lê a chave Blowfish de sessão nos bytes 21..36 dessa
   mensagem; o servidor tem que decifrar com a mesma chave. **Sem ele o login decifra lixo, com ou
   sem o loader.**
2. **Uma ServerList com o marcador MAGIC** — os 32 bytes `LU4-MAGIC-SERVERLIST-MAC-BYPASS!` onde
   vai a assinatura real, para a comparação desviada aceitar a sua lista.
3. **Um validador de credenciais** em TCP `27110` (configurável) com o protocolo de linha:
   - recebe `AUTH\t<login>\t<senha>\n`;
   - responde `OK` (ou `OK ...`) para aceitar, qualquer outra coisa para rejeitar;
   - guarda o par aceito para o IP de quem mandou e o entrega ao login vindo desse IP. No
     Open_LU4_L2OFF isso é o AuthD com `Lu4Mode=true`; o par vale durante todo o TTL, então dá
     para relogar sem reabrir o cliente.
4. **A porta de login LU4** (AuthGateD `lu4Port`, padrão `2107`) alcançável a partir de
   `LoginIp:LoginPort` — pelo portproxy no dev local, ou direto em produção.

---

## Instalar e usar (usuário final)

1. Coloque `lu4loader_gui.exe` (e/ou `lu4loader.exe`) de **`dist/`** na pasta do cliente (ao lado
   da pasta `lu4\`).
2. Copie `lu4loader.ini.example` para `lu4loader.ini` e edite (IP/portas do servidor, ou só os
   defaults pro dev local). **Nunca comite o seu `lu4loader.ini` real.**
3. Garanta que o **servidor + validador** estão rodando.
4. Rode o `lu4loader_gui.exe`, adicione uma conta e clique em **JOGAR**.
   - Com `LocalDev=1`, rode o loader **como Administrador** (ele cria o alias de loopback + o
     portproxy com `netsh`).
   - No console: `lu4loader.exe` ou `lu4loader.exe --id <login> --pwd <senha>`.
5. Deixe a janela do loader aberta até entrar no jogo.

---

## Configuração (`lu4loader.ini`)

| Chave | Padrão | Significado |
|---|---|---|
| `GameExe` | `lu4\binaries\win64\lu4.bin` | executável do cliente (relativo ao loader, ou absoluto) |
| `GameArgs` | `LU4 -USEALLAVAILABLECORES` | argumentos passados ao cliente |
| `Login` / `Pass` | *(vazio)* | opcional; se preenchido, o loader de console não pergunta (**não comite**) |
| `AutoFillLogin` | `1` | `1` = passa `-ID`/`-PWD` para o cliente preencher o login; `0` = você digita no jogo |
| `LocalDev` | `1` | `1` = monta loopback+portproxy (precisa Admin); `0` = conecta direto num IP real |
| `LoginIp` | `185.29.255.102` | IP ao qual o cliente conecta (um alias de loopback no dev) |
| `LoginPort` | `2108` | porta do cliente |
| `AuthPort` | `2107` | porta LU4 do seu AuthGateD (destino do portproxy no dev) |
| `ValidatorHost` | `127.0.0.1` | host do validador de credenciais |
| `ValidatorPort` | `27110` | porta do validador de credenciais |
| `GamePort` | `7778` | porta do GameServer; conexão TCP estabelecida nela = "em jogo" |
| `DisconnectGuard` | `0` | `1` = instala o filtro anti-queda por ociosidade ao entrar no mundo (veja a seção 4) |
| `WaitMB` | `1500` | working set do cliente (MB) a esperar antes do patch |

O GUI guarda as contas em `lu4loader_accounts.dat` ao lado do exe (uma linha
`login<TAB>senha` por conta, senha ofuscada com XOR — **não** é segurança).

---

## Compilar do fonte

```bat
:: console + GUI
src\build_lu4loader.bat
:: ou direto:
cl /nologo /O2 /W3 /D_CRT_SECURE_NO_WARNINGS src\lu4loader.c /Fe:lu4loader.exe ^
   /link user32.lib advapi32.lib shell32.lib psapi.lib ws2_32.lib iphlpapi.lib
cl /nologo /O2 /W3 /D_CRT_SECURE_NO_WARNINGS src\lu4loader_gui.c /Fe:lu4loader_gui.exe ^
   /link user32.lib gdi32.lib advapi32.lib shell32.lib comctl32.lib psapi.lib ws2_32.lib iphlpapi.lib
```
O `build_lu4loader.bat` chama o `vcvars64.bat` num caminho padrão do VS2022 — ajuste para a sua
instalação. O manifesto de Common Controls do GUI vai embutido por `#pragma`, então não precisa
de arquivo `.manifest`.

---

## Os RVAs são específicos do build

O offset está amarrado a **um** build do `lu4.bin`. Se o cliente atualizar, ache de novo antes de
usar o loader:

- **Comparação da ServerList** `0xBFEEA0` — uma pequena função de comparação em tempo constante,
  estilo `memcmp`; prólogo esperado depois de decifrada: `48 31 C0 4D 31 D2`
  (`xor rax,rax; xor r10,r10`).

Edite `CMP_RVA` (e `ORIG` se o prólogo mudar) **nos dois** fontes, `src/lu4loader.c` e
`src/lu4loader_gui.c`, e recompile.

---

## Estado

O login foi verificado de ponta a ponta com o protótipo em Python deste loader. As versões em C
são um porte dele, com os mesmos bytes de patch e a mesma mensagem ao validador.

---

## Arquivos

```
dist/
  lu4loader_gui.exe       loader gráfico (contas, jogar num clique)
  lu4loader.exe           loader de console
  lu4loader.ini.example   modelo de config (copie para lu4loader.ini)
src/
  lu4loader.c             fonte do loader de console
  lu4loader_gui.c         fonte do loader gráfico
  lu4_disconnect_guard.h  filtro anti-queda por ociosidade (DisconnectGuard; incluído pelos dois)
  build_lu4loader.bat     compila os dois
```

## Notas de segurança

- A senha vai para o validador em texto puro. Na mesma máquina ela fica em `127.0.0.1`. Para um
  servidor **remoto**, o validador escutaria num IP público e a senha trafegaria aberta — ponha
  TLS antes de fazer isso.
- `-ID`/`-PWD` põem a senha na linha de comando do cliente, visível para outros processos locais.
  Use `AutoFillLogin=0` se isso importar.
- `lu4loader_accounts.dat` usa ofuscação XOR trivial, não criptografia. Trate como texto puro.
- Nunca comite `lu4loader.ini` nem `lu4loader_accounts.dat` (os dois estão no `.gitignore`).
- Mexer na memória de um cliente pode disparar anti-cheat em ambientes protegidos. Use só com o
  seu cliente e o seu servidor.

## Licença

Veja [LICENSE](LICENSE).
