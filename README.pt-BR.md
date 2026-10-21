# LU4 Login / ServerList DLL + Launcher

**Idiomas:** [English](README.md) · **Português** · [Referência p/ LLM / agente](README.llm.md)

> **Branch `Cliente-18-10-2026`:** para o cliente `lu4.bin`, que loga com o loader sem DLL (veja
> [Loader sem DLL](#loader-sem-dll-lu4loader-cliente-de-18-10-2026)). Este branch não traz mais o
> `lu4authhook.dll`, o `inject.exe` nem o `Inject-LU4.ps1`; as seções de hook e injeção abaixo
> descrevem o branch `main`, onde eles continuam. O `lu4launcher` precisa da DLL e só funciona
> com os arquivos do `main`.

Ferramentas do **lado cliente** que permitem ao cliente do jogo **LU4** (um título baseado em
*Lineage 2* rodando na Unreal Engine 5.4) logar num **servidor privado / emulador** em vez dos
servidores de autenticação oficiais.

Inclui duas coisas:

1. **`lu4authhook.dll`** — uma DLL injetada no processo do jogo que
   - **valida login/senha contra o seu próprio servidor**, lendo as credenciais em texto puro na
     UI (antes de serem cifradas), e
   - **contorna a verificação de MAC da ServerList**, pra o seu AuthServer poder mandar uma lista
     de servidores dinâmica.
2. **Um launcher** (gráfico + console) que cria/guarda contas, inicia o cliente e injeta o hook
   num clique.

> ⚠️ **Escopo e aviso.** Isto é **ferramenta de interoperabilidade / emulação de servidor para
> servidores privados que você mesmo opera**, no espírito da antiga comunidade de *free shards*
> de L2. **Não** é bypass de anti-cheat e **não** derrota proteção de integridade do jogo — só
> mexe no handshake de login e na assinatura da lista de servidores. Use **apenas** com os seus
> servidores e a sua instalação do cliente, para estudo, preservação e desenvolvimento. **Não**
> use contra servidores oficiais/comerciais nem para violar os Termos de Serviço de ninguém ou a
> lei local. Você é responsável pelo uso.

---

## Por que isso existe

O cliente LU4 cifra o pacote de login com uma chave Blowfish estática **virtualizada pelo
VMProtect** — ela não é extraível, então um emulador não consegue verificar senhas do jeito
"normal" (o handshake acaba virando um *replay* de pacote que aceita qualquer senha). Além disso,
cada pacote de ServerList do auth carrega um **MAC de 32 bytes** assinado com um segredo que o
emulador não tem, então uma lista feita em casa é rejeitada.

Este projeto resolve os dois **no lado cliente**, de forma cirúrgica:

| Problema | Solução na `lu4authhook.dll` |
|---|---|
| Não dá pra verificar a senha no servidor | Capturar login/senha **na UI** e perguntar `OK/FAIL` ao seu servidor |
| O MAC da ServerList não pode ser forjado | Trocar o compare pra um valor **MAGIC** conhecido contar como MAC válido |

O "raio de impacto" é mínimo: só a chamada de login e o compare de 32 bytes da lista são
tocados; todo o resto do cliente roda byte-a-byte como antes.

---

## Como funciona

### Hook 1 — captura e validação do login
- **Ponto de hook:** `ConnectToLoginServer` no RVA `0x4BB1850`,
  assinatura `void __fastcall(this, FString* login /*rdx*/, FString* senha /*r8*/)`.
  Um `FString` é `{ TCHAR* Data; int32 Num; int32 Max }` em UTF-16LE.
- O hook lê as duas strings e abre um socket TCP para o **validador**, enviando:
  ```
  AUTH\t<login>\t<senha>\n
  ```
  e espera `OK` (libera) ou `FAIL` (nega). Liberando, chama a função original (o login segue com
  aquela conta); negando, mostra *"Login ou senha incorretos."* e bloqueia.
- **Fail-open:** se o validador estiver inacessível, o hook **libera** o login (pro cliente nunca
  travar num validador morto). Inverta o padrão em `validar()` pra fail-closed.
- Pra evitar corrida com o auto-login do launcher (o cliente pode auto-logar *antes* do hook
  instalar), a DLL também lê `-ID`/`-PWD` da própria linha de comando no install e valida dali.

### Hook 2 — bypass do MAC da ServerList
- **Ponto de hook:** um compare de tempo constante no RVA `0xBFEEA0`,
  `__int64 __fastcall(buf1 rcx, buf2 rdx, len r8)` → `0` quando iguais.
- É substituído inteiro por uma versão que faz o **mesmo** compare byte-a-byte, exceto: quando
  `len == 32` e um dos buffers é igual ao MAGIC
  `LU4-MAGIC-SERVERLIST-MAC-BYPASS!`, retorna `0` (iguais). O seu AuthServer põe esse MAGIC no
  lugar onde iria o MAC real de 32 bytes, e o cliente aceita a sua lista dinâmica.

### Launcher
- **`lu4launcher_gui.exe`** — janela Win32 tema escuro: escolher/salvar/remover contas e clicar
  **JOGAR**. As contas ficam em `lu4accounts.dat` ao lado do exe (senha com ofuscação XOR —
  ofuscação leve, **não** é segurança).
- **`lu4launcher.exe`** — versão console (pede login/senha, ou lê de args/ini).
- Ao iniciar, ambos: (opcional, dev local) montam loopback + portproxy, iniciam o cliente com
  `LU4 -USEALLAVAILABLECORES -ID <login> -PWD <senha>`, esperam ~1,2 s e injetam a
  `lu4authhook.dll` via `LoadLibraryW` remoto.

### Loader sem DLL (`lu4loader`, cliente de 18-10-2026)
Para o build **`lu4.bin`** do cliente. Nada é injetado, e o launcher oficial (com o módulo
`clmods64` que ele carrega) não é usado.
- **`lu4loader_gui.exe`** — janela com contas salvas (`lu4loader_accounts.dat`, senha ofuscada com
  XOR, **não** é segurança). **`lu4loader.exe`** — versão de console.
- O que faz: pega login/senha (`--id`/`--pwd`, `lu4loader.ini`, ou pergunta); no dev local monta o
  loopback + portproxy; inicia o `lu4.bin` direto com `LU4 -USEALLAVAILABLECORES` (mais `-ID`/`-PWD`
  quando `AutoFillLogin=1`); espera o cliente carregar (working set acima de `WaitMB`); desvia a
  comparação de 32 bytes da serverlist para um pequeno code cave que aceita o marcador de MAC do
  servidor; manda `AUTH	<login>	<senha>
` para o validador de credenciais do servidor
  (porta 27110) e o renova enquanto a janela estiver aberta.
- **Precisa de um servidor compatível.** O servidor tem que mandar o Init de 37 bytes do `lu4.bin`,
  que faz o cliente instalar a chave Blowfish de sessão que o servidor espera (`kInitHex` do
  AuthGateD em [Open_LU4_L2OFF, branch `Cliente-18-10-2026`](https://github.com/luannbr/Open_LU4_L2OFF/tree/Cliente-18-10-2026),
  `AuthGateD/src/Lu4Login.cpp`). Sem ele o login decifra lixo, com ou sem loader. O servidor também
  precisa do AuthD com `Lu4Mode=true` e o validador na 27110 (credenciais reaproveitáveis dentro do
  TTL, para relogar sem reabrir o cliente) e da porta de login LU4 (2107) alcançável a partir de
  `LoginIp:LoginPort`.
- Config: copie `dist/lu4loader.ini.example` para `lu4loader.ini` ao lado do exe. Nunca comite.
- Compilar: `src/build_lu4loader.bat` (as duas versões).
- Estado: login verificado de ponta a ponta com o protótipo em Python deste loader; a versão em C é
  um porte dele, com os mesmos bytes de patch e a mesma mensagem ao validador.

---

## Requisitos

- **Windows x64.**
- Um **build do cliente LU4** compatível — os RVAs acima são específicos de um build do
  `lu4-win64-shipping.exe` (ver [RVAs](#os-rvas-são-específicos-do-build)).
- O **seu lado servidor** precisa implementar o contrato abaixo (este repo é só cliente).
- Para **compilar:** Visual Studio 2022 (C/C++, x64 — `vcvars64.bat`).
- **Admin** só é necessário pro setup de rede do dev local (`LocalDev=1`).

---

## Contrato do lado servidor (o que o seu emulador precisa oferecer)

Este repo **não** contém o servidor. Qualquer emulador de auth/game compatível (por ex. um
servidor estilo L2J/Lucera) precisa oferecer:

1. **Um validador** escutando em `127.0.0.1:27110` (configurável) que fala o protocolo de linha:
   - recebe `AUTH\t<login>\t<senha>\n`
   - responde `OK` (ou `OK ...`) pra liberar, `FAIL` (ou `FAIL ...`) pra negar.
   - (Implementação típica: hash whirlpool2 comparado com a tabela `accounts`, auto-criar opcional.)
2. **Uma lista de servidores do AuthServer** que escreve o MAGIC de 32 bytes
   `LU4-MAGIC-SERVERLIST-MAC-BYPASS!` no lugar do MAC real por pacote. O Hook 2 então aceita, e
   você serve uma lista dinâmica dos **seus** servidores, com nomes reais.

---

## Instalar e usar (usuário final)

1. Coloque `lu4launcher_gui.exe` (e `lu4launcher.exe`), `lu4authhook.dll`, `inject.exe` e
   `Inject-LU4.ps1` da pasta **`dist/`** na pasta do seu cliente (ao lado do diretório `lu4\`).
2. Copie `lu4launcher.ini.example` para `lu4launcher.ini` e edite (IP/portas do servidor, ou só
   os defaults pro dev local). **Nunca comite o seu `lu4launcher.ini` real.**
3. Garanta que o **seu servidor + validador** estão no ar.
4. Rode `lu4launcher_gui.exe`, adicione uma conta e clique **JOGAR**.
   - Com `LocalDev=1`, rode o launcher **como Administrador** na primeira vez (ele adiciona o
     alias de loopback + portproxy via `netsh`).

### Injeção manual (sem o launcher)
Abra o cliente, fique na tela de login e então:
```powershell
powershell -ExecutionPolicy Bypass -File dist\Inject-LU4.ps1
```
O `Inject-LU4.ps1` acha o processo do **jogo** (`lu4-win64-shipping.exe` sem `--type=`, o de
maior working set — ou seja, não os filhos CEF da UI) e roda `inject.exe <pid> lu4authhook.dll`.

---

## Configuração (`lu4launcher.ini`)

| Chave | Default | Significado |
|---|---|---|
| `GameExe` | `lu4\binaries\win64\lu4-win64-shipping.exe` | executável do cliente (relativo ou absoluto) |
| `HookDll` | `lu4authhook.dll` | caminho da DLL do hook |
| `GameArgs` | `LU4 -USEALLAVAILABLECORES` | args passados ao cliente |
| `Login` / `Pass` | *(vazio)* | opcional; se preenchidos, o launcher console não pergunta (**não comitar**) |
| `LocalDev` | `1` | `1` = monta loopback+portproxy (precisa Admin); `0` = conecta direto num IP real |
| `LoginIp` | `185.29.255.102` | IP que o cliente conecta (um alias de loopback no dev) |
| `LoginPort` | `2108` | porta do cliente |
| `AuthPort` | `2107` | porta do seu AuthServer (destino do portproxy no dev) |

---

## Compilar do fonte

```bat
:: DLL do hook (x64)
src\build_hook.bat
:: ou direto:
cl /nologo /LD /O2 /EHsc /std:c++17 src\lu4authhook.cpp /Fe:lu4authhook.dll ^
   /link ws2_32.lib user32.lib

:: injetor
cl /nologo /O2 /EHsc src\inject.cpp /Fe:inject.exe

:: launcher (console + GUI)
src\build_launcher.bat
```
Os `build_*.bat` chamam o `vcvars64.bat` de um caminho padrão do VS2022 — ajuste pro seu.

---

## Os RVAs são específicos do build

Os offsets estão amarrados a **um** build do `lu4-win64-shipping.exe`. Se o cliente atualizar,
re-localize antes de usar a DLL:

- **Login** `0x4BB1850` — prólogo esperado:
  `48 89 5C 24 08 57 48 83 EC 20 83 7A 08 01`
- **Compare da ServerList** `0xBFEEA0` — uma função pequena e autocontida, estilo `memcmp` de
  tempo constante.

Edite `LOGIN_RVA` / `CMP_RVA` em `src/lu4authhook.cpp` e recompile.

---

## Arquivos

```
dist/
  lu4launcher_gui.exe     launcher gráfico (contas, jogar num clique)
  lu4launcher.exe         launcher console
  lu4launcher.ini.example modelo de config (copie para lu4launcher.ini)
  lu4loader_gui.exe       loader sem DLL para o lu4.bin, gráfico (cliente de 18-10-2026)
  lu4loader.exe           loader sem DLL, console
  lu4loader.ini.example   modelo de config do loader (copie para lu4loader.ini)
src/
  lu4launcher.c           fonte do launcher console
  lu4launcher_gui.c       fonte do launcher gráfico
  build_launcher.bat      compila os dois launchers
  lu4loader.c             fonte do loader sem DLL, console
  lu4loader_gui.c         fonte do loader sem DLL, gráfico
  build_lu4loader.bat     compila as duas versões do loader
```

## Notas de segurança

- A senha é lida em texto puro no cliente e enviada ao validador. Na mesma máquina ela fica em
  `127.0.0.1`. Pra um servidor **remoto**, o validador escutaria num IP público e a senha
  trafegaria em claro — coloque TLS antes de fazer isso.
- O `lu4accounts.dat` usa ofuscação XOR trivial, não criptografia. Trate como texto puro.
- Injetar DLL e rodar um cliente modificado pode disparar anti-cheat em builds protegidos. Use só
  num cliente de desenvolvimento/teste sem proteção.

## Licença

Ainda não há licença definida — até adicionar uma, vale o copyright padrão (todos os direitos
reservados). Adicione um arquivo `LICENSE` (ex. MIT) se quiser que outros reutilizem livremente.
