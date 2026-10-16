# Inject-LU4.ps1 — injeta lu4authhook.dll no processo do JOGO (nao o CEF renderer).
#
# O cliente LU4 sobe varios processos "lu4-win64-shipping.exe": o do jogo (com a UI
# de login e a funcao ConnectToLoginServer) e os do CEF (renderizador da UI web),
# que tem "--type=" na linha de comando. Injetamos so no do jogo.
#
# Uso:  powershell -ExecutionPolicy Bypass -File Inject-LU4.ps1
#       (opcional)  -Wait   espera o cliente aparecer se ainda nao subiu

param(
    [switch]$Wait
)

$ErrorActionPreference = "Stop"
$here   = Split-Path -Parent $MyInvocation.MyCommand.Definition
$inject = Join-Path $here "inject.exe"
$dll    = Join-Path $here "lu4authhook.dll"

if (-not (Test-Path $inject)) { Write-Host "[!] inject.exe nao encontrado" -ForegroundColor Red; exit 1 }
if (-not (Test-Path $dll))    { Write-Host "[!] lu4authhook.dll nao encontrada" -ForegroundColor Red; exit 1 }

function Find-GameProcess {
    $procs = Get-CimInstance Win32_Process -Filter "Name='lu4-win64-shipping.exe'" -ErrorAction SilentlyContinue
    if (-not $procs) { return $null }
    # o processo do jogo NAO tem "--type=" (isso e' dos processos filhos do CEF)
    $candidatos = $procs | Where-Object { $_.CommandLine -and ($_.CommandLine -notmatch '--type=') }
    if (-not $candidatos) { return $null }
    # se houver mais de um, o jogo e' o de maior memoria (Working Set)
    $best = $candidatos |
        Sort-Object { (Get-Process -Id $_.ProcessId -ErrorAction SilentlyContinue).WorkingSet64 } -Descending |
        Select-Object -First 1
    return $best
}

$game = Find-GameProcess
if (-not $game -and $Wait) {
    Write-Host "Aguardando o cliente LU4 subir..." -ForegroundColor Yellow
    for ($i = 0; $i -lt 60 -and -not $game; $i++) {
        Start-Sleep -Seconds 1
        $game = Find-GameProcess
    }
}
if (-not $game) {
    Write-Host "[!] Processo do jogo (lu4-win64-shipping.exe) nao encontrado." -ForegroundColor Red
    Write-Host "    Abra o cliente e tente de novo (ou use -Wait)." -ForegroundColor Yellow
    exit 1
}

Write-Host "[*] Processo do jogo: PID $($game.ProcessId)" -ForegroundColor Cyan
Write-Host "[*] Injetando $dll ..." -ForegroundColor Cyan
& $inject $game.ProcessId $dll
$rc = $LASTEXITCODE
if ($rc -eq 0) {
    Write-Host "[+] Hook instalado. Faca login normalmente; a senha sera validada." -ForegroundColor Green
} else {
    Write-Host "[!] Injecao falhou (codigo $rc)." -ForegroundColor Red
}
exit $rc
