# 격리 실측 ①(집 LAN 방식)용 부트스트랩 터널을 메인 PC 에 넣고 빼는 스크립트. 사용자가 직접 돌린다. PowerShell 5.1.
#
#   .\Test\bootstrap-tunnel.ps1 -SshHost <ssh 별칭> -Endpoint <미니PC LAN IP>:51820          첫 판 (AllowedIPs 10.183.26.1/32)
#   .\Test\bootstrap-tunnel.ps1 -SshHost <ssh 별칭> -Endpoint <미니PC LAN IP>:51820 -Wide    둘째 판 (AllowedIPs 10.183.26.0/24)
#   .\Test\bootstrap-tunnel.ps1 -Remove                                                       터널 서비스와 conf 파일 지우기
#   예: .\Test\bootstrap-tunnel.ps1 -SshHost minipc -Endpoint 192.168.1.10:51820
#
# 관리자가 아니면 같은 인자로 관리자 창을 다시 띄운다(UAC). 관리자 창도 같은 Windows 사용자로 돌기 때문에
# %USERPROFILE%\.ssh\config 의 별칭(-SshHost)과 키가 그대로 통한다. (UAC 에서 다른 관리자 계정 암호를 넣으면 안 통한다.)
# join.conf 의 값(부트스트랩 비밀키)은 화면에 찍지 않고 메모리에서만 다룬다. 미니PC 에 남는 임시 사본은 받자마자 지운다.
# -SshHost·-Endpoint 는 넣기에 꼭 준다 (기본값 없음). 미니PC 계정은 ssh 로 들어간 계정을 그대로 쓴다.
# 시험 : 함수만 쓰려면 dot-source 한다 (`. .\bootstrap-tunnel.ps1` — 본 흐름은 안 돈다).
param([string]$SshHost, [string]$Endpoint, [switch]$Wide, [switch]$Remove)

$TunnelName = 'bootstrap-test'
$ConfDir = Join-Path $env:ProgramData 'accesstool-test'
$ConfPath = Join-Path $ConfDir "$TunnelName.conf"   # 파일 이름이 곧 터널 이름이다
$WgExe = Join-Path $env:ProgramFiles 'WireGuard\wireguard.exe'

function ConvertFrom-JoinConf([string]$text) {
    $kv = @{}
    foreach ($line in ($text -split "`r?`n")) {
        if ($line -match '^\s*([a-z_0-9]+)\s*=\s*(.*?)\s*$') { $kv[$Matches[1]] = $Matches[2] }
    }
    foreach ($k in 'bootstrap_private_key', 'server_public_key') {
        if (-not $kv.ContainsKey($k)) { throw "join.conf 에 $k 가 없다" }
        # WireGuard 키는 base64 44자. 이 꼴만 받아 conf 줄 주입을 막는다
        if ($kv[$k] -notmatch '^[A-Za-z0-9+/]{43}=$') { throw "join.conf 의 $k 꼴이 이상하다 (base64 44자가 아니다)" }
    }
    $kv
}

function New-BootstrapConf($kv, [bool]$wide) {
    $allowed = if ($wide) { '10.183.26.0/24' } else { '10.183.26.1/32' }
    "[Interface]`r`nPrivateKey = $($kv['bootstrap_private_key'])`r`nAddress = 10.183.26.254/32`r`n`r`n" +
    "[Peer]`r`nPublicKey = $($kv['server_public_key'])`r`nEndpoint = $Endpoint`r`nAllowedIPs = $allowed`r`nPersistentKeepalive = 25`r`n"
}

function Invoke-Wg([string[]]$wgArgs) {
    $p = Start-Process $WgExe -ArgumentList $wgArgs -Wait -PassThru
    if ($p.ExitCode -ne 0) { throw "wireguard.exe $($wgArgs[0]) 실패 (종료 $($p.ExitCode))" }
}

function Get-TunnelService { Get-Service "WireGuardTunnel`$$TunnelName" -ErrorAction SilentlyContinue }

function Remove-Tunnel {
    if (-not (Get-TunnelService)) { return }
    Invoke-Wg @('/uninstalltunnelservice', $TunnelName)
    for ($i = 0; $i -lt 15 -and (Get-TunnelService); $i++) { Start-Sleep -Seconds 1 }
    if (Get-TunnelService) { throw "터널 서비스가 15초 안에 안 사라졌다" }
}

function Invoke-Main {
    $me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $a = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
        if ($SshHost) { $a += '-SshHost', $SshHost }
        if ($Endpoint) { $a += '-Endpoint', $Endpoint }
        if ($Wide) { $a += '-Wide' }
        if ($Remove) { $a += '-Remove' }
        Start-Process powershell -Verb RunAs -ArgumentList $a
        Write-Output '관리자 창에서 이어 간다.'
        return
    }
    if (-not (Test-Path $WgExe)) { throw "WireGuard 가 없다: $WgExe" }

    if ($Remove) {
        Remove-Tunnel
        Remove-Item -LiteralPath $ConfPath -Force -ErrorAction SilentlyContinue
        Write-Output "터널 $TunnelName 과 conf 를 지웠다."
        return
    }

    if (-not $SshHost -or $Endpoint -notmatch '^[A-Za-z0-9.-]+:[0-9]{1,5}$') {
        throw '-SshHost <ssh 별칭> -Endpoint <미니PC LAN IP>:51820 이 필요하다 (예: -SshHost minipc -Endpoint 192.168.1.10:51820)'
    }
    Write-Output '미니PC 에서 join.conf 를 임시로 복사한다. sudo 비밀번호를 넣는다.'
    try {
        ssh -t $SshHost 'sudo install -m 600 -o $(id -un) /var/lib/accesstool/join.conf ~/.join-test.conf'
        if ($LASTEXITCODE -ne 0) { throw "ssh sudo 복사 실패 (종료 $LASTEXITCODE)" }
        $text = (ssh $SshHost 'cat ~/.join-test.conf; rm -f ~/.join-test.conf') -join "`n"
        if ($LASTEXITCODE -ne 0) { throw "join.conf 받기 실패 (종료 $LASTEXITCODE)" }
    } finally {
        # 중간에 멈춰도 미니PC 에 비밀키 사본이 남지 않게 한 번 더 지운다
        ssh $SshHost 'rm -f ~/.join-test.conf'
        if ($LASTEXITCODE -ne 0) { Write-Warning '미니PC ~/.join-test.conf 를 지울 것 (자동 삭제 실패)' }
    }
    $conf = New-BootstrapConf (ConvertFrom-JoinConf $text) $Wide.IsPresent
    $text = $null

    # 폴더는 Administrators(S-1-5-32-544)·SYSTEM(S-1-5-18) 만. 상속을 끊는다
    New-Item -ItemType Directory -Force $ConfDir | Out-Null
    icacls $ConfDir /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls 실패 (종료 $LASTEXITCODE)" }
    [IO.File]::WriteAllText($ConfPath, $conf, (New-Object Text.UTF8Encoding($false)))   # BOM 없이
    $conf = $null

    Remove-Tunnel
    Invoke-Wg @('/installtunnelservice', "`"$ConfPath`"")
    for ($i = 0; $i -lt 15 -and (Get-TunnelService).Status -ne 'Running'; $i++) { Start-Sleep -Seconds 1 }
    $svc = Get-TunnelService
    if (-not $svc -or $svc.Status -ne 'Running') { throw "터널 서비스가 Running 이 아니다 ($(if ($svc) { $svc.Status } else { '없음' }))" }
    $svc | Format-Table Name, Status -AutoSize
    Test-NetConnection 10.183.26.1 -Port 7480 | Format-List RemoteAddress, RemotePort, TcpTestSucceeded   # 열림(True) 기대

    $mode = if ($Wide) { '둘째 판(/24)' } else { '첫 판(/32)' }
    Write-Output "$mode 터널을 넣었다. 다음 할 일:"
    Write-Output "  1. & '$PSScriptRoot\isolation-check.ps1'"
    if (-not $Wide) { Write-Output "  2. & '$PSScriptRoot\bootstrap-tunnel.ps1' -SshHost $SshHost -Endpoint $Endpoint -Wide 로 다시 넣고 1 을 한 번 더" }
    Write-Output "  끝나면 & '$PSScriptRoot\bootstrap-tunnel.ps1' -Remove"
}

if ($MyInvocation.InvocationName -ne '.') {
    try { Invoke-Main } catch { Write-Output "오류: $($_.Exception.Message)" }
    Read-Host '엔터를 누르면 창이 닫힌다'
}
