# 친구에게 보낼 가입 zip(homegames-join.exe + join.conf)을 다운로드 폴더에 만든다. 사용자가 직접 돌린다. PowerShell 5.1, 관리자 필요 없음.
#
#   .\Test\make-friend-zip.ps1 -SshHost <ssh 별칭>   → 다운로드\HomeGames-가입.zip (sudo 비밀번호를 한 번 넣는다)
#   예: .\Test\make-friend-zip.ps1 -SshHost minipc
#
# zip 에는 부트스트랩 비밀키가 들어 있다. 그래서 저장소 안에는 만들지 않고, join.conf 내용은 화면에 찍지 않는다.
# -SshHost 는 꼭 준다 (기본값 없음). 미니PC 계정은 ssh 로 들어간 계정을 그대로 쓴다.
# 시험 : 함수만 쓰려면 dot-source 한다 (`. .\make-friend-zip.ps1` — 본 흐름은 안 돈다).
param([string]$SshHost)

$ExePath = Join-Path $PSScriptRoot '..\bin\homegames-join.exe'
# 바탕화면은 OneDrive 로 동기화될 수 있어 다운로드 폴더에 둔다
$ZipPath = Join-Path (New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path 'HomeGames-가입.zip'

function Test-JoinConf([string]$text) {
    $kv = @{}
    foreach ($line in ($text -split "`r?`n")) {
        if ($line -match '^\s*([a-z_0-9]+)\s*=\s*(.*?)\s*$') { $kv[$Matches[1]] = $Matches[2] }
    }
    foreach ($k in 'bootstrap_private_key', 'server_public_key') {
        if (-not $kv.ContainsKey($k)) { throw "join.conf 에 $k 가 없다" }
        # WireGuard 키는 base64 44자
        if ($kv[$k] -notmatch '^[A-Za-z0-9+/]{43}=$') { throw "join.conf 의 $k 꼴이 이상하다 (base64 44자가 아니다)" }
    }
    if (-not $kv['endpoint']) { throw 'join.conf 에 endpoint 가 없다' }
}

function New-FriendZip([byte[]]$bytes, [string]$exe, [string]$zip) {
    Test-JoinConf ([Text.Encoding]::UTF8.GetString($bytes))
    $tmp = Join-Path $env:TEMP ('friendzip-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory $tmp | Out-Null
    try {
        # 받은 바이트를 그대로 쓴다
        [IO.File]::WriteAllBytes((Join-Path $tmp 'join.conf'), $bytes)
        Copy-Item -LiteralPath $exe -Destination (Join-Path $tmp 'homegames-join.exe')
        Compress-Archive -Path (Join-Path $tmp '*') -DestinationPath $zip -Force
    } catch {
        # 반쯤 쓴 zip 을 남기지 않는다
        Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue
        throw
    } finally {
        Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-Main {
    if (-not (Test-Path -LiteralPath $ExePath)) {
        throw "친구 exe 가 없다: $ExePath`n먼저 저장소 루트에서 빌드한다:`n  `$env:GOOS='windows'; `$env:GOARCH='amd64'; `$env:CGO_ENABLED='0'; go build -o bin/homegames-join.exe ./cmd/homegames-join"
    }
    if ($env:OneDrive -and $ZipPath.StartsWith($env:OneDrive, [StringComparison]::OrdinalIgnoreCase)) { throw "zip 자리가 OneDrive 아래다 (비밀키가 클라우드로 올라간다): $ZipPath" }

    if (-not $SshHost) { throw '-SshHost <ssh 별칭> 이 필요하다 (예: -SshHost minipc)' }

    Write-Output '미니PC 에서 join.conf 를 임시로 복사한다. sudo 비밀번호를 넣는다.'
    try {
        ssh -t $SshHost 'sudo install -m 600 -o $(id -un) /var/lib/accesstool/join.conf ~/.join-zip.conf'
        if ($LASTEXITCODE -ne 0) { throw "ssh sudo 복사 실패 (종료 $LASTEXITCODE)" }
        # 콘솔 코드페이지로 글자가 깨지지 않게 base64 로 받아 바이트를 그대로 되살린다
        $b64 = (ssh $SshHost 'base64 -w0 ~/.join-zip.conf && rm -f ~/.join-zip.conf') -join ''
        if ($LASTEXITCODE -ne 0) { throw "join.conf 받기 실패 (종료 $LASTEXITCODE)" }
        $bytes = [Convert]::FromBase64String($b64.Trim())
    } finally {
        # 중간에 멈춰도 미니PC 에 비밀키 사본이 남지 않게 한 번 더 지운다
        ssh $SshHost 'rm -f ~/.join-zip.conf'
        if ($LASTEXITCODE -ne 0) { Write-Warning '미니PC ~/.join-zip.conf 를 지울 것 (자동 삭제 실패)' }
    }

    New-FriendZip $bytes $ExePath $ZipPath
    $b64 = $null; $bytes = $null

    Write-Output ''
    Write-Output "만들었다: $ZipPath"
    Write-Output '친구에게 디스코드 DM 으로 보낸다 · 공개 채널 금지 · 한 번에 한 명씩 가입.'
    Write-Output '보낸 뒤 zip 은 지워도 된다 (다시 만들 수 있다).'
}

if ($MyInvocation.InvocationName -ne '.') {
    $ErrorActionPreference = 'Stop'
    Invoke-Main
}
