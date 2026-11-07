# 설계 9장 ① 「부트스트랩은 접수 API 말고 아무 데도 못 닿는다」 실측 스크립트. PowerShell 5.1, 외부 모듈 없음.
#
# 쓰는 법
#   1. 메인 PC 를 집 LAN 에 둔 채 부트스트랩 conf 의 Endpoint 를 미니PC LAN 주소로 해서 켠다
#      (Test\bootstrap-tunnel.ps1 이 넣어 준다. 틀은 Test\bootstrap-lan.conf.example). 다른 터널은 끈다.
#   2. powershell -NoProfile -ExecutionPolicy Bypass -File Test\isolation-check.ps1
#      종료 0 = PASS, 1 = FAIL.
#   3. 첫 판은 AllowedIPs = 10.183.26.1/32, 둘째 판은 10.183.26.0/24 로 넓혀 한 번 더 돌린다.
#      0.0.0.0/0 은 쓰지 않는다 : Windows WireGuard 가 터널 밖 트래픽을 막아 메인 PC 인터넷이 끊긴다.
#   4. 미니PC 의 `sudo nft list table inet accesstool` drop 카운터가 늘었는지는 사람이 따로 본다 (이 스크립트는 안 본다).
#      이 스크립트만으로는 시간초과가 nft 에서 났는지 ufw 에서 났는지 못 가른다.
#
# 판정 : 접수 API(서버:7480/tcp)만 「열림」, 판정 칸 나머지 전부 「시간초과」이면 PASS.
#        「거부」도 실패다 — 거부 응답(RST·ICMP unreachable)이 왔다는 건 패킷이 미니PC 에 닿았다는 뜻이다.
# 「참고」 칸은 판정에서 뺀다 (실패할 수 없는 칸이라서) :
#   - 게임 UDP 포트 : 게임 서버가 쓰레기 패킷에 답을 안 하므로 뚫려 있어도 시간초과가 난다.
#     대신 닫힌 게 확실한 UDP 포트($ClosedUdpPort)를 판정 칸에 둔다 — 뚫려 있으면 ICMP port unreachable 로 「거부」가 뜬다.
#   - 다른 친구 IP : 그 IP 에 살아 있는 피어가 없으면 뚫려 있어도 답이 없다.
#     포워딩 차단은 미니PC ip_forward=0 · ufw FORWARD DROP 으로 확인한다 (규칙 읽기).
# 터널 대역(서버 주소 /24) 밖 주소(192.168.1.x 같은 집 LAN)는 LAN 으로 닿으므로 건너뛰고 「규칙 읽기로 확인」으로 적는다.
# 포트 기본값은 집 서버 포트 예시다 : 게임 서버 16261·16262·16271·16272, 웹 서비스 8080, 승인 웹 7481, SSH 22. 내 서버에 맞게 인자로 바꾼다.
# 비밀값(키·공인 주소)은 받지 않는다.
param(
    [string]$Server = '10.183.26.1',
    [int]$IntakePort = 7480,
    # 목록 인자는 문자열로 받아 쉼표로 쪼갠다 — `-File` 로 부르면 `1,2` 가 [int[]] 에서 12 로 붙어 버린다
    [string[]]$ServerTcpPorts = @('22', '7481', '8080', '16261', '16262', '16271', '16272'),
    [string[]]$ServerUdpPorts = @('16261', '16262', '16271', '16272'),
    [int]$ClosedUdpPort = 9,
    # 다른 친구 IP · 미니PC LAN 주소 · 공유기 (LAN 두 칸은 예시값, 내 집 값으로 바꾼다). 빼려면 PowerShell 창에서 `& .\isolation-check.ps1 -OtherHosts @()` (-File 로는 빈 값이 안 넘어간다)
    [string[]]$OtherHosts = @('10.183.26.2', '192.168.1.10', '192.168.1.1'),
    [string[]]$OtherTcpPorts = @('22', '7481', '8080'),
    [int]$TimeoutMs = 3000
)

$ErrorActionPreference = 'Stop'
function Split-List($a) { @($a -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
$ServerTcpPorts = Split-List $ServerTcpPorts | ForEach-Object { [int]$_ }
$ServerUdpPorts = Split-List $ServerUdpPorts | ForEach-Object { [int]$_ }
$OtherTcpPorts = Split-List $OtherTcpPorts | ForEach-Object { [int]$_ }
$OtherHosts = Split-List $OtherHosts
# shortcut: 터널 대역을 서버 주소의 /24 로 본다. 대역이 /24 가 아니게 되면 인자로 받는다
$net = ($Server -split '\.')[0..2] -join '.'
$skipped = @($OtherHosts | Where-Object { $_ -notlike "$net.*" })
$OtherHosts = @($OtherHosts | Where-Object { $_ -like "$net.*" })

function Test-Tcp([string]$h, [int]$port) {
    $c = New-Object System.Net.Sockets.TcpClient
    try {
        $t = $c.ConnectAsync($h, $port)
        if (-not $t.Wait($TimeoutMs)) { return '시간초과' }
        if ($c.Connected) { return '열림' }
        return '거부'
    } catch {
        $e = $_.Exception
        while ($e.InnerException) { $e = $e.InnerException }
        if ($e -is [System.Net.Sockets.SocketException] -and $e.SocketErrorCode -eq 'ConnectionRefused') { return '거부' }
        if ($e -is [System.Net.Sockets.SocketException] -and $e.SocketErrorCode -eq 'TimedOut') { return '시간초과' }
        return "오류($($e.Message))"
    } finally { $c.Close() }
}

function Test-Udp([string]$h, [int]$port) {
    $u = New-Object System.Net.Sockets.UdpClient
    try {
        $u.Client.ReceiveTimeout = $TimeoutMs
        $u.Connect($h, $port)
        [void]$u.Send([byte[]](0x00, 0x01, 0x02, 0x03), 4)
        $ep = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        [void]$u.Receive([ref]$ep)
        return '열림'   # 무엇이든 답이 왔다
    } catch {
        $e = $_.Exception
        while ($e.InnerException) { $e = $e.InnerException }
        # Windows 는 ICMP port unreachable 을 ConnectionReset 으로 돌려준다
        if ($e -is [System.Net.Sockets.SocketException] -and $e.SocketErrorCode -eq 'ConnectionReset') { return '거부' }
        if ($e -is [System.Net.Sockets.SocketException] -and $e.SocketErrorCode -eq 'TimedOut') { return '시간초과' }
        return "오류($($e.Message))"
    } finally { $u.Close() }
}

function Test-Icmp([string]$h) {
    # Test-Connection 은 PS 5.1 에서 실패하면 객체를 안 돌려줘 시간초과와 unreachable 을 못 가른다. 밑의 Win32_PingStatus 를 직접 본다
    $r = Get-WmiObject Win32_PingStatus -Filter "Address='$h' AND Timeout=$TimeoutMs"
    if ($null -eq $r -or $null -eq $r.StatusCode) { return '오류(주소 해석 실패)' }
    switch ([int]$r.StatusCode) {
        0 { return '열림' }
        11010 { return '시간초과' }
        default { return "거부($($r.StatusCode))" }   # 11003 host unreachable 등 — 답이 왔다
    }
}

$rows = New-Object System.Collections.Generic.List[object]
function Add-Row($proto, $h, $port, $state, $want, [switch]$Ref) {
    $verdict = if ($Ref) { '참고' } elseif ($state -eq $want) { 'ok' } else { 'X' }
    $rows.Add([pscustomobject]@{ 프로토콜 = $proto; 대상 = $h; 포트 = $port; 결과 = $state; 기대 = $want; 판정 = $verdict })
}

Add-Row 'TCP' $Server $IntakePort (Test-Tcp $Server $IntakePort) '열림'
foreach ($p in $ServerTcpPorts) { Add-Row 'TCP' $Server $p (Test-Tcp $Server $p) '시간초과' }
Add-Row 'UDP' $Server $ClosedUdpPort (Test-Udp $Server $ClosedUdpPort) '시간초과'
foreach ($p in $ServerUdpPorts) { Add-Row 'UDP' $Server $p (Test-Udp $Server $p) '시간초과' -Ref }
Add-Row 'ICMP' $Server '-' (Test-Icmp $Server) '시간초과'
foreach ($h in $OtherHosts) {
    Add-Row 'ICMP' $h '-' (Test-Icmp $h) '시간초과' -Ref
    foreach ($p in $OtherTcpPorts) { Add-Row 'TCP' $h $p (Test-Tcp $h $p) '시간초과' -Ref }
}

$rows | Format-Table -AutoSize | Out-String -Width 200 | Write-Output
foreach ($h in $skipped) { Write-Output "$h : 터널 대역 밖이라 건너뜀 — 규칙 읽기로 확인" }
$judged = @($rows | Where-Object { $_.판정 -ne '참고' })
$bad = @($judged | Where-Object { $_.판정 -ne 'ok' })
if ($bad.Count -eq 0) {
    Write-Output "PASS : $IntakePort 만 열림, 판정 칸 나머지 $($judged.Count - 1) 개 전부 시간초과 (참고 칸 $($rows.Count - $judged.Count) 개는 판정에서 뺌)"
    exit 0
}
Write-Output "FAIL : 기대와 다른 칸 $($bad.Count) 개"
exit 1
