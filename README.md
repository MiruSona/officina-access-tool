# AccessTool — 승인형 WireGuard 가입

**집 게임 서버에 친구를 WireGuard 로 들여보낼 때, 키를 만들어 나눠 주는 일을 없앤다.**

보통은 서버 주인이 친구마다 키를 만들고 설정 파일을 디스코드로 보낸다. 귀찮고, 비밀키가 채팅방에 남는다.
AccessTool 은 거꾸로 한다. **친구 PC 가 키를 직접 만들고**, 서버 주인은 집 LAN 의 승인 웹에서 **「친구가 알려 준 확인 코드와 같으면 승인」** 만 누른다.
설정은 양쪽에 자동으로 들어간다. 친구 비밀키는 친구 PC 밖으로 나가지 않는다.

MIT 라이선스. 친구 실가입 전 단계다 (서버 데몬·설치 스크립트·친구 exe·관리 API 1판 끝, 부트스트랩 격리 실측 통과).

## 어떻게 돌아가나

조각은 셋이다.

| 조각 | 어디서 도나 | 하는 일 |
| --- | --- | --- |
| `homegames-join.exe` | 친구 PC (Windows) | 키 만들기 · WireGuard 설치 · 가입 요청 · 승인되면 본 터널로 갈아타기 |
| `accessd` | 서버 (Linux, systemd) | 가입 요청 받기(터널 안 `10.183.26.1:7480`) · 승인되면 `wg0` 에 피어 더하기 |
| 승인 웹 | `accessd` 안, 서버 LAN IP `:7481` | 대기 요청·확인 코드 보기 · 승인 · 거절 · 피어 회수 |

```
 친구 PC                                   서버 (wg0)                     관리자 PC (같은 LAN)
 homegames-join.exe                        accessd
  1. 키쌍 만들기 (비밀키는 PC 안에만)
  2. 가입용 임시 터널 켜기 ── 51820/udp ──▶ 부트스트랩 피어 (.254)
  3. 이름 + 공개키 보내기 ───────────────▶ 7480 접수 ──▶ 요청 저장
  4. 확인 코드 6자리 표시                                               5. 승인 웹(7481)에서
     (디스코드로 서버 주인에게 알림)                ◀── 승인 ─────────     코드가 같으면 승인
  6. 설정 받기 → 임시 터널 내리고 본 터널 켜기 ── wg0 피어로 접속
```

- **확인 코드**는 친구 공개키 SHA-256 의 앞 6자리다. 친구 화면과 승인 웹에 같은 값이 뜬다.
- 친구가 창을 닫았다 다시 켜도 같은 키·같은 요청으로 이어서 기다린다.

## 준비물

| 무엇 | 조건 |
| --- | --- |
| 서버 | Linux + systemd. `wg-quick@wg0` 가 이미 돌고 `/etc/wireguard/wg0.conf` · `/etc/wireguard/server.pub` 가 있다. `wg` · `nft` · `ufw` 명령이 있다. Go 는 없어도 된다 |
| 터널 대역 | `10.183.26.0/24` 로 코드에 고정 (서버 `.1`, 가입용 부트스트랩 `.254`) |
| 공유기 | `51820/udp` 를 서버로 포트포워딩. 밖에서 부를 DDNS 이름 (예 `games.example.org`) |
| 관리자 PC | 서버와 같은 LAN. 승인 웹은 이 한 대에서만 열린다 |
| 친구 PC | Windows 10/11 (64비트) |
| 빌드 PC (직접 빌드할 때) | Go 1.26 이상 (`go.mod`) |

## 빠른 시작

예시 값 : 서버 `192.168.1.10`, 관리자 PC `192.168.1.20`, DDNS `games.example.org`.

**① 서버에 설치한다.** GitHub Release 에서 `accessd` 를 받아 `deploy/` 폴더에 넣거나, 직접 빌드한다 (PowerShell) :

```powershell
$env:GOOS='linux'; $env:GOARCH='amd64'; $env:CGO_ENABLED='0'; go build -trimpath -o deploy/accessd ./cmd/accessd
```

`deploy/` 폴더를 통째로 서버에 올리고, 그 폴더에서 :

```bash
sudo bash install.sh --web-addr 192.168.1.10 --admin-pc 192.168.1.20 --endpoint games.example.org:51820
```

- `--web-addr` 는 승인 웹이 묶일 서버 LAN IP, `--admin-pc` 는 승인 웹에 들어올 수 있는 PC 한 대다. **매번 꼭 준다** (기본값 없음).
- 스크립트는 전용 계정 `accesstool`, 권한, nft 표, ufw 규칙 둘, 부트스트랩 피어, systemd 유닛, 친구용 `join.conf` 를 만든다.
- 끝에 **승인 웹 토큰을 한 번만** 보여 준다. 잃어버렸으면 `sudo cat /var/lib/accesstool/web.token`.
- 상태는 `systemctl status accessd`, 격리 카운터는 `nft list table inet accesstool` 로 본다.

**② 승인 웹을 연다.** 관리자 PC 브라우저로 `http://192.168.1.10:7481` 에 들어가 토큰으로 로그인한다. 로그인 뒤 「사용법」 상자에 이 흐름이 요약돼 있다.

**③ 친구에게 줄 zip 을 만든다.** zip 에는 두 파일이 **같은 폴더**로 들어간다 (exe 가 자기 옆의 `join.conf` 를 읽는다).

| 파일 | 어디서 |
| --- | --- |
| `homegames-join.exe` | GitHub Release 의 것(지금은 서명 없음), 또는 직접 빌드한 `bin/homegames-join.exe` |
| `join.conf` | 서버의 `sudo cat /var/lib/accesstool/join.conf` 를 그대로 저장. 꼴은 `deploy/join.conf.example` |

관리자 PC 에서 서버로 ssh 가 되면 스크립트 하나로 만든다. 다운로드 폴더에 `HomeGames-가입.zip` 이 생긴다 (sudo 비밀번호 한 번, 키는 화면에 안 찍힘) :

```powershell
powershell -ExecutionPolicy Bypass -File .\Test\make-friend-zip.ps1 -SshHost <서버 ssh 이름>
```

`-ExecutionPolicy Bypass` 는 이 한 번만 스크립트 실행을 허용한다. 빼고 치면 기본 설정 PowerShell 에서 「이 시스템에서 스크립트를 실행할 수 없으므로」 오류가 난다.

`join.conf` 에는 부트스트랩 비밀키가 들어 있다. 여러 친구가 같은 zip 을 써도 되지만 공개된 곳에 올리지는 않는다 (가입 요청이 쏟아지는 원천이 된다).

**④ 친구가 할 일**

1. zip 을 「모두 압축 풀기」로 푼다.
2. `homegames-join.exe` 실행 → UAC 「예」. SmartScreen 이 막으면 「추가 정보 → 실행」.
3. 이름을 넣는다 (영소문자·숫자·`-`, 20자까지).
4. 화면에 뜬 확인 코드 6자리를 디스코드로 알려 준다.

**⑤ 관리자가 승인한다.** 승인 웹의 이름·확인 코드가 친구가 알려 준 코드와 **같을 때만** 「승인」, 다르면 「거절」. 승인하면 친구 exe 가 알아서 본 터널로 갈아타고 끝난다.

**⑥ 게임에 접속한다.** 접속 주소는 터널 서버 IP `10.183.26.1` 이다. 친구 exe 도 끝날 때 이 주소를 띄운다 (게임 포트는 따로 알려 준다). hosts 파일은 고치지 않는다.

친구 exe 종료 코드 : `0` 끝(또는 이미 연결됨) · `1` 실패 · `2` `join.conf` 문제.

## 운영

| 할 일 | 방법 |
| --- | --- |
| 판올림 | 새 `accessd` 를 `deploy/` 에 넣고 `--endpoint` 만 빼고 다시 돌린다. 있는 키·토큰·요청은 안 덮는다 : `sudo bash install.sh --web-addr <서버 LAN IP> --admin-pc <관리자 PC LAN IP>` |
| zip 이 퍼졌을 때 | 위 명령에 `--rotate-bootstrap` 을 더해 부트스트랩 키를 바꾸고, zip 을 다시 만든다. exe 는 그대로, 이미 가입한 친구도 그대로다 |
| 친구 내보내기 | 승인 웹 피어 목록의 「회수」 |
| 다시 가입 | 이미 연결된 PC 에서 `homegames-join.exe --rejoin` |
| 여러 명 가입 | **한 번에 한 명씩.** 모두 같은 부트스트랩 피어를 써서 동시에 하면 꼬인다 |

다른 관리 도구에서 쓰는 JSON API 도 있다 (승인 웹과 같은 7481).
헤더 `Authorization: Bearer <web.token 값>` 이 필수이고, 브라우저용이 아니라 `Origin` 이 붙으면 403 이다.
`GET /api/state` · `POST /api/approve {"id"}` · `POST /api/reject {"id"}` · `POST /api/revoke {"name"}`. 약속 표는 [설계 문서](Docs/Design/2026-11-04-승인형가입설계.md) 10장.

피어는 `wg0.conf` 에 `# BEGIN peer <이름>` … `# END peer <이름>` 블록으로 쓰고 `/run/wg-friend.lock` 잠금을 잡는다. 같은 꼴을 쓰는 다른 피어 관리 스크립트(예전에 쓰던 `wg-friend`, 이 저장소에 없음)와 같이 돌아도 안 꼬이게 맞춰 둔 것이다. 없어도 된다.

## 친구 PC 에 하는 일 (전부)

| 무엇 | 내용 |
| --- | --- |
| 관리자 권한 | 관리자가 아니면 자신을 다시 띄워 UAC 를 한 번 묻는다. 「아니요」면 아무것도 안 한다 |
| 상태 폴더 | `%ProgramData%\HomeGames\` (SYSTEM·Administrators 만 읽음) 에 키·상태·터널 설정을 둔다 |
| WireGuard 설치 | 없을 때만 공식 MSI 1.1.1 을 받아 **SHA256 대조 뒤** 조용히 설치한다 |
| 터널 서비스 | 가입용 임시 `home-games-join`, 본 터널 `home-games`. 끝나면 임시 터널은 지운다. 본 터널은 부팅 때 켜진다 |
| 통신 | 임시 터널 안에서 이름·공개키·프로그램 판만 보낸다. 비밀키는 안 보낸다 |

**하지 않는 일** : 시작 프로그램 등록, 방화벽 규칙 수정, hosts 수정, WireGuard MSI 말고 다른 것 내려받기, 자기 업데이트.

제거는 관리자 PowerShell 에서 아래를 돌리고, WireGuard 는 「설정 → 앱」에서 지운다.

```powershell
& "$env:ProgramFiles\WireGuard\wireguard.exe" /uninstalltunnelservice home-games
& "$env:ProgramFiles\WireGuard\wireguard.exe" /uninstalltunnelservice home-games-join
Remove-Item -Recurse -Force "$env:ProgramData\HomeGames"
```

자세한 건 [`Docs/Guide/코드서명정책.md`](Docs/Guide/코드서명정책.md) 5·6장.

## 왜 안전한가

| 걱정 | 막는 것 |
| --- | --- |
| 부트스트랩 키는 사실상 공개다 | nft 전용 표 `inet accesstool` 이 부트스트랩(`.254`)에서 오는 것 중 접수 API(`10.183.26.1:7480`) 말고는 전부 버린다. ufw 규칙 순서와 상관없다 |
| 누가 친구 이름으로 요청을 넣으면 | 확인 코드가 다르다. 코드가 같을 때만 승인한다 |
| 집 와이파이의 다른 기기·웹페이지가 승인하면 | 승인 웹은 서버 LAN IP 에만 묶이고, ufw 로 관리자 PC 한 대만 들어온다. 토큰 로그인(`HttpOnly; SameSite=Strict` 쿠키) |
| DNS 리바인딩·CSRF | 승인 웹이 `Host`·`Origin` 을 `--web-addr` 값과 그대로 견준다 |
| 응답을 엿보면 | 피어 PSK 는 친구 공개키로 봉해서 보낸다 |

알려진 한계 : 승인 웹은 HTTP 평문이라 토큰이 LAN 에서 보일 수 있다. 서명 없는 exe 라 SmartScreen·백신이 의심할 수 있다.
경계 전체와 결정 까닭은 [설계 문서](Docs/Design/2026-11-04-승인형가입설계.md) 5~7장.

## 빌드와 릴리스

시험 : `go vet ./... ; go test -count=1 ./...`

친구 exe 를 직접 빌드할 때는 먼저 버전 정보·매니페스트를 만든다. `.syso` 는 커밋하지 않는다 (gitignore). 빼먹어도 빌드는 되지만 exe 에 버전 정보가 안 들어간다.

```powershell
go install github.com/tc-hib/go-winres@v0.3.3      # 한 번만
cd cmd/homegames-join; go-winres make --arch amd64; cd ../..
$env:GOOS='windows'; $env:GOARCH='amd64'; $env:CGO_ENABLED='0'; go build -trimpath -o bin/homegames-join.exe ./cmd/homegames-join
```

CI (`.github/workflows/build.yml`) :

- main 푸시·PR·태그 `v*` 마다 vet → test → go-winres → 빌드(`-trimpath`) → `SHA256SUMS` 를 돌리고 `dist` 산출물로 올린다.
- 태그 `vX.Y.Z` 를 푸시하면 Release 에 `homegames-join.exe` · `accessd` · `SHA256SUMS` 가 붙는다.
- 태그 전에 `cmd/homegames-join/winres/winres.json` 의 판 번호를 올린다. 태그와 판이 다르면 CI 가 멈춘다.
- 코드 서명은 SignPath Foundation 승인 뒤 붙인다. 규칙은 [`Docs/Guide/코드서명정책.md`](Docs/Guide/코드서명정책.md).

## 저장소 구조

| 경로 | 내용 |
| --- | --- |
| `cmd/accessd/` | 서버 데몬 — 접수 API(wg0 위 7480) · 승인 웹(LAN 7481) · 요청 저장 |
| `cmd/homegames-join/` | 친구 exe (Windows) — 관리자 권한 받기 · 콘솔 문구 · `--rejoin` |
| `internal/joinflow/` | 친구 exe 의 가입 흐름 — `join.conf` · `join.json` · conf 문자열 · 접수 API 대화 |
| `internal/wgwin/` | 친구 PC 의 WireGuard 앱 제어 — MSI 받기·SHA256 · 터널 서비스 · 폴더 ACL |
| `internal/proto/` | 접수 API 요청·응답 꼴, 이름 규칙, 확인 코드, PSK 봉하기 (친구 exe 도 쓴다) |
| `internal/wgconf/` | `wg0.conf` 피어 블록 읽기·쓰기 — `wg-friend` 와 같은 꼴·같은 잠금 |
| `internal/wgctl/` | 살아 있는 wg0 에 피어 하나 더하기·빼기 (wgctrl) |
| `internal/kvconf/` | `key = value` 설정 파일 읽기 (`accessd.conf`, 친구용 `join.conf`) |
| `deploy/` | systemd 유닛 둘 · tmpfiles · nft 표 · `install.sh` · `join.conf.example` |
| `Test/` | 시험 자료 · 친구 zip 만들기 `make-friend-zip.ps1` |
| `Docs/` | [설계](Docs/Design/2026-11-04-승인형가입설계.md) (흐름·부품·프로토콜·보안 경계·결정 표·검증 계획) · [코드 서명 정책](Docs/Guide/코드서명정책.md) |

## 라이선스 · 문의

[MIT](LICENSE). 문제·오탐 신고는 이 저장소의 [Issues](https://github.com/MiruSona/officina-access-tool/issues).

## English summary

AccessTool lets friends join a home game server over WireGuard without the owner generating and sending keys.
The friend runs `homegames-join.exe` (Windows 10/11), which creates its own key pair, connects through a locked-down
bootstrap tunnel, and requests to join. The server daemon `accessd` (Linux, systemd, existing `wg-quick@wg0`) shows the
request in a LAN-only, token-protected approval page; the owner approves only when the 6-character confirmation code
matches what the friend reports. The friend's private key never leaves their PC. Games are reached at the tunnel
server IP `10.183.26.1`.

Setup: forward `51820/udp`, run `deploy/install.sh --web-addr <server LAN IP> --admin-pc <admin PC LAN IP> --endpoint <ddns>:51820`,
open `http://<server LAN IP>:7481`, and give friends a zip with `homegames-join.exe` + `join.conf`.
Join one friend at a time. Release binaries are built by GitHub Actions (`-trimpath`, `SHA256SUMS`); they are currently unsigned.
See [`Docs/Guide/코드서명정책.md`](Docs/Guide/코드서명정책.md) for everything the exe does on a friend's PC and how to remove it. License: MIT.
