# AccessTool — 승인형 WireGuard 가입

친구가 exe 하나로 키를 만들어 가입을 요청하면, 사용자가 LAN 의 승인 웹에서 승인하고 설정이 자동으로 들어가는 툴.
(1판 구현 끝 — 미니PC 데몬 `accessd` · 설치 스크립트 · 친구 exe `homegames-join` · 관리 API. 부트스트랩 격리 실측(설계 9장 ①) 통과, 친구 실가입 전)
MIT 라이선스 (`LICENSE`).

| 문서 | 내용 |
| --- | --- |
| [`Docs/Design/2026-11-04-승인형가입설계.md`](Docs/Design/2026-11-04-승인형가입설계.md) | 1차 설계 — 흐름 · 부품 · 프로토콜 · 보안 경계 · 결정 표 · 검증 계획 |
| [`Docs/Guide/코드서명정책.md`](Docs/Guide/코드서명정책.md) | 코드 서명 정책 — 서명 대상 · 빌드 출처 · 릴리스 절차 · 친구 PC 에 하는 일 전부 · 제거 방법 |

## 폴더 지도

| 경로 | 내용 |
| --- | --- |
| `cmd/accessd/` | 미니PC 데몬 — 접수 API(wg0 위 7480) · 승인 웹(LAN 7481) · 요청 저장 |
| `cmd/homegames-join/` | 친구 exe (windows) — 관리자 권한 받기 · 콘솔 문구 · `--rejoin` |
| `internal/joinflow/` | 친구 exe 의 가입 흐름 — join.conf · join.json · conf 문자열 · 접수 API 대화 |
| `internal/wgwin/` | 친구 PC 의 WireGuard 앱 제어 — MSI 받기·SHA256 · 터널 서비스 · 폴더 ACL |
| `internal/proto/` | 접수 API 요청·응답 꼴, 이름 규칙, 확인 코드, PSK 봉하기 (친구 exe 도 쓴다) |
| `internal/wgconf/` | wg0.conf 피어 블록 읽기·쓰기 — 옛 `wg-friend` 와 같은 꼴·같은 잠금 |
| `internal/wgctl/` | 살아 있는 wg0 에 피어 하나 더하기·빼기 (wgctrl) |
| `internal/kvconf/` | `key = value` 설정 파일 읽기 (`accessd.conf`, 친구용 `join.conf`) |
| `deploy/` | systemd 유닛 둘 · tmpfiles · nft 표 · `install.sh` · `join.conf.example` |

## 관리 API

승인 웹과 같은 리스너(LAN 7481)에 JSON API 가 있다. 다른 관리 도구가 자기 화면에서 가입 요청·피어를 보여 주고 승인·거절·회수를 할 때 쓴다.

- 헤더 `Authorization: Bearer <web.token 값>` 필수. 브라우저용이 아니다 (`Origin` 이 붙으면 403).
- `GET /api/state` · `POST /api/approve {"id"}` · `POST /api/reject {"id"}` · `POST /api/revoke {"name"}`. 약속 표는 설계 문서 10장.

## 빌드 · 시험 · 설치

전제 :

- 빌드 PC 에 Go 1.26 이상 (`go.mod`). 미니PC 에는 Go 가 없어도 된다.
- 미니PC(Linux, systemd)에 `wg-quick@wg0` 서버가 이미 돈다 — `/etc/wireguard/wg0.conf` 와 서버 공개키 `/etc/wireguard/server.pub` 이 있어야 한다. `wg` · `nft` · `ufw` 명령도 필요하다.
- 터널 대역은 `10.183.26.0/24` (서버 `.1`, 부트스트랩 `.254`) 로 코드에 고정돼 있다.
- `wg-friend` 는 이전에 쓰던 피어 관리 셸 스크립트다 (이 저장소에 없다). 없어도 된다 — 같은 블록 꼴·같은 잠금 파일을 써서 같이 돌아도 안 꼬이게 맞춰 둔 것이다.

- 시험 : `go vet ./... ; go test -count=1 ./...`
- 빌드 (메인 PC PowerShell) : `$env:GOOS='linux'; $env:GOARCH='amd64'; $env:CGO_ENABLED='0'; go build -trimpath -o deploy/accessd ./cmd/accessd`
- 설치 (미니PC, `deploy/` 폴더를 올린 뒤) : `sudo bash install.sh --web-addr <미니PC LAN IP> --admin-pc <메인 PC LAN IP> --endpoint <DDNS 이름>:51820`
  - 예 : `sudo bash install.sh --web-addr 192.168.1.10 --admin-pc 192.168.1.20 --endpoint games.example.org:51820`
  - `--web-addr`(승인 웹이 묶일 LAN IP)·`--admin-pc`(승인 웹에 들어올 수 있는 한 대)는 **매번 꼭 준다.** 판올림은 `--endpoint` 만 빼고 다시 돌린다.
- 게임 접속 주소는 터널 서버 IP `10.183.26.1` 이다. 친구 exe 가 가입 끝에 화면에 띄운다. hosts 는 안 고친다 (설계 12장).
- 친구 exe 빌드 : 먼저 버전 정보·매니페스트를 만든다 (`go install github.com/tc-hib/go-winres@v0.3.3` 한 번, `cd cmd/homegames-join; go-winres make --arch amd64; cd ../..`). 그다음 `$env:GOOS='windows'; $env:GOARCH='amd64'; $env:CGO_ENABLED='0'; go build -trimpath -o bin/homegames-join.exe ./cmd/homegames-join`
  - `.syso` 는 커밋하지 않는다 (gitignore). 빼먹어도 빌드는 되지만 exe 에 버전 정보가 안 들어간다.

## 빌드 · 릴리스 (CI)

- `.github/workflows/build.yml` 이 main 푸시·PR·태그 `v*` 마다 vet → test → go-winres → 빌드(`-trimpath`) → `SHA256SUMS` 를 돌리고 `dist` 산출물로 올린다.
- 태그 `vX.Y.Z` 를 푸시하면 Release 에 `homegames-join.exe` · `accessd` · `SHA256SUMS` 가 붙는다. 태그 전에 `cmd/homegames-join/winres/winres.json` 의 판 번호를 올린다.
- 서명은 SignPath Foundation 승인 뒤 워크플로에 붙인다. 규칙은 [`Docs/Guide/코드서명정책.md`](Docs/Guide/코드서명정책.md).

## 친구에게 줄 zip

zip 하나에 두 파일만 넣는다. 두 파일은 **같은 폴더**에 있어야 한다 (exe 가 자기 옆의 `join.conf` 를 읽는다).

| 파일 | 어디서 |
| --- | --- |
| `homegames-join.exe` | 위 빌드의 `bin/homegames-join.exe`, 또는 GitHub Release 의 것 (지금은 서명 없음) |
| `join.conf` | 미니PC 에서 `sudo cat /var/lib/accesstool/join.conf` 를 그대로 저장. 꼴은 `deploy/join.conf.example` |

`Test/make-friend-zip.ps1 -SshHost <미니PC ssh 별칭>` 을 돌리면 다운로드 폴더에 zip 이 만들어진다 (sudo 비밀번호 한 번, 키가 화면에 안 찍힘).

- 친구는 zip 을 「모두 압축 풀기」로 푼 뒤 exe 를 실행 → UAC 「예」 → 이름 넣기 → 화면의 확인 코드를 디스코드로 알려 준다. 창을 닫았다 다시 켜도 이어서 기다린다.
- SmartScreen 이 막으면 「추가 정보 → 실행」. 이미 연결된 PC 를 다시 가입시키려면 `homegames-join.exe --rejoin`.
- `join.conf` 에는 부트스트랩 비밀키가 들어 있다. 공개 전제지만 아무 데나 올리지 않는다 (요청 폭주 원천).
- 상태·키는 친구 PC 의 `%ProgramData%\HomeGames\` (SYSTEM·Administrators 만 읽음) 에 남는다.
- 종료 코드 : 0 끝(또는 이미 연결됨) · 1 실패 · 2 `join.conf` 문제.
- 승인 웹 화면(로그인 뒤 「사용법」 상자)에도 같은 사용법이 있다.
