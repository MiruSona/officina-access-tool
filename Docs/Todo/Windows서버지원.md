# accessd Windows 서버 지원 (다음 할 일)

> 2026-11-08 · 저장소 소유자 결정 · 상태 「시작 전」

## 1. 왜 하나

- 일반 사용자는 대부분 Windows 를 쓴다. 서버(`accessd`)도 Windows 에서 돌아야 쓸 사람이 는다.
- 친구 exe 는 이미 Windows 다. 지금 Linux 전용인 것은 서버 쪽뿐이다.

## 2. Linux 에 묶인 자리

코드 확인은 끝났다. 다섯 자리를 바꾸면 된다.

| 자리 | Linux 에 묶인 까닭 | Windows 에서 할 방법 | 크기 |
| --- | --- | --- | --- |
| 파일 잠금 `internal/wgconf/lock_unix.go` | `syscall.Flock` | `LockFileEx` 로 `lock_windows.go` 추가 (빌드 태그) | 작음 |
| 설정 파일 자리 `/etc/wireguard/wg0.conf` | Linux 경로 | 이미 설정값(`wg_conf`). WireGuard for Windows 는 자기 폴더 conf 를 암호화하므로, 따로 둔 평문 conf 를 `wireguard.exe /installtunnelservice` 로 올리는 꼴(친구 exe 와 같은 방식) | 작음 |
| 살아 있는 터널에 피어 넣기 `internal/wgctl` | `wgctrl` 라이브러리 | 같은 라이브러리가 Windows 명명 파이프를 지원한다. 거의 그대로 | 작음 |
| 부트스트랩 격리 `deploy/nft/accesstool.nft` | nftables | Windows 방화벽 규칙(`netsh advfirewall` 또는 `New-NetFirewallRule`)으로 「`.254` 에서 오는 것은 접수 포트만 허용」. 보안 경계라 실측 필수 | 중간 |
| 서비스·설치 `deploy/*.service` · `install.sh` · ufw | systemd·bash | `golang.org/x/sys/windows/svc` 로 Windows 서비스 포장 + `install.ps1` | 중간 |

## 3. WSL2 길은 접었다

WSL2 안에서 Linux 판을 그대로 돌리는 길도 봤지만 접었다.

- WSL2 는 NAT 뒤에 있어 UDP 51820 이 못 들어온다. `portproxy` 는 TCP 만 넘긴다.
- 그래서 미러드 네트워크 모드가 필요하다.
- 부팅 때 자동 시작이 로그인이나 작업 스케줄러에 기대야 한다.
- 게임 서버가 Windows 쪽에 있으면 WSL → 호스트로 넘기는 DNAT 가 또 필요하다.

사용자마다 환경이 달라 지원 비용이 계속 든다. 네이티브 이식은 한 번 고생하고 끝난다.

실측 안 한 것 : WSL 커널에 WireGuard·nftables 가 들어 있는지, 미러드 모드에서 UDP 를 받는지.

## 4. 할 일 순서 (조사 → 설계 → 작업)

1. Windows 시험 서버 한 대 확보
2. 방화벽 격리 규칙 실측 — 부트스트랩 피어에서 접수 포트 밖으로 가는 접근이 막히는지
3. 잠금·경로·서비스 포장 구현
4. `install.ps1`
5. `README.md` 준비물 표의 「서버 (Linux, systemd)」 고치기
6. 설계 문서 `Docs/Design/2026-11-04-승인형가입설계.md` 의 「5. 보안 경계」 절에 Windows 줄 추가

## 5. 공수 (어림)

코딩 반나절 + 실측 하루. 시작할 때 소단계로 쪼개 `effort estimate` 로 다시 잰다.

## 6. 확인 못 한 것

- `wgctrl` 로 더한 피어가 Windows 재부팅 뒤에도 남는지. conf 파일도 같이 고치는 방식으로 풀 예정이다.
- Windows 방화벽 규칙이 WireGuard 터널 인터페이스에 적용되는지.
