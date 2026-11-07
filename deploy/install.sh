#!/bin/bash
# AccessTool 설치·판올림. 미니PC 에서 사용자가 sudo 로 돌린다. 다시 돌려도 안전하다 (있는 키·토큰·요청은 안 덮는다).
# --web-addr·--admin-pc 는 매번 꼭 준다 (기본값 없음).
#   sudo bash install.sh --web-addr <미니PC LAN IP> --admin-pc <메인 PC LAN IP> --endpoint <DDNS 이름>:51820   첫 설치
#   sudo bash install.sh --web-addr <미니PC LAN IP> --admin-pc <메인 PC LAN IP>                               판올림
#   위에 --rotate-bootstrap 을 더하면 부트스트랩 키를 바꾼다 (친구용 join.conf 도 새로 나간다)
#   예: sudo bash install.sh --web-addr 192.168.1.10 --admin-pc 192.168.1.20 --endpoint games.example.org:51820
# 설계 : Docs/Design/2026-11-04-승인형가입설계.md 3-3
set -euo pipefail
umask 077

SRC=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
WG_DIR=/etc/wireguard
WG_CONF=$WG_DIR/wg0.conf
SERVER_PUB=$WG_DIR/server.pub
LOCK=/run/wg-friend.lock
ETC=/etc/accesstool
STATE=/var/lib/accesstool
BIN=/usr/local/sbin/accessd
BOOT_NAME=accesstool-bootstrap
BOOT_IP=10.183.26.254
SERVER_IP=10.183.26.1
INTAKE_PORT=7480
WEB_PORT=7481

die() { echo "install.sh: $1" >&2; exit 1; }
usage() {
    echo "사용법: sudo bash install.sh --web-addr <미니PC LAN IP> --admin-pc <메인 PC LAN IP> [--endpoint <DDNS 이름>:51820] [--rotate-bootstrap]" >&2
    echo "  예: sudo bash install.sh --web-addr 192.168.1.10 --admin-pc 192.168.1.20 --endpoint games.example.org:51820" >&2
    exit 1
}

endpoint=""
WEB_ADDR=""
ADMIN_PC=""
rotate=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --endpoint)
            [[ $# -ge 2 ]] || die "--endpoint 뒤에 <이름>:<포트> 가 필요하다"
            endpoint=$2
            shift 2
            ;;
        --web-addr)
            [[ $# -ge 2 ]] || die "--web-addr 뒤에 IP 가 필요하다"
            WEB_ADDR=$2
            shift 2
            ;;
        --admin-pc)
            [[ $# -ge 2 ]] || die "--admin-pc 뒤에 IP 가 필요하다"
            ADMIN_PC=$2
            shift 2
            ;;
        --rotate-bootstrap) rotate=1; shift ;;
        *) die "모르는 인자: $1" ;;
    esac
done
# sed·설정 파일에 그대로 들어가므로 꼴을 좁힌다
if [[ -n $endpoint && ! $endpoint =~ ^[A-Za-z0-9.-]+:[0-9]{1,5}$ ]]; then
    die "--endpoint 꼴이 이상하다 (예: host.example.org:51820)"
fi
[[ -n $WEB_ADDR && -n $ADMIN_PC ]] || usage
for ip in "$WEB_ADDR" "$ADMIN_PC"; do
    [[ $ip =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || die "IPv4 꼴이 아니다: $ip (예: 192.168.1.10)"
done

[[ $EUID -eq 0 ]] || die "sudo 로 돌려야 한다"
for f in accessd accessd.service accesstool-nft.service tmpfiles.d/accesstool.conf nft/accesstool.nft; do
    [[ -f $SRC/$f ]] || die "없음: $SRC/$f (accessd 는 GOOS=linux 로 빌드해 이 폴더에 둔다)"
done
[[ -f $WG_CONF && -f $SERVER_PUB ]] || die "wg0 가 먼저 있어야 한다 ($WG_CONF, $SERVER_PUB)"
for c in wg nft ufw systemctl systemd-tmpfiles flock useradd; do
    command -v "$c" >/dev/null || die "$c 명령이 없다"
done
if [[ ! -f $ETC/accessd.conf && -z $endpoint ]]; then
    die "첫 설치에는 --endpoint <DDNS 이름>:51820 이 필요하다"
fi

echo "[1] 계정 accesstool"
id -u accesstool >/dev/null 2>&1 || useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin accesstool

echo "[2] 권한 (/etc/wireguard 710, wg0.conf 660, server.key 는 그대로)"
chown root:accesstool "$WG_DIR" "$WG_CONF"
chmod 710 "$WG_DIR"
chmod 660 "$WG_CONF"
install -d -o root -g accesstool -m 750 "$ETC"

echo "[3] tmpfiles (잠금 파일, 상태 폴더)"
install -m 644 "$SRC/tmpfiles.d/accesstool.conf" /etc/tmpfiles.d/accesstool.conf
systemd-tmpfiles --create /etc/tmpfiles.d/accesstool.conf

echo "[4] nft 표 inet accesstool (부팅 때도 wg0 보다 먼저 올라간다)"
install -m 644 "$SRC/nft/accesstool.nft" "$ETC/accesstool.nft"
install -m 644 "$SRC/accesstool-nft.service" /etc/systemd/system/accesstool-nft.service
systemctl daemon-reload
systemctl enable accesstool-nft.service
systemctl restart accesstool-nft.service

echo "[5] ufw 규칙 둘 (있으면 ufw 가 건너뛴다)"
ufw allow in on wg0 from "$BOOT_IP" to "$SERVER_IP" port "$INTAKE_PORT" proto tcp comment accesstool-intake
ufw allow from "$ADMIN_PC" to "$WEB_ADDR" port "$WEB_PORT" proto tcp comment accesstool-web

echo "[6] 부트스트랩 키와 wg0.conf 블록"
if [[ ! -f $ETC/bootstrap.key || $rotate -eq 1 ]]; then
    wg genkey > "$ETC/bootstrap.key.new"
    mv "$ETC/bootstrap.key.new" "$ETC/bootstrap.key"
fi
chmod 600 "$ETC/bootstrap.key"
boot_pub=$(wg pubkey < "$ETC/bootstrap.key")
(
    flock 9    # wg-friend·accessd 와 같은 잠금
    cur=$(sed -n "/^# BEGIN peer $BOOT_NAME\$/,/^# END peer $BOOT_NAME\$/s/^PublicKey[[:space:]]*=[[:space:]]*//p" "$WG_CONF")
    if [[ $cur != "$boot_pub" ]]; then
        if [[ -z $cur ]] && grep -qE "^AllowedIPs[[:space:]]*=[[:space:]]*${BOOT_IP//./\\.}/32" "$WG_CONF"; then
            die "$BOOT_IP 를 다른 피어가 쓰고 있다. 그 피어를 먼저 옮겨야 한다"
        fi
        new=$(mktemp)
        trap 'rm -f "$new"' EXIT
        if [[ -n $cur ]]; then
            # wg-friend cmd_remove 와 같은 awk : 블록과 그 바로 앞 빈 줄만 뺀다
            awk -v b="# BEGIN peer $BOOT_NAME" -v e="# END peer $BOOT_NAME" '
                $0 == b { skip = 1; blank = 0; next }
                skip    { if ($0 == e) skip = 0; next }
                /^$/    { blank++; next }
                { while (blank > 0) { print ""; blank-- } print }
                END     { if (skip) exit 3; while (blank > 0) { print ""; blank-- } }
            ' "$WG_CONF" > "$new" || die "'# END peer $BOOT_NAME' 줄이 없다. wg0.conf 를 손으로 확인하라"
        else
            cat "$WG_CONF" > "$new"
        fi
        printf '\n# BEGIN peer %s\n# by accesstool %s\n[Peer]\nPublicKey = %s\nAllowedIPs = %s/32\n# END peer %s\n' \
            "$BOOT_NAME" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$boot_pub" "$BOOT_IP" "$BOOT_NAME" >> "$new"
        cp -p "$WG_CONF" "$STATE/wg0.conf.bak"
        cat "$new" > "$WG_CONF"    # cat > 로 덮어 소유자·권한을 그대로 둔다
        systemctl reload wg-quick@wg0
        echo "    부트스트랩 블록을 넣었다 ($BOOT_IP)"
    fi
) 9>"$LOCK"

echo "[7] 바이너리"
install -m 755 -o root -g root "$SRC/accessd" "$BIN"

echo "[8] 설정 $ETC/accessd.conf"
if [[ ! -f $ETC/accessd.conf ]]; then
    cat > "$ETC/accessd.conf" <<EOF
# accessd 설정. 키 목록은 cmd/accessd/config.go
intake_listen = $SERVER_IP:$INTAKE_PORT
web_listen = $WEB_ADDR:$WEB_PORT
wg_conf = $WG_CONF
lock = $LOCK
state_dir = $STATE
interface = wg0
bootstrap_ip = $BOOT_IP
server_public_key = $(cat "$SERVER_PUB")
endpoint = $endpoint
EOF
else
    [[ -z $endpoint ]] || sed -i "s|^endpoint[[:space:]]*=.*|endpoint = $endpoint|" "$ETC/accessd.conf"
    sed -i "s|^web_listen[[:space:]]*=.*|web_listen = $WEB_ADDR:$WEB_PORT|" "$ETC/accessd.conf"
fi
chown root:accesstool "$ETC/accessd.conf"
chmod 640 "$ETC/accessd.conf"
endpoint=$(sed -n 's/^endpoint[[:space:]]*=[[:space:]]*//p' "$ETC/accessd.conf")

echo "[9] 승인 웹 토큰"
if [[ ! -s $STATE/web.token ]]; then
    head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$STATE/web.token"
    chown accesstool:accesstool "$STATE/web.token"
    chmod 600 "$STATE/web.token"
    echo "    새 토큰 (한 번만 보인다, http://$WEB_ADDR:$WEB_PORT 로그인에 쓴다):"
    echo "    $(cat "$STATE/web.token")"
fi

echo "[10] 유닛 accessd"
install -m 644 "$SRC/accessd.service" /etc/systemd/system/accessd.service
systemctl daemon-reload
systemctl enable accessd.service
systemctl restart accessd.service

echo "[11] 친구용 $STATE/join.conf"

cat > "$STATE/join.conf.new" <<EOF
# homegames-join.exe 옆에 두는 설정. 부트스트랩 비밀키가 들어 있다 — 친구에게만 준다.
bootstrap_private_key = $(cat "$ETC/bootstrap.key")
endpoint = $endpoint
server_public_key = $(cat "$SERVER_PUB")
server_ip = $SERVER_IP
intake_port = $INTAKE_PORT
EOF
chown root:root "$STATE/join.conf.new"
chmod 600 "$STATE/join.conf.new"
mv "$STATE/join.conf.new" "$STATE/join.conf"

echo "끝. 상태: systemctl status accessd · 격리 카운터: nft list table inet accesstool"
echo "친구용 설정 꺼내기: sudo cat $STATE/join.conf  (exe 와 같이 zip 으로 준다)"
