// Package joinflow 는 친구 exe 의 가입 흐름이다 (join.conf · join.json · conf 문자열 · 접수 API 대화).
// 흐름 원문 : Docs/Design/2026-11-04-승인형가입설계.md 3-2 · 4장
package joinflow

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/MiruSona/officina-access-tool/internal/kvconf"
	"github.com/MiruSona/officina-access-tool/internal/proto"
)

// 터널 이름. WireGuard 앱은 conf 파일 이름으로 터널(서비스 WireGuardTunnel$<이름>)을 만든다.
const (
	MainTunnel      = "home-games"
	BootstrapTunnel = "home-games-join"
	StateFile       = "join.json"
	keepaliveSec    = 25
)

// DefaultMSISHA256 는 옛 INSTALL.bat 에 박혀 있던 wireguard-amd64-1.1.1.msi 의 SHA256 이다.
const DefaultMSISHA256 = "7bfed60ad61b785c914b38b61555a975488e1d3ec472dbfb2fcdf498fca75242"

// Config 는 exe 옆 join.conf 의 값이다.
type Config struct {
	BootstrapPrivateKey string
	Endpoint            string
	ServerPublicKey     string
	ServerIP            netip.Addr
	IntakePort          int
	MSISHA256           string
}

// LoadConfig 는 join.conf 를 읽고 값마다 꼴을 검사한다 (conf 파일에 그대로 들어가므로 줄바꿈·공백을 막는다).
func LoadConfig(path string) (Config, error) {
	var c Config
	data, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	kv, err := kvconf.Parse(data, []string{"bootstrap_private_key", "endpoint", "server_public_key", "server_ip", "intake_port", "msi_sha256"})
	if err != nil {
		return c, err
	}
	c.BootstrapPrivateKey = kv["bootstrap_private_key"]
	if _, err := proto.ParseKey(c.BootstrapPrivateKey); err != nil {
		return c, fmt.Errorf("bootstrap_private_key: %w", err)
	}
	c.ServerPublicKey = kv["server_public_key"]
	if _, err := proto.ParseKey(c.ServerPublicKey); err != nil {
		return c, fmt.Errorf("server_public_key: %w", err)
	}
	c.Endpoint = kv["endpoint"]
	if _, port, err := net.SplitHostPort(c.Endpoint); err != nil || port == "" || strings.ContainsAny(c.Endpoint, " \t\r\n#") {
		return c, fmt.Errorf("endpoint 가 '이름:포트' 꼴이 아니다: %q", c.Endpoint)
	}

	ipText := kv["server_ip"]
	if ipText == "" {
		ipText = "10.183.26.1"
	}
	c.ServerIP, err = netip.ParseAddr(ipText)
	if err != nil || !c.ServerIP.Is4() {
		return c, fmt.Errorf("server_ip 가 IPv4 가 아니다: %q", ipText)
	}

	c.IntakePort = 7480
	if p := kv["intake_port"]; p != "" {
		c.IntakePort, err = strconv.Atoi(p)
		if err != nil || c.IntakePort < 1 || c.IntakePort > 65535 {
			return c, fmt.Errorf("intake_port 가 1~65535 가 아니다: %q", p)
		}
	}

	c.MSISHA256 = strings.ToLower(kv["msi_sha256"])
	if c.MSISHA256 == "" {
		c.MSISHA256 = DefaultMSISHA256
	}
	if raw, err := hex.DecodeString(c.MSISHA256); err != nil || len(raw) != 32 {
		return c, fmt.Errorf("msi_sha256 가 64자리 hex 가 아니다")
	}

	return c, nil
}

// bootstrapAddr 는 서버와 같은 /24 의 .254 다 (서버 wg0.conf 의 부트스트랩 피어 자리).
func (c Config) bootstrapAddr() netip.Addr {
	b := c.ServerIP.As4()
	b[3] = 254
	return netip.AddrFrom4(b)
}

// BootstrapConf 는 부트스트랩 터널 conf 다. 접수 API 하나만 닿게 AllowedIPs 를 서버 /32 로 묶는다.
func (c Config) BootstrapConf() string {
	return fmt.Sprintf("[Interface]\r\nPrivateKey = %s\r\nAddress = %s/32\r\n\r\n[Peer]\r\nPublicKey = %s\r\nEndpoint = %s\r\nAllowedIPs = %s/32\r\nPersistentKeepalive = %d\r\n",
		c.BootstrapPrivateKey, c.bootstrapAddr(), c.ServerPublicKey, c.Endpoint, c.ServerIP, keepaliveSec)
}

// PeerConf 는 승인 뒤 진짜 터널 conf 다. 서버 키·Endpoint·AllowedIPs 는 응답이 아니라 join.conf 값을 쓴다 —
// 부트스트랩 응답은 가로채일 수 있어서 Address 와 PSK 만 받는다 (설계 4장).
func (c Config) PeerConf(privateKey string, pc *proto.PeerConfig, psk [32]byte) (string, error) {
	if pc.ServerPubkey != c.ServerPublicKey {
		return "", errors.New("응답의 서버 공개키가 join.conf 와 다르다")
	}
	addr, err := netip.ParsePrefix(pc.Address)
	if err != nil || addr.Bits() != 32 || !netip.PrefixFrom(c.ServerIP, 24).Contains(addr.Addr()) || addr.Addr() == c.ServerIP {
		return "", fmt.Errorf("응답의 address 가 서버 대역의 /32 가 아니다: %q", pc.Address)
	}
	return fmt.Sprintf("[Interface]\r\nPrivateKey = %s\r\nAddress = %s\r\n\r\n[Peer]\r\nPublicKey = %s\r\nPresharedKey = %s\r\nEndpoint = %s\r\nAllowedIPs = %s/32\r\nPersistentKeepalive = %d\r\n",
		privateKey, addr, c.ServerPublicKey, wgtypes.Key(psk).String(), c.Endpoint, c.ServerIP, keepaliveSec), nil
}

// State 는 %ProgramData%\HomeGames\join.json 이다. exe 를 다시 켜면 이 값으로 이어 간다.
type State struct {
	Name       string `json:"name"`
	PrivateKey string `json:"private_key"`
	RequestID  string `json:"request_id,omitempty"`
	Code       string `json:"code,omitempty"`
}

// LoadState 는 상태 파일이 없으면 nil, nil 을 돌려준다.
func LoadState(dir string) (*State, error) {
	data, err := os.ReadFile(filepath.Join(dir, StateFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var st State
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("%s 가 깨졌다: %w", StateFile, err)
	}
	if !proto.ValidName(st.Name) {
		return nil, fmt.Errorf("%s 의 이름이 규칙에 안 맞는다", StateFile)
	}
	if _, err := proto.ParseKey(st.PrivateKey); err != nil {
		return nil, fmt.Errorf("%s 의 비밀키: %w", StateFile, err)
	}
	return &st, nil
}

func SaveState(dir string, st *State) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return WriteAtomic(filepath.Join(dir, StateFile), data)
}

// WriteAtomic 은 같은 폴더의 임시 파일에 쓰고 rename 한다. 새 파일은 폴더 ACL 을 물려받는다.
func WriteAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	_, err = tmp.Write(data)
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), path)
	}
	if err != nil {
		os.Remove(tmp.Name())
	}
	return err
}
