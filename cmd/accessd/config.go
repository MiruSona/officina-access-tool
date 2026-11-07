package main

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"

	"github.com/MiruSona/officina-access-tool/internal/kvconf"
	"github.com/MiruSona/officina-access-tool/internal/proto"
)

const defaultConfigPath = "/etc/accesstool/accessd.conf"

// config 는 accessd 설정이다. 각 칸은 같은 이름의 플래그나 accessd.conf 의 키로 넣는다 (플래그가 이긴다).
type config struct {
	IntakeListen    string // 접수 API, wg0 위
	WebListen       string // 승인 웹, LAN 위 (기본값 없음, install.sh --web-addr 가 쓴다). Host·Origin 검사도 이 값으로 한다
	WgConf          string
	Lock            string
	StateDir        string
	TokenFile       string
	Interface       string
	BootstrapIP     string
	ServerPublicKey string
	Endpoint        string
}

func loadConfig(args []string) (config, error) {
	c := config{}
	fset := flag.NewFlagSet("accessd", flag.ContinueOnError)
	configPath := fset.String("config", defaultConfigPath, "설정 파일 (key = value)")
	fields := map[string]*string{
		"intake_listen":     &c.IntakeListen,
		"web_listen":        &c.WebListen,
		"wg_conf":           &c.WgConf,
		"lock":              &c.Lock,
		"state_dir":         &c.StateDir,
		"token_file":        &c.TokenFile,
		"interface":         &c.Interface,
		"bootstrap_ip":      &c.BootstrapIP,
		"server_public_key": &c.ServerPublicKey,
		"endpoint":          &c.Endpoint,
	}
	defaults := map[string]string{
		"intake_listen": "10.183.26.1:7480",
		"wg_conf":       "/etc/wireguard/wg0.conf",
		"lock":          "/run/wg-friend.lock",
		"state_dir":     "/var/lib/accesstool",
		"interface":     "wg0",
		"bootstrap_ip":  "10.183.26.254",
	}
	keys := make([]string, 0, len(fields))
	for k, p := range fields {
		fset.StringVar(p, k, defaults[k], k)
		keys = append(keys, k)
	}
	if err := fset.Parse(args); err != nil {
		return c, err
	}

	setByFlag := map[string]bool{}
	fset.Visit(func(f *flag.Flag) { setByFlag[f.Name] = true })

	data, err := os.ReadFile(*configPath)
	missingDefault := errors.Is(err, fs.ErrNotExist) && !setByFlag["config"]
	if err != nil && !missingDefault {
		return c, err
	}
	if err == nil {
		values, err := kvconf.Parse(data, keys)
		if err != nil {
			return c, fmt.Errorf("%s: %w", *configPath, err)
		}
		for k, v := range values {
			if !setByFlag[k] {
				*fields[k] = v
			}
		}
	}

	if c.TokenFile == "" {
		c.TokenFile = filepath.Join(c.StateDir, "web.token")
	}
	if c.Endpoint == "" {
		return c, errors.New("endpoint 가 없다 (예: <DDNS 이름>:51820)")
	}
	// 승인 웹은 Host·Origin 을 이 문자열과 그대로 견준다 — 0.0.0.0·호스트명이면 모든 요청이 403 이 된다
	if ap, err := netip.ParseAddrPort(c.WebListen); err != nil || ap.Addr().IsUnspecified() {
		return c, fmt.Errorf("web_listen %q: 구체적인 LAN IP:포트 를 적는다 (0.0.0.0·[::]·호스트명은 안 된다)", c.WebListen)
	}
	if _, err := proto.ParseKey(c.ServerPublicKey); err != nil {
		return c, fmt.Errorf("server_public_key: %w", err)
	}
	return c, nil
}
