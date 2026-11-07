// Package wgconf 는 wg0.conf 의 피어 블록을 옛 wg-friend 와 같은 꼴로 읽고 쓴다.
// 블록 꼴·IP 규칙의 원본은 이전에 쓰던 wg-friend 스크립트다. 한 글자도 바꾸지 않는다.
package wgconf

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	SubnetPrefix = "10.183.26"
	// BootstrapHost 는 부트스트랩 피어 자리라 친구에게 안 준다.
	BootstrapHost = 254
	BootstrapName = "accesstool-bootstrap"
	byPrefix      = "# by accesstool "
)

// allowedRe 는 wg-friend next_ip 의 sed 식과 같다 (블록 안팎 가리지 않고 모든 줄).
var allowedRe = regexp.MustCompile(`^AllowedIPs[ \t]*=[ \t]*10\.183\.26\.([0-9]+)/32`)

var ErrNoFreeIP = errors.New("빈 터널 IP 가 없다 (.2~.253 전부 사용 중)")

type Peer struct {
	Name         string
	PublicKey    string
	PresharedKey string
	IP           string // 10.183.26.N (/32 없이)
	ByAccesstool bool
}

// Peers 는 BEGIN/END 블록을 읽는다. 끝나지 않은 블록이 있으면 오류다 (그 파일은 손으로 봐야 한다).
func Peers(data []byte) ([]Peer, error) {
	var peers []Peer
	var cur *Peer
	for i, line := range splitLines(data) {
		if name, ok := strings.CutPrefix(line, "# BEGIN peer "); ok {
			if cur != nil {
				return nil, fmt.Errorf("%d번 줄: '%s' 블록이 끝나기 전에 새 블록이 시작됐다", i+1, cur.Name)
			}
			cur = &Peer{Name: name}
			continue
		}
		if cur == nil {
			continue
		}
		if line == "# END peer "+cur.Name {
			peers = append(peers, *cur)
			cur = nil
			continue
		}
		if strings.HasPrefix(line, byPrefix) {
			cur.ByAccesstool = true
			continue
		}
		if v, ok := value(line, "PublicKey"); ok {
			cur.PublicKey = v
		}
		if v, ok := value(line, "PresharedKey"); ok {
			cur.PresharedKey = v
		}
		if v, ok := value(line, "AllowedIPs"); ok {
			cur.IP, _, _ = strings.Cut(v, "/")
		}
	}
	if cur != nil {
		return nil, fmt.Errorf("'# END peer %s' 줄이 없다", cur.Name)
	}
	return peers, nil
}

// NextIP 는 .2~.253 중 가장 작은 빈 칸을 고른다. wg-friend 는 .254 까지 보지만 거기엔 부트스트랩 블록이 있어 늘 찬다.
func NextIP(data []byte) (string, error) {
	used := map[int]bool{BootstrapHost: true}
	for _, line := range splitLines(data) {
		m := allowedRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		n, _ := strconv.Atoi(m[1])
		used[n] = true
	}
	for n := 2; n < BootstrapHost; n++ {
		if !used[n] {
			return fmt.Sprintf("%s.%d", SubnetPrefix, n), nil
		}
	}
	return "", ErrNoFreeIP
}

// AppendPeer 는 wg-friend cmd_add 의 printf 와 같은 블록을 덧붙인다. 다른 점은 BEGIN 다음의 by 주석 한 줄뿐이다.
// PresharedKey 가 비었으면 그 줄을 안 쓴다 (부트스트랩 블록).
func AppendPeer(data []byte, p Peer, now time.Time) []byte {
	var b bytes.Buffer
	b.Write(data)
	fmt.Fprintf(&b, "\n# BEGIN peer %s\n%s%s\n[Peer]\nPublicKey = %s\n", p.Name, byPrefix, now.UTC().Format(time.RFC3339), p.PublicKey)
	if p.PresharedKey != "" {
		fmt.Fprintf(&b, "PresharedKey = %s\n", p.PresharedKey)
	}
	fmt.Fprintf(&b, "AllowedIPs = %s/32\n# END peer %s\n", p.IP, p.Name)
	return b.Bytes()
}

// RemovePeer 는 wg-friend cmd_remove 의 awk 를 그대로 옮긴 것이다 : 블록과 그 바로 앞 빈 줄만 뺀다.
func RemovePeer(data []byte, name string) ([]byte, error) {
	begin, end := "# BEGIN peer "+name, "# END peer "+name
	var out bytes.Buffer
	skip, found := false, false
	blank := 0
	for _, line := range splitLines(data) {
		switch {
		case line == begin:
			skip, found = true, true
			blank = 0
		case skip:
			if line == end {
				skip = false
			}
		case line == "":
			blank++
		default:
			out.WriteString(strings.Repeat("\n", blank))
			blank = 0
			out.WriteString(line + "\n")
		}
	}
	if !found {
		return nil, fmt.Errorf("'%s' 피어가 없다", name)
	}
	if skip {
		return nil, fmt.Errorf("'%s' 줄을 못 찾았다. wg0.conf 를 손으로 확인하라", end)
	}
	out.WriteString(strings.Repeat("\n", blank))
	return out.Bytes(), nil
}

// splitLines 는 awk 처럼 줄을 나눈다 : 마지막 줄바꿈 뒤의 빈 조각은 줄이 아니다.
func splitLines(data []byte) []string {
	s := strings.TrimSuffix(string(data), "\n")
	if s == "" && len(data) == 0 {
		return nil
	}
	return strings.Split(s, "\n")
}

// value 는 `Key = v` 꼴 줄에서 v 를 꺼낸다 (wg-friend 의 sub(/^Key[ \t]*=[ \t]*/, "") 와 같은 셈).
func value(line, key string) (string, bool) {
	rest, ok := strings.CutPrefix(line, key)
	if !ok {
		return "", false
	}
	rest = strings.TrimLeft(rest, " \t")
	rest, ok = strings.CutPrefix(rest, "=")
	if !ok {
		return "", false
	}
	return strings.TrimSpace(rest), true
}
