// Package proto 는 접수 API 의 요청·응답 꼴과 양쪽(데몬·친구 exe)이 같이 쓰는 검사·암호 함수다.
// 프로토콜 원문 : Docs/Design/2026-11-04-승인형가입설계.md 4장
package proto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"

	"golang.org/x/crypto/nacl/box"
)

// 요청 상태. GET /v1/join/<id> 의 state 칸 값이다.
const (
	StatePending  = "pending"
	StateApproved = "approved"
	StateRejected = "rejected"
	StateExpired  = "expired"
)

// 409·429 의 error 칸 값.
const (
	ErrNameTaken   = "name_taken"
	ErrPubkeyTaken = "pubkey_taken"
	ErrBusy        = "busy"
)

// MaxBodyBytes 는 POST /v1/join 본문 상한이다.
const MaxBodyBytes = 1024

// nameRe 는 옛 wg-friend 의 check_name 과 같은 규칙이다.
var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,19}$`)

type JoinRequest struct {
	Name   string `json:"name"`
	Pubkey string `json:"pubkey"`
	Client string `json:"client"`
}

// JoinAccepted 는 202 응답이다.
type JoinAccepted struct {
	ID        string `json:"id"`
	Code      string `json:"code"`
	PollAfter int    `json:"poll_after"`
}

type ErrorResponse struct {
	Error      string `json:"error"`
	RetryAfter int    `json:"retry_after,omitempty"`
}

type JoinStatus struct {
	State  string      `json:"state"`
	Config *PeerConfig `json:"config,omitempty"`
}

// PeerConfig 는 친구 conf 를 만드는 데 드는 값이다. PSKSealed 말고는 비밀이 아니다.
type PeerConfig struct {
	Address      string   `json:"address"`
	ServerPubkey string   `json:"server_pubkey"`
	Endpoint     string   `json:"endpoint"`
	AllowedIPs   []string `json:"allowed_ips"`
	Keepalive    int      `json:"keepalive"`
	PSKSealed    string   `json:"psk_sealed"`
}

func ValidName(name string) bool {
	return nameRe.MatchString(name)
}

// ParseKey 는 base64 로 적힌 32바이트 WireGuard 키를 읽는다.
func ParseKey(s string) ([32]byte, error) {
	var key [32]byte
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return key, fmt.Errorf("키가 base64 가 아니다: %w", err)
	}
	if len(raw) != 32 {
		return key, fmt.Errorf("키 길이가 %d 바이트다 (32 여야 한다)", len(raw))
	}
	// 디코더는 줄바꿈을 건너뛴다. 이 값이 wg0.conf 한 줄로 들어가므로 정규형만 받는다
	if base64.StdEncoding.EncodeToString(raw) != s {
		return key, errors.New("키가 정규 base64 꼴이 아니다")
	}
	copy(key[:], raw)
	return key, nil
}

// ConfirmCode 는 공개키 SHA-256 을 base32 로 적은 앞 6자리다. 친구 화면과 승인 웹에 같은 값이 뜬다.
func ConfirmCode(pubkey [32]byte) string {
	sum := sha256.Sum256(pubkey[:])
	return base32.StdEncoding.EncodeToString(sum[:])[:6]
}

// SealPSK 는 PSK 를 친구 공개키에 봉한다. WireGuard 키가 Curve25519 라 NaCl box 키로 그대로 쓴다.
func SealPSK(psk, recipient [32]byte) (string, error) {
	sealed, err := box.SealAnonymous(nil, psk[:], &recipient, rand.Reader)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// OpenPSK 는 SealPSK 로 봉한 PSK 를 친구 키쌍으로 연다.
func OpenPSK(sealed string, pub, priv [32]byte) ([32]byte, error) {
	var psk [32]byte
	raw, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil {
		return psk, fmt.Errorf("psk_sealed 가 base64 가 아니다: %w", err)
	}
	opened, ok := box.OpenAnonymous(nil, raw, &pub, &priv)
	if !ok {
		return psk, errors.New("psk_sealed 를 열지 못했다 (다른 키에 봉했거나 깨짐)")
	}
	if len(opened) != 32 {
		return psk, fmt.Errorf("열린 PSK 길이가 %d 바이트다", len(opened))
	}
	copy(psk[:], opened)
	return psk, nil
}
