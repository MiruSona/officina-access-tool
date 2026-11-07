package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"sync"
	"time"

	"github.com/MiruSona/officina-access-tool/internal/proto"
	"github.com/MiruSona/officina-access-tool/internal/wgconf"
	"github.com/MiruSona/officina-access-tool/internal/wgctl"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// 폭주 제한 (설계 4장). 부트스트랩 출발지는 .254 하나뿐이라 전체 단위로 건다.
const (
	postPerMinute = 10
	getPerSecond  = 5
	maxPending    = 20
	maxInFlight   = 16
	retryAfterSec = 60
	keepaliveSec  = 25
)

type server struct {
	cfg     config
	conf    wgconf.File
	wg      wgctl.Controller
	session string // 승인 웹 쿠키 값 (토큰에서 나온다)
	now     func() time.Time

	mu       sync.Mutex // reqs 와 wg0.conf 변경을 한 줄로 세운다
	reqs     map[string]*request
	reqsPath string

	postRate *window
	getRate  *window
	slots    chan struct{}
}

func newServer(cfg config, wg wgctl.Controller, token string) (*server, error) {
	reqsPath := filepath.Join(cfg.StateDir, "requests.json")
	reqs, err := loadRequests(reqsPath)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", reqsPath, err)
	}
	return &server{
		cfg:      cfg,
		conf:     wgconf.File{Path: cfg.WgConf, LockPath: cfg.Lock, BakPath: filepath.Join(cfg.StateDir, "wg0.conf.bak")},
		wg:       wg,
		session:  sessionValue(token),
		now:      time.Now,
		reqs:     reqs,
		reqsPath: reqsPath,
		postRate: &window{limit: postPerMinute, period: time.Minute},
		getRate:  &window{limit: getPerSecond, period: time.Second},
		slots:    make(chan struct{}, maxInFlight),
	}, nil
}

// errConflict 는 사람이 고칠 수 있는 거절이다 (이름 겹침 등). 승인 웹에 문구 그대로 보인다.
var errConflict = errors.New("충돌")

var (
	errNameTaken   = fmt.Errorf("%w: %s", errConflict, proto.ErrNameTaken)
	errPubkeyTaken = fmt.Errorf("%w: %s", errConflict, proto.ErrPubkeyTaken)
)

func (s *server) approve(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	req := s.reqs[id]
	if req == nil || req.State != proto.StatePending {
		return fmt.Errorf("%w: 대기 중인 요청이 아니다", errConflict)
	}
	pub, err := wgtypes.ParseKey(req.Pubkey)
	if err != nil {
		return err
	}
	psk, err := wgtypes.GenerateKey()
	if err != nil {
		return err
	}

	var ip string
	err = s.conf.Update(func(data []byte) ([]byte, error) {
		if err := checkFree(data, req.Name, req.Pubkey); err != nil {
			return nil, err
		}
		ip, err = wgconf.NextIP(data)
		if err != nil {
			return nil, err
		}
		peer := wgconf.Peer{Name: req.Name, PublicKey: req.Pubkey, PresharedKey: psk.String(), IP: ip}
		return wgconf.AppendPeer(data, peer, s.now()), nil
	})
	if err != nil {
		return err
	}
	// 파일과 살아 있는 인터페이스가 어긋나지 않게 블록을 도로 뺀다
	undoFile := func() error {
		return s.conf.Update(func(data []byte) ([]byte, error) { return wgconf.RemovePeer(data, req.Name) })
	}
	if err := s.wg.AddPeer(pub, psk, net.ParseIP(ip)); err != nil {
		return errors.Join(fmt.Errorf("wg 피어 추가 실패: %w", err), undoFile())
	}

	sealed, err := proto.SealPSK(psk, pub)
	if err == nil {
		prev := *req
		req.State = proto.StateApproved
		req.Decided = s.now()
		req.Address = ip + "/32"
		req.PSKSealed = sealed
		if err = saveRequests(s.reqsPath, s.reqs); err != nil {
			*req = prev
		}
	}
	if err != nil {
		// 기록이 pending 으로 남으니 피어도 빼야 다시 승인할 때 pubkey_taken 에 안 막힌다
		return errors.Join(err, s.wg.RemovePeer(pub), undoFile())
	}
	return nil
}

func (s *server) reject(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	req := s.reqs[id]
	if req == nil || req.State != proto.StatePending {
		return fmt.Errorf("%w: 대기 중인 요청이 아니다", errConflict)
	}
	req.State = proto.StateRejected
	req.Decided = s.now()
	return saveRequests(s.reqsPath, s.reqs)
}

// revoke 는 wg-friend 로 넣은 피어도 뺄 수 있다. 부트스트랩 블록은 install.sh 몫이라 막는다.
func (s *server) revoke(name string) error {
	if !proto.ValidName(name) || name == wgconf.BootstrapName {
		return fmt.Errorf("%w: 회수할 수 없는 이름이다", errConflict)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var pubText string
	err := s.conf.Update(func(data []byte) ([]byte, error) {
		peers, err := wgconf.Peers(data)
		if err != nil {
			return nil, err
		}
		for _, p := range peers {
			if p.Name == name {
				pubText = p.PublicKey
			}
		}
		return wgconf.RemovePeer(data, name)
	})
	if err != nil {
		return err
	}
	// 옛 승인 기록을 지운다 — 남기면 같은 공개키 재요청이 회수된 설정을 다시 받는다
	saveErr := s.forgetPubkey(pubText)
	pub, err := wgtypes.ParseKey(pubText)
	if err != nil {
		return errors.Join(fmt.Errorf("블록은 뺐지만 공개키를 못 읽어 살아 있는 피어는 reload 때 빠진다: %w", err), saveErr)
	}
	return errors.Join(s.wg.RemovePeer(pub), saveErr)
}

// forgetPubkey 는 그 공개키의 요청 기록을 지운다. s.mu 를 잡은 채 부른다.
func (s *server) forgetPubkey(pub string) error {
	changed := false
	for id, r := range s.reqs {
		if pub != "" && r.Pubkey == pub {
			delete(s.reqs, id)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return saveRequests(s.reqsPath, s.reqs)
}

// checkFree 는 이름·공개키가 wg0.conf 에 없는지 본다.
func checkFree(data []byte, name, pubkey string) error {
	peers, err := wgconf.Peers(data)
	if err != nil {
		return err
	}
	for _, p := range peers {
		if p.PublicKey == pubkey {
			return errPubkeyTaken
		}
		if p.Name == name {
			return errNameTaken
		}
	}
	return nil
}

func (s *server) cleanup() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !expire(s.reqs, s.now()) {
		return nil
	}
	return saveRequests(s.reqsPath, s.reqs)
}

func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// window 는 고정 창 하나짜리 횟수 제한이다.
type window struct {
	mu     sync.Mutex
	limit  int
	period time.Duration
	start  time.Time
	count  int
}

func (w *window) allow(now time.Time) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if now.Sub(w.start) >= w.period {
		w.start = now
		w.count = 0
	}
	if w.count >= w.limit {
		return false
	}
	w.count++
	return true
}
