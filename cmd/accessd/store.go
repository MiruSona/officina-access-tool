package main

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/MiruSona/officina-access-tool/internal/proto"
)

const (
	pendingTTL = 24 * time.Hour
	resultTTL  = 7 * 24 * time.Hour
)

// request 는 가입 요청 하나다. 승인 전에는 wg 피어가 아니라 이 줄 하나일 뿐이다.
// PSK 원문은 여기 없다 — 친구 공개키에 봉한 것만 둔다.
type request struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Pubkey    string    `json:"pubkey"`
	Code      string    `json:"code"`
	State     string    `json:"state"`
	Created   time.Time `json:"created"`
	Decided   time.Time `json:"decided,omitempty"`
	Address   string    `json:"address,omitempty"`
	PSKSealed string    `json:"psk_sealed,omitempty"`
	Fetched   time.Time `json:"fetched,omitempty"` // 친구가 승인 설정을 처음 가져간 때. 옛 파일엔 없다(영값)
}

func loadRequests(path string) (map[string]*request, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]*request{}, nil
	}
	if err != nil {
		return nil, err
	}
	var list []*request
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, err
	}
	out := make(map[string]*request, len(list))
	for _, r := range list {
		out[r.ID] = r
	}
	return out, nil
}

// saveRequests 는 tmp 에 쓰고 rename 한다 (상태 폴더는 데몬 것이라 가능).
func saveRequests(path string, reqs map[string]*request) error {
	list := make([]*request, 0, len(reqs))
	for _, r := range reqs {
		list = append(list, r)
	}
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".requests-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// expire 는 오래된 pending 을 expired 로 바꾸고, 결정 뒤 7일 지난 요청을 지운다. 바뀐 게 있으면 true.
// approved 는 친구가 가져간 뒤 7일에 지운다. 안 가져갔으면 남긴다 (revoke 가 지운다).
func expire(reqs map[string]*request, now time.Time) bool {
	changed := false
	for id, r := range reqs {
		if r.State == proto.StatePending && now.Sub(r.Created) > pendingTTL {
			r.State = proto.StateExpired
			r.Decided = now
			changed = true
			continue
		}
		since := r.Decided
		if r.State == proto.StateApproved {
			if r.Fetched.IsZero() {
				continue
			}
			since = r.Fetched
		}
		if r.State != proto.StatePending && now.Sub(since) > resultTTL {
			delete(reqs, id)
			changed = true
		}
	}
	return changed
}
