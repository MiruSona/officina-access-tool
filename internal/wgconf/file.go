package wgconf

import (
	"fmt"
	"os"
)

// File 은 wg0.conf 하나와 wg-friend 와 같이 잡는 잠금 파일이다.
type File struct {
	Path     string // /etc/wireguard/wg0.conf
	LockPath string // /run/wg-friend.lock
	BakPath  string // /var/lib/accesstool/wg0.conf.bak
}

// Read 는 잠금을 잡고 내용을 읽는다 (wg-friend 가 쓰는 중에 반쯤 읽지 않게).
func (f File) Read() ([]byte, error) {
	unlock, err := lockFile(f.LockPath)
	if err != nil {
		return nil, err
	}
	defer unlock()
	return os.ReadFile(f.Path)
}

// Update 는 잠금 안에서 읽기 → change → .bak → 제자리 덮어쓰기를 한다.
// change 가 오류를 내면 아무것도 안 쓴다.
// shortcut: /etc/wireguard 에 쓰기 권한이 없어 tmp+rename 을 못 한다 (설계 3-1). 쓰다 끊기면 .bak 으로 되돌린다.
func (f File) Update(change func(data []byte) ([]byte, error)) error {
	unlock, err := lockFile(f.LockPath)
	if err != nil {
		return err
	}
	defer unlock()

	old, err := os.ReadFile(f.Path)
	if err != nil {
		return err
	}
	data, err := change(old)
	if err != nil {
		return err
	}
	// .bak 에는 서버 비밀키가 들어 있다 — 0600
	if err := writeSync(f.BakPath, old, os.O_CREATE); err != nil {
		return fmt.Errorf("백업 실패, wg0.conf 는 안 건드렸다: %w", err)
	}
	if err := writeSync(f.Path, data, 0); err != nil {
		return fmt.Errorf("wg0.conf 쓰기 실패, 직전 판은 %s: %w", f.BakPath, err)
	}
	return nil
}

// writeSync 는 자르지 않고 덮어쓴 뒤 길이를 맞추고 fsync 한다. 있는 파일의 소유자·권한은 그대로 둔다.
// O_TRUNC 를 안 쓰는 까닭: 쓰다 죽으면 0바이트 wg0.conf 가 남아 부팅 때 wg0 이 안 뜬다.
// shortcut: 새 내용이 더 짧을 때 Write 와 Truncate 사이에 죽으면 꼬리에 옛 내용이 남는다 — 그때는 .bak 으로 되돌린다.
func writeSync(path string, data []byte, extra int) error {
	fh, err := os.OpenFile(path, os.O_WRONLY|extra, 0o600)
	if err != nil {
		return err
	}
	if _, err := fh.Write(data); err != nil {
		fh.Close()
		return err
	}
	if err := fh.Truncate(int64(len(data))); err != nil {
		fh.Close()
		return err
	}
	if err := fh.Sync(); err != nil {
		fh.Close()
		return err
	}
	return fh.Close()
}
