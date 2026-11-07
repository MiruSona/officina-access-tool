//go:build unix

package wgconf

import (
	"os"
	"syscall"
)

// lockFile 은 wg-friend 의 `exec 9>"$LOCK"; flock 9` 와 같은 파일에 같은 배타 잠금을 잡는다.
// 파일은 지우지 않는다 — wg-friend 와 나눠 쓰는 산 잠금이다.
func lockFile(path string) (func(), error) {
	fh, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o660)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(fh.Fd()), syscall.LOCK_EX); err != nil {
		fh.Close()
		return nil, err
	}
	return func() {
		syscall.Flock(int(fh.Fd()), syscall.LOCK_UN)
		fh.Close()
	}, nil
}
