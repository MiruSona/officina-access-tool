//go:build !unix

package wgconf

import "sync"

var devLock sync.Mutex

// lockFile 은 개발 PC(Windows) 시험용이다. 프로세스 안에서만 막는다.
// shortcut: wg-friend 와의 프로세스 사이 잠금은 unix 판에만 있다. 데몬은 리눅스에서만 돈다.
func lockFile(string) (func(), error) {
	devLock.Lock()
	return devLock.Unlock, nil
}
