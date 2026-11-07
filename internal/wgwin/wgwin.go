// Package wgwin 은 친구 PC 의 Windows WireGuard 앱과 PC 설정(ACL)을 다룬다.
// 이 파일은 OS 와 상관없는 조각이고, 서비스·관리자 권한은 system_windows.go 에 있다.
package wgwin

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// MSIURL 은 옛 INSTALL.bat 과 같은 고정 판이다. SHA256 은 join.conf(msi_sha256)나 기본값으로 대조한다.
const MSIURL = "https://download.wireguard.com/windows-client/wireguard-amd64-1.1.1.msi"

const maxMSIBytes = 64 << 20

// 친구가 읽는 실패 문구 (옛 INSTALL.bat 의 실패 칸과 같은 말).
var (
	ErrDownload    = errors.New("WireGuard 를 내려받지 못했습니다. 인터넷 연결을 확인하고 다시 실행하세요")
	ErrBadFile     = errors.New("내려받은 파일이 손상됐습니다. 서버장에게 알려 주세요")
	ErrMSI         = errors.New("WireGuard 설치에 실패했습니다. 이 화면을 찍어 서버장에게 보내 주세요")
	ErrService     = errors.New("등록 실패. 이 화면을 찍어 서버장에게 보내 주세요")
	ErrNotElevated = errors.New("'예' 를 눌러야 설치됩니다. 다시 실행하고 '예' 를 눌러 주세요")
)

// Download 는 url 을 dst 에 받고 SHA256 이 맞는지 본다. 안 맞으면 dst 를 지우고 ErrBadFile.
// 대조를 통과하기 전에는 파일을 실행하는 길이 없다 (부르는 쪽은 nil 일 때만 msiexec 를 부른다).
func Download(client *http.Client, url, dst, wantSHA256 string) error {
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("%w (%v)", ErrDownload, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w (HTTP %d)", ErrDownload, resp.StatusCode)
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(out, h), io.LimitReader(resp.Body, maxMSIBytes))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(dst)
		return fmt.Errorf("%w (%v)", ErrDownload, err)
	}
	if !strings.EqualFold(hex.EncodeToString(h.Sum(nil)), wantSHA256) {
		os.Remove(dst)
		return ErrBadFile
	}
	return nil
}
