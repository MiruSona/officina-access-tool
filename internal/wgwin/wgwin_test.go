package wgwin

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestDownloadChecksSHA256(t *testing.T) {
	body := []byte("가짜 msi")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(body) }))
	defer ts.Close()
	sum := sha256.Sum256(body)
	good := hex.EncodeToString(sum[:])
	dir := t.TempDir()

	if err := Download(ts.Client(), ts.URL, filepath.Join(dir, "a.msi"), good); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(dir, "b.msi")
	if err := Download(ts.Client(), ts.URL, bad, DefaultBadHash); !errors.Is(err, ErrBadFile) {
		t.Fatalf("해시가 다르면 ErrBadFile: %v", err)
	}
	if _, err := os.Stat(bad); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("해시가 다른 파일은 남기지 않는다")
	}
}

const DefaultBadHash = "0000000000000000000000000000000000000000000000000000000000000000"
