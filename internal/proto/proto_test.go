package proto

import (
	"encoding/base64"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestValidName(t *testing.T) {
	good := []string{"a", "chulsoo", "alice-pc", "0x", strings.Repeat("a", 20)}
	bad := []string{"", "-a", "Abc", "a_b", "a b", strings.Repeat("a", 21), "철수", "a\n"}
	for _, n := range good {
		if !ValidName(n) {
			t.Errorf("%q 는 통과해야 한다", n)
		}
	}
	for _, n := range bad {
		if ValidName(n) {
			t.Errorf("%q 는 막혀야 한다", n)
		}
	}
}

func TestParseKey(t *testing.T) {
	k, _ := wgtypes.GeneratePrivateKey()
	got, err := ParseKey(k.String())
	if err != nil || got != [32]byte(k) {
		t.Fatalf("왕복 실패: %v", err)
	}
	if _, err := ParseKey(base64.StdEncoding.EncodeToString(make([]byte, 31))); err == nil {
		t.Error("31바이트는 거부해야 한다")
	}
	if _, err := ParseKey(k.String()[:20] + "\n" + k.String()[20:]); err == nil {
		t.Error("줄바꿈이 낀 키는 거부해야 한다 (wg0.conf 줄 주입)")
	}
	if _, err := ParseKey("!!!"); err == nil {
		t.Error("base64 아닌 것은 거부해야 한다")
	}
}

func TestConfirmCode(t *testing.T) {
	var a, b [32]byte
	b[0] = 1
	ca, cb := ConfirmCode(a), ConfirmCode(b)
	if len(ca) != 6 || ca == cb {
		t.Fatalf("코드 %q %q", ca, cb)
	}
	if ca != ConfirmCode(a) {
		t.Error("같은 키는 같은 코드여야 한다")
	}
	// 0바이트 32개의 SHA-256 은 66687aad... → base32 앞 6자리 고정값
	if ca != "MZUHVL" {
		t.Errorf("알려진 값과 다르다: %q", ca)
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	priv, _ := wgtypes.GeneratePrivateKey()
	pub := priv.PublicKey()
	psk, _ := wgtypes.GenerateKey()

	sealed, err := SealPSK(psk, pub)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenPSK(sealed, pub, priv)
	if err != nil || got != [32]byte(psk) {
		t.Fatalf("열기 실패: %v", err)
	}

	other, _ := wgtypes.GeneratePrivateKey()
	if _, err := OpenPSK(sealed, other.PublicKey(), other); err == nil {
		t.Error("다른 키로는 열리면 안 된다")
	}
}
