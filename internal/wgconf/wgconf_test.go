package wgconf

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// 시험용 가짜 키. 실제 키가 아니다.
const sample = `[Interface]
Address    = 10.183.26.1/24
ListenPort = 51820
PrivateKey = FAKE-SERVER-PRIVATE=
SaveConfig = false

# BEGIN peer alice-pc
[Peer]
PublicKey = AAAA=
PresharedKey = PPPP=
AllowedIPs = 10.183.26.2/32
# END peer alice-pc

# BEGIN peer friend3
[Peer]
PublicKey = CCCC=
PresharedKey = QQQQ=
AllowedIPs = 10.183.26.3/32
# END peer friend3
`

var when = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

func TestAppendMatchesWgFriendPrintf(t *testing.T) {
	got := string(AppendPeer([]byte("X\n"), Peer{Name: "bob", PublicKey: "K=", PresharedKey: "S=", IP: "10.183.26.9"}, when))
	// wg-friend printf 와 같고, BEGIN 다음 by 줄 하나만 더해진다
	want := "X\n\n# BEGIN peer bob\n# by accesstool 2026-11-04T12:00:00Z\n[Peer]\nPublicKey = K=\nPresharedKey = S=\nAllowedIPs = 10.183.26.9/32\n# END peer bob\n"
	if got != want {
		t.Fatalf("블록 꼴이 다르다:\n%q\n%q", got, want)
	}
	noPSK := string(AppendPeer(nil, Peer{Name: BootstrapName, PublicKey: "B=", IP: "10.183.26.254"}, when))
	if strings.Contains(noPSK, "PresharedKey") {
		t.Error("PSK 가 없으면 줄도 없어야 한다")
	}
}

func TestPeersAndNextIP(t *testing.T) {
	peers, err := Peers([]byte(sample))
	if err != nil || len(peers) != 2 {
		t.Fatalf("%v %v", peers, err)
	}
	if peers[1] != (Peer{Name: "friend3", PublicKey: "CCCC=", PresharedKey: "QQQQ=", IP: "10.183.26.3"}) {
		t.Errorf("파싱 값: %+v", peers[1])
	}
	ip, _ := NextIP([]byte(sample))
	if ip != "10.183.26.4" {
		t.Errorf("빈 칸 %s", ip)
	}
	// .2 가 비면 .2 부터 채운다
	removed, _ := RemovePeer([]byte(sample), "alice-pc")
	if ip, _ := NextIP(removed); ip != "10.183.26.2" {
		t.Errorf("빈 칸 %s", ip)
	}
}

func TestNextIPSkipsBootstrapAndFull(t *testing.T) {
	var b strings.Builder
	for n := 2; n <= 253; n++ {
		b.WriteString("AllowedIPs = 10.183.26." + strconv.Itoa(n) + "/32\n")
	}
	if _, err := NextIP([]byte(b.String())); err != ErrNoFreeIP {
		t.Errorf(".254 는 줄 수 없으니 꽉 찬 것이어야 한다: %v", err)
	}
}

func TestPeersBrokenBlock(t *testing.T) {
	if _, err := Peers([]byte("# BEGIN peer a\n[Peer]\n")); err == nil {
		t.Error("END 없는 블록은 오류여야 한다")
	}
	if _, err := RemovePeer([]byte("# BEGIN peer a\n[Peer]\n"), "a"); err == nil {
		t.Error("END 없는 블록 제거는 오류여야 한다")
	}
	if _, err := RemovePeer([]byte(sample), "nobody"); err == nil {
		t.Error("없는 피어 제거는 오류여야 한다")
	}
}

func TestAppendRemoveRoundTrip(t *testing.T) {
	added := AppendPeer([]byte(sample), Peer{Name: "new1", PublicKey: "N=", PresharedKey: "S=", IP: "10.183.26.4"}, when)
	peers, _ := Peers(added)
	if len(peers) != 3 || !peers[2].ByAccesstool {
		t.Fatalf("%+v", peers)
	}
	back, err := RemovePeer(added, "new1")
	if err != nil || string(back) != sample {
		t.Fatalf("되돌린 내용이 원본과 다르다: %v\n%q", err, back)
	}
}

// 옛 wg-friend 의 awk 두 개(remove·list)를 그대로 돌려 Go 쪽과 맞춰 본다. awk 가 없으면 건너뛴다.
const wgFriendRemoveAwk = `
        $0 == b { skip = 1; blank = 0; next }
        skip    { if ($0 == e) skip = 0; next }
        /^$/    { blank++; next }
        { while (blank > 0) { print ""; blank-- } print }
        END     { if (skip) exit 3; while (blank > 0) { print ""; blank-- } }
`
const wgFriendListAwk = `
        /^# BEGIN peer / { name = $4; pub = ""; ip = "" }
        /^PublicKey/     { sub(/^PublicKey[ \t]*=[ \t]*/, ""); pub = $0 }
        /^AllowedIPs/    { sub(/^AllowedIPs[ \t]*=[ \t]*/, ""); sub(/\/32.*/, ""); ip = $0 }
        /^# END peer /   { print name, pub, ip }
`

func TestWgFriendAwkCompat(t *testing.T) {
	awk, err := exec.LookPath("awk")
	if err != nil {
		t.Skip("awk 없음")
	}
	conf := AppendPeer([]byte(sample), Peer{Name: "go-made", PublicKey: "G=", PresharedKey: "S=", IP: "10.183.26.4"}, when)
	path := filepath.Join(t.TempDir(), "wg0.conf")
	os.WriteFile(path, conf, 0o600)

	list, err := exec.Command(awk, wgFriendListAwk, path).Output()
	if err != nil {
		t.Fatal(err)
	}
	wantList := "alice-pc AAAA= 10.183.26.2\nfriend3 CCCC= 10.183.26.3\ngo-made G= 10.183.26.4\n"
	if string(list) != wantList {
		t.Errorf("wg-friend list 결과:\n%s", list)
	}

	for _, name := range []string{"go-made", "friend3", "alice-pc"} {
		byAwk, err := exec.Command(awk, "-v", "b=# BEGIN peer "+name, "-v", "e=# END peer "+name, wgFriendRemoveAwk, path).Output()
		if err != nil {
			t.Fatal(err)
		}
		byGo, _ := RemovePeer(conf, name)
		if string(byAwk) != string(byGo) {
			t.Errorf("%s 제거 결과가 다르다:\nawk %q\ngo  %q", name, byAwk, byGo)
		}
	}
}

func TestUpdateWritesBakInPlace(t *testing.T) {
	dir := t.TempDir()
	f := File{Path: filepath.Join(dir, "wg0.conf"), LockPath: filepath.Join(dir, "lock"), BakPath: filepath.Join(dir, "wg0.conf.bak")}
	os.WriteFile(f.Path, []byte(sample), 0o600)

	err := f.Update(func(d []byte) ([]byte, error) { return RemovePeer(d, "friend3") })
	if err != nil {
		t.Fatal(err)
	}
	bak, _ := os.ReadFile(f.BakPath)
	now, _ := f.Read()
	want, _ := RemovePeer([]byte(sample), "friend3")
	if string(bak) != sample || string(now) != string(want) {
		t.Errorf("bak 또는 본문이 틀렸다 (줄어든 뒤 옛 꼬리가 남으면 안 된다)")
	}
	// change 가 실패하면 아무것도 안 쓴다
	before, _ := f.Read()
	f.Update(func(d []byte) ([]byte, error) { return RemovePeer(d, "nobody") })
	after, _ := f.Read()
	if string(before) != string(after) {
		t.Error("실패한 변경이 파일을 건드렸다")
	}
}
