package joinflow

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/MiruSona/officina-access-tool/internal/proto"
)

type fakeSys struct {
	running bool
	noPing  bool
	calls   []string
	confs   map[string]string // 터널 이름 → 등록 때 conf 내용
}

func (s *fakeSys) TunnelRunning(name string) bool { return s.running }
func (s *fakeSys) Ping(host string) bool          { return !s.noPing }
func (s *fakeSys) EnsureWireGuard(sha string) error {
	s.calls = append(s.calls, "ensure")
	return nil
}
func (s *fakeSys) InstallTunnel(path string) error {
	name := strings.TrimSuffix(filepath.Base(path), ".conf")
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	s.confs[name] = string(data)
	s.calls = append(s.calls, "install "+name)
	return nil
}
func (s *fakeSys) RemoveTunnel(name string) error {
	s.calls = append(s.calls, "remove "+name)
	return nil
}

// fakeServer 는 접수 API 흉내다. states 를 GET 마다 하나씩 꺼낸다 (마지막 값은 계속).
type fakeServer struct {
	t         *testing.T
	serverPub string
	posts     []proto.JoinRequest
	postCodes []int // POST 마다 돌려줄 상태. 다 쓰면 202
	states    []string
	codeOver  string // 비어 있지 않으면 확인 코드를 이 값으로 속인다
}

func (fs *fakeServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/join", func(w http.ResponseWriter, r *http.Request) {
		var in proto.JoinRequest
		json.NewDecoder(r.Body).Decode(&in)
		fs.posts = append(fs.posts, in)
		if len(fs.postCodes) > 0 {
			code := fs.postCodes[0]
			fs.postCodes = fs.postCodes[1:]
			w.WriteHeader(code)
			json.NewEncoder(w).Encode(proto.ErrorResponse{Error: proto.ErrNameTaken})
			return
		}
		pub, _ := proto.ParseKey(in.Pubkey)
		code := proto.ConfirmCode(pub)
		if fs.codeOver != "" {
			code = fs.codeOver
		}
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(proto.JoinAccepted{ID: "req1", Code: code, PollAfter: 10})
	})
	mux.HandleFunc("GET /v1/join/{id}", func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("id") != "req1" {
			http.NotFound(w, r)
			return
		}
		state := fs.states[0]
		if len(fs.states) > 1 {
			fs.states = fs.states[1:]
		}
		out := proto.JoinStatus{State: state}
		if state == proto.StateApproved {
			out.Config = fs.approvedConfig()
		}
		json.NewEncoder(w).Encode(out)
	})
	return mux
}

// approvedConfig 는 가장 최근 POST 의 공개키에 PSK 를 봉한다.
func (fs *fakeServer) approvedConfig() *proto.PeerConfig {
	pubText := fs.posts[len(fs.posts)-1].Pubkey
	pub, err := proto.ParseKey(pubText)
	if err != nil {
		fs.t.Fatal(err)
	}
	var psk [32]byte
	psk[0] = 7
	sealed, err := proto.SealPSK(psk, pub)
	if err != nil {
		fs.t.Fatal(err)
	}
	return &proto.PeerConfig{Address: "127.0.0.7/32", ServerPubkey: fs.serverPub, Endpoint: "evil.example:1",
		AllowedIPs: []string{"0.0.0.0/0"}, Keepalive: 25, PSKSealed: sealed}
}

type rig struct {
	flow  *Flow
	sys   *fakeSys
	srv   *fakeServer
	asked []string
	said  []string
}

func newRig(t *testing.T, names ...string) *rig {
	t.Helper()
	boot, _ := wgtypes.GeneratePrivateKey()
	server, _ := wgtypes.GeneratePrivateKey()
	r := &rig{sys: &fakeSys{confs: map[string]string{}}}
	r.srv = &fakeServer{t: t, serverPub: server.PublicKey().String(), states: []string{proto.StateApproved}}
	ts := httptest.NewServer(r.srv.handler())
	t.Cleanup(ts.Close)
	addr := netip.MustParseAddrPort(strings.TrimPrefix(ts.URL, "http://"))

	cfg := Config{BootstrapPrivateKey: boot.String(), Endpoint: "home.example:51820", ServerPublicKey: r.srv.serverPub,
		ServerIP: addr.Addr(), IntakePort: int(addr.Port()), MSISHA256: DefaultMSISHA256}
	r.flow = &Flow{
		Cfg: cfg, Dir: t.TempDir(), Sys: r.sys, HTTP: ts.Client(),
		AskName: func(reason string) (string, error) {
			r.asked = append(r.asked, reason)
			if len(r.asked) > len(names) {
				return "", errors.New("이름을 너무 많이 물었다")
			}
			return names[len(r.asked)-1], nil
		},
		Say: func(m string) { r.said = append(r.said, m) }, ShowCode: func(string) {}, Sleep: func(time.Duration) {},
		PollEvery: time.Millisecond, MaxNetTries: 2,
	}
	return r
}

func TestPendingThenApproved(t *testing.T) {
	r := newRig(t, "Bad Name", "chulsoo")
	r.srv.states = []string{proto.StatePending, proto.StatePending, proto.StateApproved}
	if err := r.flow.Run(false); err != nil {
		t.Fatal(err)
	}
	if len(r.asked) != 2 {
		t.Fatalf("규칙에 안 맞는 이름은 다시 물어야 한다: %v", r.asked)
	}
	want := []string{"ensure", "remove home-games", "remove home-games-join", "install home-games-join",
		"remove home-games-join", "remove home-games", "install home-games"}
	if strings.Join(r.sys.calls, ",") != strings.Join(want, ",") {
		t.Fatalf("순서가 다르다 (부트스트랩을 먼저 내려야 한다)\n got %v\nwant %v", r.sys.calls, want)
	}
	if !strings.Contains(r.sys.confs["home-games-join"], "Address = 127.0.0.254/32") {
		t.Fatalf("부트스트랩 conf:\n%s", r.sys.confs["home-games-join"])
	}
	conf := r.sys.confs["home-games"]
	var psk [32]byte
	psk[0] = 7
	for _, line := range []string{"Address = 127.0.0.7/32", "PresharedKey = " + wgtypes.Key(psk).String(),
		"Endpoint = home.example:51820", "AllowedIPs = 127.0.0.1/32", "PersistentKeepalive = 25"} {
		if !strings.Contains(conf, line+"\r\n") {
			t.Fatalf("진짜 conf 에 %q 가 없다 (응답의 endpoint·allowed_ips 는 무시해야 한다):\n%s", line, conf)
		}
	}
	if last := r.said[len(r.said)-1]; !strings.Contains(last, "게임 접속 주소: 127.0.0.1") {
		t.Fatalf("끝에 터널 서버 IP 를 알려야 한다: %q", last)
	}
	st, _ := LoadState(r.flow.Dir)
	if st == nil || st.Name != "chulsoo" || st.RequestID != "req1" {
		t.Fatalf("join.json: %+v", st)
	}
}

func TestNameTakenAsksAgain(t *testing.T) {
	r := newRig(t, "chulsoo", "chulsoo2")
	r.srv.postCodes = []int{http.StatusConflict}
	if err := r.flow.Run(false); err != nil {
		t.Fatal(err)
	}
	if len(r.srv.posts) != 2 || r.srv.posts[1].Name != "chulsoo2" || r.srv.posts[0].Pubkey != r.srv.posts[1].Pubkey {
		t.Fatalf("이름만 바꿔 같은 키로 다시 보내야 한다: %+v", r.srv.posts)
	}
	if r.asked[1] == "" {
		t.Fatal("두 번째 물음에는 까닭이 있어야 한다")
	}
}

func TestRejectedRemovesState(t *testing.T) {
	r := newRig(t, "chulsoo")
	r.srv.states = []string{proto.StatePending, proto.StateRejected}
	if err := r.flow.Run(false); !errors.Is(err, ErrRejected) {
		t.Fatalf("ErrRejected 여야 한다: %v", err)
	}
	if st, _ := LoadState(r.flow.Dir); st != nil {
		t.Fatal("거절이면 join.json 을 지워야 한다")
	}
	if last := r.sys.calls[len(r.sys.calls)-1]; last != "remove home-games-join" {
		t.Fatalf("부트스트랩을 내려야 한다: %v", r.sys.calls)
	}
	if _, ok := r.sys.confs["home-games"]; ok {
		t.Fatal("거절인데 진짜 터널을 등록했다")
	}
}

func TestResumeKeepsKeyAndSkipsPost(t *testing.T) {
	r := newRig(t)
	key, _ := wgtypes.GeneratePrivateKey()
	st := &State{Name: "chulsoo", PrivateKey: key.String(), RequestID: "req1", Code: "ABCDEF"}
	if err := SaveState(r.flow.Dir, st); err != nil {
		t.Fatal(err)
	}
	// 봉할 공개키를 서버가 알도록 POST 기록만 미리 채운다
	r.srv.posts = []proto.JoinRequest{{Name: "chulsoo", Pubkey: key.PublicKey().String()}}
	if err := r.flow.Run(false); err != nil {
		t.Fatal(err)
	}
	if len(r.asked) != 0 || len(r.srv.posts) != 1 {
		t.Fatalf("이어 가기는 이름을 안 묻고 POST 도 안 한다: asked=%v posts=%d", r.asked, len(r.srv.posts))
	}
}

func TestUnknownIDPostsAgain(t *testing.T) {
	r := newRig(t)
	key, _ := wgtypes.GeneratePrivateKey()
	SaveState(r.flow.Dir, &State{Name: "chulsoo", PrivateKey: key.String(), RequestID: "gone", Code: "ABCDEF"})
	if err := r.flow.Run(false); err != nil {
		t.Fatal(err)
	}
	if len(r.srv.posts) != 1 || r.srv.posts[0].Pubkey != key.PublicKey().String() {
		t.Fatalf("404 면 같은 키로 새로 POST 한다: %+v", r.srv.posts)
	}
}

func TestAlreadyConnected(t *testing.T) {
	r := newRig(t)
	r.sys.running = true
	if err := r.flow.Run(false); err != nil || len(r.sys.calls) != 0 {
		t.Fatalf("이미 연결이면 아무것도 안 한다: err=%v calls=%v", err, r.sys.calls)
	}
}

func TestRejectsForgedResponses(t *testing.T) {
	r := newRig(t, "chulsoo")
	r.srv.codeOver = "ZZZZZZ"
	if err := r.flow.Run(false); err == nil || !strings.Contains(err.Error(), "확인 코드") {
		t.Fatalf("코드가 키와 안 맞으면 멈춰야 한다: %v", err)
	}

	r = newRig(t, "chulsoo")
	other, _ := wgtypes.GeneratePrivateKey()
	r.srv.serverPub = other.PublicKey().String() // 응답만 다른 서버 키를 댄다
	if err := r.flow.Run(false); err == nil || !strings.Contains(err.Error(), "서버 공개키") {
		t.Fatalf("응답 서버 키가 join.conf 와 다르면 멈춰야 한다: %v", err)
	}
	if _, ok := r.sys.confs["home-games"]; ok {
		t.Fatal("가짜 응답으로 진짜 터널을 등록했다")
	}
}

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	boot, _ := wgtypes.GeneratePrivateKey()
	server, _ := wgtypes.GeneratePrivateKey()
	base := "bootstrap_private_key = " + boot.String() + "\nendpoint = home.example:51820\nserver_public_key = " + server.PublicKey().String() + "\n"
	path := filepath.Join(dir, "join.conf")

	os.WriteFile(path, []byte(base), 0o600)
	c, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.ServerIP.String() != "10.183.26.1" || c.IntakePort != 7480 || c.MSISHA256 != DefaultMSISHA256 {
		t.Fatalf("기본값: %+v", c)
	}
	if !strings.Contains(c.BootstrapConf(), "Address = 10.183.26.254/32\r\n") {
		t.Fatal(c.BootstrapConf())
	}

	for _, bad := range []string{"intake_port = 0\n", "msi_sha256 = abc\n", "host_name = home.internal\n", "server_ip = ::1\n", "nope = 1\n"} {
		os.WriteFile(path, []byte(base+bad), 0o600)
		if _, err := LoadConfig(path); err == nil {
			t.Errorf("%q 를 받으면 안 된다", bad)
		}
	}
	os.WriteFile(path, []byte(strings.Replace(base, "home.example:51820", "home.example", 1)), 0o600)
	if _, err := LoadConfig(path); err == nil {
		t.Error("포트 없는 endpoint 를 받으면 안 된다")
	}
}

func TestFailedRequestRestoresMainTunnel(t *testing.T) {
	r := newRig(t, "chulsoo")
	os.WriteFile(filepath.Join(r.flow.Dir, MainTunnel+".conf"), []byte("옛 conf"), 0o600)
	r.srv.postCodes = []int{http.StatusInternalServerError}
	if err := r.flow.Run(true); err == nil {
		t.Fatal("서버 오류면 실패해야 한다")
	}
	got := strings.Join(r.sys.calls[len(r.sys.calls)-2:], ",")
	if got != "remove home-games-join,install home-games" || r.sys.confs["home-games"] != "옛 conf" {
		t.Fatalf("실패하면 옛 진짜 터널을 되살려야 한다: %v", r.sys.calls)
	}
}

func TestSavedConfReconnectsWithoutPost(t *testing.T) {
	r := newRig(t)
	os.WriteFile(filepath.Join(r.flow.Dir, MainTunnel+".conf"), []byte("옛 conf"), 0o600)
	if err := r.flow.Run(false); err != nil {
		t.Fatal(err)
	}
	if len(r.srv.posts) != 0 || r.sys.confs["home-games"] != "옛 conf" {
		t.Fatalf("conf 가 있으면 POST 없이 그 conf 로 다시 깔아야 한다: posts=%d calls=%v", len(r.srv.posts), r.sys.calls)
	}

	r.sys.noPing = true
	if err := r.flow.Run(false); err == nil || !strings.Contains(err.Error(), "--rejoin") || len(r.srv.posts) != 0 {
		t.Fatalf("ping 이 안 되면 --rejoin 안내로 끝나야 한다: %v", err)
	}
}
