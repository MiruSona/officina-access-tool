package main

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MiruSona/officina-access-tool/internal/proto"
	"github.com/MiruSona/officina-access-tool/internal/wgconf"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const testToken = "0123456789abcdef0123456789abcdef-test-token"

type fakeWG struct {
	peers   map[string]wgtypes.Key // pub → psk
	failAdd bool
	hs      map[string]time.Time
}

func (f *fakeWG) AddPeer(pub, psk wgtypes.Key, _ net.IP) error {
	if f.failAdd {
		return errors.New("가짜 실패")
	}
	f.peers[pub.String()] = psk
	return nil
}

func (f *fakeWG) RemovePeer(pub wgtypes.Key) error {
	delete(f.peers, pub.String())
	return nil
}

func (f *fakeWG) Handshakes() (map[string]time.Time, error) {
	return f.hs, nil
}

type harness struct {
	s      *server
	wg     *fakeWG
	intake http.Handler
	web    http.Handler
	clock  time.Time
}

func newHarness(t *testing.T, conf string) *harness {
	t.Helper()
	dir := t.TempDir()
	serverKey, _ := wgtypes.GeneratePrivateKey()
	cfg := config{
		IntakeListen: "10.183.26.1:7480", WebListen: "192.168.1.10:7481",
		WgConf: filepath.Join(dir, "wg0.conf"), Lock: filepath.Join(dir, "lock"), StateDir: dir,
		Interface: "wg0", BootstrapIP: "10.183.26.254",
		ServerPublicKey: serverKey.PublicKey().String(), Endpoint: "example.invalid:51820",
	}
	os.WriteFile(cfg.WgConf, []byte(conf), 0o600)
	h := &harness{wg: &fakeWG{peers: map[string]wgtypes.Key{}}, clock: time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)}
	s, err := newServer(cfg, h.wg, testToken)
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return h.clock }
	h.s, h.intake, h.web = s, s.intakeHandler(), s.webHandler(testToken)
	return h
}

func (h *harness) post(name, pub string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(proto.JoinRequest{Name: name, Pubkey: pub, Client: "test"})
	r := httptest.NewRequest("POST", "/v1/join", strings.NewReader(string(body)))
	r.RemoteAddr = "10.183.26.254:40000"
	w := httptest.NewRecorder()
	h.intake.ServeHTTP(w, r)
	return w
}

func (h *harness) status(id string) (int, proto.JoinStatus) {
	r := httptest.NewRequest("GET", "/v1/join/"+id, nil)
	r.RemoteAddr = "10.183.26.254:40000"
	w := httptest.NewRecorder()
	h.intake.ServeHTTP(w, r)
	var st proto.JoinStatus
	json.Unmarshal(w.Body.Bytes(), &st)
	return w.Code, st
}

func (h *harness) webPost(path string, form url.Values, origin string, cookie bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "http://192.168.1.10:7481"+path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", origin)
	if cookie {
		r.AddCookie(&http.Cookie{Name: cookieName, Value: sessionValue(testToken)})
	}
	w := httptest.NewRecorder()
	h.web.ServeHTTP(w, r)
	return w
}

const okOrigin = "http://192.168.1.10:7481"

const baseConf = `[Interface]
Address = 10.183.26.1/24
PrivateKey = FAKE=

# BEGIN peer alice-pc
[Peer]
PublicKey = AAAA=
PresharedKey = PPPP=
AllowedIPs = 10.183.26.2/32
# END peer alice-pc
`

func newKey(t *testing.T) wgtypes.Key {
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestIntakeSourceCheck(t *testing.T) {
	h := newHarness(t, baseConf)
	r := httptest.NewRequest("POST", "/v1/join", strings.NewReader("{}"))
	r.RemoteAddr = "10.183.26.3:5000"
	w := httptest.NewRecorder()
	h.intake.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("다른 출발지가 %d", w.Code)
	}
}

func TestJoinFlowApprove(t *testing.T) {
	h := newHarness(t, baseConf)
	friend := newKey(t)
	pub := friend.PublicKey().String()

	w := h.post("chulsoo", pub)
	var acc proto.JoinAccepted
	json.Unmarshal(w.Body.Bytes(), &acc)
	if w.Code != http.StatusAccepted || len(acc.ID) != 32 || acc.Code != proto.ConfirmCode(friend.PublicKey()) {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	// 같은 공개키 재요청 → 같은 id
	var again proto.JoinAccepted
	json.Unmarshal(h.post("other-name", pub).Body.Bytes(), &again)
	if again.ID != acc.ID {
		t.Error("같은 공개키인데 id 가 다르다")
	}
	if _, st := h.status(acc.ID); st.State != proto.StatePending {
		t.Errorf("상태 %q", st.State)
	}

	if w := h.webPost("/approve", url.Values{"id": {acc.ID}}, okOrigin, true); w.Code != http.StatusSeeOther {
		t.Fatalf("승인 %d %s", w.Code, w.Body)
	}
	code, st := h.status(acc.ID)
	if code != 200 || st.State != proto.StateApproved || st.Config.Address != "10.183.26.3/32" {
		t.Fatalf("%d %+v", code, st)
	}
	psk, err := proto.OpenPSK(st.Config.PSKSealed, friend.PublicKey(), friend)
	if err != nil {
		t.Fatal(err)
	}
	conf, _ := os.ReadFile(h.s.cfg.WgConf)
	peers, _ := wgconf.Peers(conf)
	last := peers[len(peers)-1]
	if last.Name != "chulsoo" || last.PresharedKey != wgtypes.Key(psk).String() || !last.ByAccesstool {
		t.Errorf("wg0.conf 블록: %+v", last)
	}
	if h.wg.peers[pub] != wgtypes.Key(psk) {
		t.Error("wgctl 에 같은 PSK 로 안 들어갔다")
	}
	saved, _ := os.ReadFile(filepath.Join(h.s.cfg.StateDir, "requests.json"))
	if strings.Contains(string(saved), wgtypes.Key(psk).String()) {
		t.Error("requests.json 에 PSK 원문이 있다")
	}
	if _, err := os.Stat(filepath.Join(h.s.cfg.StateDir, "wg0.conf.bak")); err != nil {
		t.Error(".bak 가 없다")
	}

	// 승인된 공개키로 새 요청 → 같은 id (상태 approved)
	var third proto.JoinAccepted
	json.Unmarshal(h.post("x", pub).Body.Bytes(), &third)
	if third.ID != acc.ID {
		t.Error("승인 뒤 재요청 id 가 다르다")
	}
}

func TestJoinConflicts(t *testing.T) {
	h := newHarness(t, baseConf)
	if w := h.post("alice-pc", newKey(t).PublicKey().String()); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), proto.ErrNameTaken) {
		t.Errorf("conf 에 있는 이름 %d %s", w.Code, w.Body)
	}
	h.post("dup", newKey(t).PublicKey().String())
	if w := h.post("dup", newKey(t).PublicKey().String()); w.Code != http.StatusConflict {
		t.Errorf("대기 중인 이름 %d", w.Code)
	}

	k := newKey(t)
	h2 := newHarness(t, string(wgconf.AppendPeer([]byte(baseConf), wgconf.Peer{Name: "old", PublicKey: k.PublicKey().String(), IP: "10.183.26.3"}, h.clock)))
	if w := h2.post("new", k.PublicKey().String()); !strings.Contains(w.Body.String(), proto.ErrPubkeyTaken) {
		t.Errorf("등록된 공개키 %d %s", w.Code, w.Body)
	}
	for _, bad := range []string{"Bad", wgconf.BootstrapName} {
		if w := h.post(bad, newKey(t).PublicKey().String()); w.Code != http.StatusBadRequest {
			t.Errorf("이름 %q → %d", bad, w.Code)
		}
	}
}

func TestJoinLimits(t *testing.T) {
	h := newHarness(t, baseConf)
	big := `{"name":"a","pubkey":"` + strings.Repeat("A", 2000) + `"}`
	r := httptest.NewRequest("POST", "/v1/join", strings.NewReader(big))
	r.RemoteAddr = "10.183.26.254:1"
	w := httptest.NewRecorder()
	h.intake.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("1KB 넘는 본문 %d", w.Code)
	}
	for i := 0; i < postPerMinute-1; i++ {
		h.post("n"+string(rune('a'+i)), newKey(t).PublicKey().String())
	}
	if w := h.post("over", newKey(t).PublicKey().String()); w.Code != http.StatusTooManyRequests {
		t.Errorf("분당 11번째 %d", w.Code)
	}
	h.clock = h.clock.Add(time.Minute)
	if w := h.post("later", newKey(t).PublicKey().String()); w.Code != http.StatusAccepted {
		t.Errorf("1분 뒤 %d", w.Code)
	}
	for i := 0; i < getPerSecond; i++ {
		h.status("nope")
	}
	if code, _ := h.status("nope"); code != http.StatusTooManyRequests {
		t.Errorf("초당 6번째 GET %d", code)
	}
	h.clock = h.clock.Add(time.Second)
	if code, _ := h.status("nope"); code != http.StatusNotFound {
		t.Errorf("모르는 id %d", code)
	}
}

func TestMaxPending(t *testing.T) {
	h := newHarness(t, baseConf)
	for i := 0; i < maxPending; i++ {
		h.clock = h.clock.Add(time.Minute) // 분당 제한 피하기
		if w := h.post("p"+string(rune('a'+i)), newKey(t).PublicKey().String()); w.Code != http.StatusAccepted {
			t.Fatalf("%d번째 %d", i, w.Code)
		}
	}
	h.clock = h.clock.Add(time.Minute)
	if w := h.post("full", newKey(t).PublicKey().String()); w.Code != http.StatusTooManyRequests {
		t.Errorf("대기 21번째 %d", w.Code)
	}
}

func TestWebGuards(t *testing.T) {
	h := newHarness(t, baseConf)
	r := httptest.NewRequest("GET", "http://192.168.1.10:7481/", nil)
	w := httptest.NewRecorder()
	h.web.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("쿠키 없이 %d", w.Code)
	}
	if w := h.webPost("/reject", url.Values{"id": {"x"}}, "http://evil.example", true); w.Code != http.StatusForbidden {
		t.Errorf("다른 Origin %d", w.Code)
	}
	if w := h.webPost("/reject", url.Values{"id": {"x"}}, okOrigin, false); w.Code != http.StatusUnauthorized {
		t.Errorf("쿠키 없는 POST %d", w.Code)
	}
	r = httptest.NewRequest("GET", "http://evil.example:7481/", nil)
	w = httptest.NewRecorder()
	h.web.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("다른 Host %d", w.Code)
	}

	if w := h.webPost("/login", url.Values{"token": {"wrong"}}, okOrigin, false); w.Code != http.StatusUnauthorized {
		t.Errorf("틀린 토큰 %d", w.Code)
	}
	w = h.webPost("/login", url.Values{"token": {testToken}}, okOrigin, false)
	c := w.Result().Cookies()
	if w.Code != http.StatusSeeOther || len(c) != 1 || !c[0].HttpOnly || c[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("로그인 %d %+v", w.Code, c)
	}
	r = httptest.NewRequest("GET", "http://192.168.1.10:7481/", nil)
	r.AddCookie(c[0])
	w = httptest.NewRecorder()
	h.web.ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "alice-pc") {
		t.Errorf("목록 %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "<summary>사용법</summary>") {
		t.Errorf("목록 화면에 사용법이 없다")
	}
}

func TestRejectRevokeExpire(t *testing.T) {
	boot := wgconf.AppendPeer([]byte(baseConf), wgconf.Peer{Name: wgconf.BootstrapName, PublicKey: "BOOT=", IP: "10.183.26.254"}, time.Now())
	h := newHarness(t, string(boot))

	var a proto.JoinAccepted
	json.Unmarshal(h.post("rej", newKey(t).PublicKey().String()).Body.Bytes(), &a)
	h.webPost("/reject", url.Values{"id": {a.ID}}, okOrigin, true)
	if _, st := h.status(a.ID); st.State != proto.StateRejected {
		t.Errorf("거절 %q", st.State)
	}

	friend := newKey(t)
	json.Unmarshal(h.post("gone", friend.PublicKey().String()).Body.Bytes(), &a)
	h.webPost("/approve", url.Values{"id": {a.ID}}, okOrigin, true)
	if w := h.webPost("/revoke", url.Values{"name": {"gone"}}, okOrigin, true); w.Code != http.StatusSeeOther {
		t.Fatalf("회수 %d %s", w.Code, w.Body)
	}
	conf, _ := os.ReadFile(h.s.cfg.WgConf)
	if strings.Contains(string(conf), "gone") || len(h.wg.peers) != 0 {
		t.Error("회수 뒤에도 남아 있다")
	}
	if string(conf) != string(boot) {
		t.Errorf("회수 뒤 파일이 원래와 다르다:\n%s", conf)
	}
	if w := h.webPost("/revoke", url.Values{"name": {wgconf.BootstrapName}}, okOrigin, true); w.Code != http.StatusConflict {
		t.Errorf("부트스트랩 회수 %d", w.Code)
	}

	json.Unmarshal(h.post("slow", newKey(t).PublicKey().String()).Body.Bytes(), &a)
	h.clock = h.clock.Add(pendingTTL + time.Minute)
	h.s.cleanup()
	if _, st := h.status(a.ID); st.State != proto.StateExpired {
		t.Errorf("만료 %q", st.State)
	}
	h.clock = h.clock.Add(resultTTL + time.Minute)
	h.s.cleanup()
	if len(h.s.reqs) != 0 {
		t.Errorf("7일 지난 결과가 %d건 남았다", len(h.s.reqs))
	}
}

func TestApproveRollsBackOnWgFailure(t *testing.T) {
	h := newHarness(t, baseConf)
	h.wg.failAdd = true
	var a proto.JoinAccepted
	json.Unmarshal(h.post("fail", newKey(t).PublicKey().String()).Body.Bytes(), &a)
	if w := h.webPost("/approve", url.Values{"id": {a.ID}}, okOrigin, true); w.Code != http.StatusInternalServerError {
		t.Errorf("%d", w.Code)
	}
	conf, _ := os.ReadFile(h.s.cfg.WgConf)
	if string(conf) != baseConf {
		t.Error("wg 실패 뒤 블록이 남았다")
	}
	if _, st := h.status(a.ID); st.State != proto.StatePending {
		t.Errorf("상태 %q", st.State)
	}
}

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	k := newKey(t).PublicKey().String()
	path := filepath.Join(dir, "accessd.conf")
	os.WriteFile(path, []byte("endpoint = file.invalid:51820\nserver_public_key = "+k+"\nweb_listen = 1.2.3.4:1\n"), 0o600)
	c, err := loadConfig([]string{"-config", path, "-web_listen", "5.6.7.8:2"})
	if err != nil {
		t.Fatal(err)
	}
	if c.Endpoint != "file.invalid:51820" || c.WebListen != "5.6.7.8:2" || c.TokenFile != filepath.Join("/var/lib/accesstool", "web.token") {
		t.Errorf("%+v", c)
	}
	os.WriteFile(path, []byte("typo_key = 1\n"), 0o600)
	if _, err := loadConfig([]string{"-config", path}); err == nil {
		t.Error("모르는 키는 실패해야 한다")
	}
	if _, err := loadConfig([]string{"-config", filepath.Join(dir, "none")}); err == nil {
		t.Error("직접 준 설정 파일이 없으면 실패해야 한다")
	}
}

func TestRevokeForgetsRequest(t *testing.T) {
	h := newHarness(t, baseConf)
	pub := newKey(t).PublicKey().String()
	var a, b proto.JoinAccepted
	json.Unmarshal(h.post("gone", pub).Body.Bytes(), &a)
	h.webPost("/approve", url.Values{"id": {a.ID}}, okOrigin, true)
	h.webPost("/revoke", url.Values{"name": {"gone"}}, okOrigin, true)
	if code, _ := h.status(a.ID); code != http.StatusNotFound {
		t.Errorf("회수 뒤 옛 요청은 없어야 한다: %d", code)
	}
	json.Unmarshal(h.post("gone", pub).Body.Bytes(), &b)
	if _, st := h.status(b.ID); b.ID == a.ID || st.State != proto.StatePending {
		t.Errorf("같은 키 재요청은 새 pending 이어야 한다: %q %q", b.ID, st.State)
	}
}

func TestApproveRollsBackOnSaveFailure(t *testing.T) {
	h := newHarness(t, baseConf)
	var a proto.JoinAccepted
	json.Unmarshal(h.post("save", newKey(t).PublicKey().String()).Body.Bytes(), &a)
	good := h.s.reqsPath
	h.s.reqsPath = filepath.Join(t.TempDir(), "없음", "requests.json")
	if w := h.webPost("/approve", url.Values{"id": {a.ID}}, okOrigin, true); w.Code != http.StatusInternalServerError {
		t.Errorf("%d", w.Code)
	}
	conf, _ := os.ReadFile(h.s.cfg.WgConf)
	if string(conf) != baseConf || len(h.wg.peers) != 0 || h.s.reqs[a.ID].State != proto.StatePending {
		t.Fatal("기록 실패 뒤 블록·피어·상태가 되돌려지지 않았다")
	}
	h.s.reqsPath = good
	if w := h.webPost("/approve", url.Values{"id": {a.ID}}, okOrigin, true); w.Code != http.StatusSeeOther {
		t.Errorf("다시 승인 %d %s", w.Code, w.Body)
	}
}

func TestApprovedKeptUntilFetched(t *testing.T) {
	h := newHarness(t, baseConf)
	var a proto.JoinAccepted
	json.Unmarshal(h.post("late", newKey(t).PublicKey().String()).Body.Bytes(), &a)
	h.webPost("/approve", url.Values{"id": {a.ID}}, okOrigin, true)
	h.clock = h.clock.Add(resultTTL + time.Minute)
	h.s.cleanup()
	if _, st := h.status(a.ID); st.State != proto.StateApproved || st.Config == nil {
		t.Fatalf("안 가져간 승인은 7일이 지나도 남는다: %q", st.State)
	}
	reloaded, _ := loadRequests(h.s.reqsPath)
	if reloaded[a.ID].Fetched.IsZero() {
		t.Error("가져간 때가 파일에 남아야 한다")
	}
	h.clock = h.clock.Add(resultTTL + time.Minute)
	h.s.cleanup()
	if len(h.s.reqs) != 0 {
		t.Error("가져간 뒤 7일이면 지운다")
	}
}

// api 는 관리 API 를 부른다. body 가 "" 이면 GET.
func (h *harness) api(path, body, auth, origin, ctype string, cookie bool) (*httptest.ResponseRecorder, map[string]any) {
	method := "POST"
	if body == "" {
		method = "GET"
	}
	r := httptest.NewRequest(method, "http://192.168.1.10:7481"+path, strings.NewReader(body))
	if auth != "" {
		r.Header.Set("Authorization", auth)
	}
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	if ctype != "" {
		r.Header.Set("Content-Type", ctype)
	}
	if cookie {
		r.AddCookie(&http.Cookie{Name: cookieName, Value: sessionValue(testToken)})
	}
	w := httptest.NewRecorder()
	h.web.ServeHTTP(w, r)
	var out map[string]any
	json.Unmarshal(w.Body.Bytes(), &out)
	return w, out
}

const bearer = "Bearer " + testToken
const jsonType = "application/json"

func TestAPIGuards(t *testing.T) {
	h := newHarness(t, baseConf)
	cases := []struct {
		what                     string
		path, body, auth, origin string
		ctype                    string
		cookie                   bool
		want                     int
	}{
		{"토큰 없음", "/api/state", "", "", "", "", false, 401},
		{"틀린 토큰", "/api/state", "", "Bearer wrong", "", "", false, 401},
		{"쿠키만", "/api/state", "", "", "", "", true, 401},
		{"쿠키만 POST", "/api/reject", `{"id":"x"}`, "", "", jsonType, true, 401},
		{"Origin 있음", "/api/state", "", bearer, okOrigin, "", false, 403},
		{"Content-Type 틀림", "/api/reject", `{"id":"x"}`, bearer, "", "application/x-www-form-urlencoded", false, 415},
		{"빈 id", "/api/reject", `{"id":""}`, bearer, "", jsonType, false, 400},
		{"JSON 아님", "/api/reject", `id=x`, bearer, "", jsonType, false, 400},
		{"4KB 넘음", "/api/reject", `{"id":"` + strings.Repeat("a", 5000) + `"}`, bearer, "", jsonType, false, 413},
		{"모르는 id", "/api/approve", `{"id":"x","extra":1}`, bearer, "", "application/json; charset=utf-8", false, 409},
	}
	for _, c := range cases {
		w, out := h.api(c.path, c.body, c.auth, c.origin, c.ctype, c.cookie)
		if w.Code != c.want || out["ok"] != false || out["error"] == "" {
			t.Errorf("%s: %d %s", c.what, w.Code, w.Body)
		}
		if ct := w.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" || w.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s: 헤더 %q", c.what, ct)
		}
	}
	if _, out := h.api("/api/state", "", "", "", "", false); out["error"] != "토큰이 틀렸다" {
		t.Errorf("401 문구 %v", out["error"])
	}
	// 다른 Host 는 /api/ 도 막힌다
	r := httptest.NewRequest("GET", "http://evil.example:7481/api/state", nil)
	r.Header.Set("Authorization", bearer)
	w := httptest.NewRecorder()
	h.web.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("다른 Host %d", w.Code)
	}
}

func TestAPIFlow(t *testing.T) {
	boot := wgconf.AppendPeer([]byte(baseConf), wgconf.Peer{Name: wgconf.BootstrapName, PublicKey: "BOOT=", IP: "10.183.26.254"}, time.Now())
	h := newHarness(t, string(boot))
	friend := newKey(t)
	var a, b proto.JoinAccepted
	json.Unmarshal(h.post("chulsoo", friend.PublicKey().String()).Body.Bytes(), &a)
	h.clock = h.clock.Add(time.Minute)
	json.Unmarshal(h.post("younghee", newKey(t).PublicKey().String()).Body.Bytes(), &b)

	h.wg.hs = map[string]time.Time{"BOOT=": h.clock.Add(-90 * time.Second)}
	w, out := h.api("/api/state", "", bearer, "", "", false)
	if w.Code != 200 || out["ok"] != true || out["peers_error"] != "" {
		t.Fatalf("state %d %s", w.Code, w.Body)
	}
	pending := out["pending"].([]any)
	first := pending[0].(map[string]any)
	if len(pending) != 2 || first["id"] != a.ID || first["code"] != a.Code || first["created"] != "2026-11-04T12:00:00Z" {
		t.Errorf("pending %v", pending)
	}
	if len(out["recent"].([]any)) != 0 {
		t.Errorf("recent 는 빈 배열 %v", out["recent"])
	}
	peers := out["peers"].([]any)
	p0, p1 := peers[0].(map[string]any), peers[1].(map[string]any)
	if len(peers) != 2 || p0["name"] != "alice-pc" || p0["ip"] != "10.183.26.2" || p0["source"] != "wg-friend" ||
		p0["bootstrap"] != false || p0["handshake_ago_s"] != nil || p1["bootstrap"] != true || p1["handshake_ago_s"] != float64(90) {
		t.Errorf("peers %v", peers)
	}

	if w, out := h.api("/api/approve", `{"id":"`+a.ID+`"}`, bearer, "", jsonType, false); w.Code != 200 || out["ok"] != true {
		t.Fatalf("승인 %d %s", w.Code, w.Body)
	}
	if w, _ := h.api("/api/approve", `{"id":"`+a.ID+`"}`, bearer, "", jsonType, false); w.Code != http.StatusConflict {
		t.Errorf("두 번 승인 %d", w.Code)
	}
	h.clock = h.clock.Add(time.Minute)
	if w, _ := h.api("/api/reject", `{"id":"`+b.ID+`"}`, bearer, "", jsonType, false); w.Code != 200 {
		t.Errorf("거절 %d %s", w.Code, w.Body)
	}
	if w, _ := h.api("/api/reject", `{"id":"`+b.ID+`"}`, bearer, "", jsonType, false); w.Code != http.StatusConflict {
		t.Errorf("두 번 거절 %d", w.Code)
	}

	_, out = h.api("/api/state", "", bearer, "", "", false)
	recent := out["recent"].([]any)
	if len(recent) != 2 || recent[0].(map[string]any)["state"] != proto.StateRejected || recent[1].(map[string]any)["state"] != proto.StateApproved {
		t.Errorf("recent 는 최근 것부터 %v", recent)
	}
	last := out["peers"].([]any)[2].(map[string]any)
	if last["name"] != "chulsoo" || last["source"] != "accesstool" {
		t.Errorf("승인 피어 %v", last)
	}

	if w, _ := h.api("/api/revoke", `{"name":"`+wgconf.BootstrapName+`"}`, bearer, "", jsonType, false); w.Code != http.StatusConflict {
		t.Errorf("부트스트랩 회수 %d", w.Code)
	}
	if w, _ := h.api("/api/revoke", `{"name":"chulsoo"}`, bearer, "", jsonType, false); w.Code != 200 {
		t.Errorf("회수 %d %s", w.Code, w.Body)
	}
	if conf, _ := os.ReadFile(h.s.cfg.WgConf); string(conf) != string(boot) {
		t.Errorf("회수 뒤 파일:\n%s", conf)
	}
	if w, _ := h.api("/api/revoke", `{"name":""}`, bearer, "", jsonType, false); w.Code != http.StatusBadRequest {
		t.Errorf("빈 이름 %d", w.Code)
	}
}

func TestPageStateNames(t *testing.T) {
	h := newHarness(t, baseConf)
	var a proto.JoinAccepted
	json.Unmarshal(h.post("rej", newKey(t).PublicKey().String()).Body.Bytes(), &a)
	h.webPost("/reject", url.Values{"id": {a.ID}}, okOrigin, true)
	r := httptest.NewRequest("GET", "http://192.168.1.10:7481/", nil)
	r.AddCookie(&http.Cookie{Name: cookieName, Value: sessionValue(testToken)})
	w := httptest.NewRecorder()
	h.web.ServeHTTP(w, r)
	if !strings.Contains(w.Body.String(), "<td>거절</td>") {
		t.Errorf("최근 결과 상태가 한글이 아니다")
	}
}

func TestLoadConfigRejectsWildcardWebListen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accessd.conf")
	os.WriteFile(path, []byte("endpoint = file.invalid:51820\nserver_public_key = "+newKey(t).PublicKey().String()+"\n"), 0o600)
	for _, bad := range []string{"0.0.0.0:7481", "[::]:7481", "mini.lan:7481", "7481"} {
		if _, err := loadConfig([]string{"-config", path, "-web_listen", bad}); err == nil {
			t.Errorf("%q 는 시동 오류여야 한다", bad)
		}
	}
}
