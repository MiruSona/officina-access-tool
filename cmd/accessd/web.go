package main

import (
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"errors"
	"html/template"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/MiruSona/officina-access-tool/internal/proto"
	"github.com/MiruSona/officina-access-tool/internal/wgconf"
)

const cookieName = "accesstool_session"

//go:embed page.html
var pageHTML string

var stateNames = map[string]string{
	proto.StateApproved: "승인",
	proto.StateRejected: "거절",
	proto.StateExpired:  "만료",
}

var pageTmpl = template.Must(template.New("page").Funcs(template.FuncMap{
	"stateName": func(st string) string {
		if n, ok := stateNames[st]; ok {
			return n
		}
		return st
	},
}).Parse(pageHTML))

type peerRow struct {
	Name         string
	IP           string
	Handshake    string
	HandshakeSec *int64 // 핸드셰이크 뒤 지난 초. 없으면 nil (관리 API 용)
	Mine         bool
	Bootstrap    bool
}

type pageData struct {
	Login    bool
	Message  string
	Pending  []*request
	Recent   []*request
	Peers    []peerRow
	PeersErr string
}

// sessionValue 는 쿠키 값이다. 토큰을 바꾸면 옛 쿠키도 같이 죽는다.
func sessionValue(token string) string {
	sum := sha256.Sum256([]byte("accesstool-session\x00" + token))
	return hex.EncodeToString(sum[:])
}

func (s *server) webHandler(token string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.handleIndex)
	mux.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.PostFormValue("token")), []byte(token)) != 1 {
			s.render(w, http.StatusUnauthorized, pageData{Login: true, Message: "토큰이 틀렸다"})
			return
		}
		http.SetCookie(w, &http.Cookie{Name: cookieName, Value: s.session, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})
	mux.HandleFunc("POST /approve", s.action(func(r *http.Request) error { return s.approve(r.PostFormValue("id")) }))
	mux.HandleFunc("POST /reject", s.action(func(r *http.Request) error { return s.reject(r.PostFormValue("id")) }))
	mux.HandleFunc("POST /revoke", s.action(func(r *http.Request) error { return s.revoke(r.PostFormValue("name")) }))
	api := s.apiHandler(token)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Host 검사는 DNS 리바인딩 막기, Origin 검사는 CSRF 막기 (설계 6장)
		if r.Host != s.cfg.WebListen {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			api.ServeHTTP(w, r)
			return
		}
		if r.Method == http.MethodPost && r.Header.Get("Origin") != "http://"+s.cfg.WebListen {
			http.Error(w, "forbidden origin", http.StatusForbidden)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (s *server) authed(r *http.Request) bool {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(c.Value), []byte(s.session)) == 1
}

func (s *server) action(do func(r *http.Request) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.authed(r) {
			s.render(w, http.StatusUnauthorized, pageData{Login: true})
			return
		}
		if err := do(r); err != nil {
			log.Printf("%s 실패: %v", r.URL.Path, err)
			status := http.StatusInternalServerError
			if errors.Is(err, errConflict) {
				status = http.StatusConflict
			}
			http.Error(w, err.Error(), status)
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func (s *server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if !s.authed(r) {
		s.render(w, http.StatusUnauthorized, pageData{Login: true})
		return
	}
	var d pageData
	d.Pending, d.Recent = s.requestLists()
	peers, err := s.peerRows()
	if err != nil {
		d.PeersErr = err.Error()
	}
	d.Peers = peers
	s.render(w, http.StatusOK, d)
}

// requestLists 는 대기 요청(오래된 것부터)과 결정된 요청(최근 것부터)의 사본을 돌려준다.
// 결정된 요청은 cleanup 이 7일 뒤 지우므로 따로 거르지 않는다.
func (s *server) requestLists() (pending, recent []*request) {
	s.mu.Lock()
	for _, req := range s.reqs {
		copied := *req
		if req.State == proto.StatePending {
			pending = append(pending, &copied)
		} else {
			recent = append(recent, &copied)
		}
	}
	s.mu.Unlock()
	sort.Slice(pending, func(i, j int) bool { return pending[i].Created.Before(pending[j].Created) })
	sort.Slice(recent, func(i, j int) bool { return recent[i].Decided.After(recent[j].Decided) })
	return pending, recent
}

func (s *server) peerRows() ([]peerRow, error) {
	data, err := s.conf.Read()
	if err != nil {
		return nil, err
	}
	peers, err := wgconf.Peers(data)
	if err != nil {
		return nil, err
	}
	// 핸드셰이크를 못 읽어도 목록은 보인다
	hs, hsErr := s.wg.Handshakes()
	now := s.now()
	rows := make([]peerRow, 0, len(peers))
	for _, p := range peers {
		row := peerRow{Name: p.Name, IP: p.IP, Handshake: "-", Mine: p.ByAccesstool, Bootstrap: p.Name == wgconf.BootstrapName}
		if t, ok := hs[p.PublicKey]; ok && !t.IsZero() {
			ago := now.Sub(t).Truncate(time.Second)
			sec := int64(ago / time.Second)
			row.Handshake = ago.String() + " 전"
			row.HandshakeSec = &sec
		}
		rows = append(rows, row)
	}
	return rows, hsErr
}

func (s *server) render(w http.ResponseWriter, status int, d pageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	w.WriteHeader(status)
	if err := pageTmpl.Execute(w, d); err != nil {
		log.Printf("화면 그리기 실패: %v", err)
	}
}
