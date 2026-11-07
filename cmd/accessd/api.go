package main

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log"
	"mime"
	"net/http"
	"time"
)

// 관리 API — 다른 관리 도구가 서버끼리 부른다 (설계 10장). 승인 웹과 같은 리스너·같은 토큰.
const apiBodyLimit = 4 << 10

type apiPending struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Code    string `json:"code"`
	Created string `json:"created"`
}

type apiRecent struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Code    string `json:"code"`
	State   string `json:"state"`
	Decided string `json:"decided"`
}

type apiPeer struct {
	Name          string `json:"name"`
	IP            string `json:"ip"`
	HandshakeAgoS *int64 `json:"handshake_ago_s"`
	Source        string `json:"source"`
	Bootstrap     bool   `json:"bootstrap"`
}

type apiState struct {
	OK         bool         `json:"ok"`
	Pending    []apiPending `json:"pending"`
	Recent     []apiRecent  `json:"recent"`
	Peers      []apiPeer    `json:"peers"`
	PeersError string       `json:"peers_error"`
}

func (s *server) apiHandler(token string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/state", s.apiState)
	mux.HandleFunc("POST /api/approve", s.apiAction("id", s.approve))
	mux.HandleFunc("POST /api/reject", s.apiAction("id", s.reject))
	mux.HandleFunc("POST /api/revoke", s.apiAction("name", s.revoke))

	want := []byte("Bearer " + token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 서버끼리 부르는 API 라 브라우저에서 올 일이 없다 — Origin 이 있으면 브라우저발로 보고 막는다
		if r.Header.Get("Origin") != "" {
			apiError(w, http.StatusForbidden, "브라우저에서 부를 수 없다")
			return
		}
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), want) != 1 {
			apiError(w, http.StatusUnauthorized, "토큰이 틀렸다")
			return
		}
		if r.Method == http.MethodPost {
			if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
				apiError(w, http.StatusUnsupportedMediaType, "Content-Type 은 application/json 이어야 한다")
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, apiBodyLimit)
		}
		mux.ServeHTTP(w, r)
	})
}

func (s *server) apiState(w http.ResponseWriter, _ *http.Request) {
	pending, recent := s.requestLists()
	st := apiState{OK: true, Pending: []apiPending{}, Recent: []apiRecent{}, Peers: []apiPeer{}}
	for _, r := range pending {
		st.Pending = append(st.Pending, apiPending{r.ID, r.Name, r.Code, r.Created.Format(time.RFC3339)})
	}
	for _, r := range recent {
		st.Recent = append(st.Recent, apiRecent{r.ID, r.Name, r.Code, r.State, r.Decided.Format(time.RFC3339)})
	}
	peers, err := s.peerRows()
	if err != nil {
		st.PeersError = err.Error()
	}
	for _, p := range peers {
		src := "wg-friend"
		if p.Mine {
			src = "accesstool"
		}
		st.Peers = append(st.Peers, apiPeer{p.Name, p.IP, p.HandshakeSec, src, p.Bootstrap})
	}
	apiJSON(w, http.StatusOK, st)
}

// apiAction 은 본문 {"<field>": "..."} 의 값으로 기존 승인 웹 동작을 그대로 부른다.
func (s *server) apiAction(field string, do func(string) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			var tooBig *http.MaxBytesError
			if errors.As(err, &tooBig) {
				apiError(w, http.StatusRequestEntityTooLarge, "본문이 너무 크다 (4KB 상한)")
				return
			}
			apiError(w, http.StatusBadRequest, "본문이 JSON 객체가 아니다")
			return
		}
		v, _ := body[field].(string)
		if v == "" {
			apiError(w, http.StatusBadRequest, field+" 가 비었다")
			return
		}
		if err := do(v); err != nil {
			log.Printf("%s 실패: %v", r.URL.Path, err)
			status := http.StatusInternalServerError
			if errors.Is(err, errConflict) {
				status = http.StatusConflict
			}
			apiError(w, status, err.Error())
			return
		}
		apiJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func apiError(w http.ResponseWriter, status int, msg string) {
	apiJSON(w, status, map[string]any{"ok": false, "error": msg})
}

func apiJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("JSON 쓰기 실패: %v", err)
	}
}
