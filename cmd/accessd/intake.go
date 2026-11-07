package main

import (
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/MiruSona/officina-access-tool/internal/proto"
	"github.com/MiruSona/officina-access-tool/internal/wgconf"
)

func (s *server) intakeHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/join", s.handleJoin)
	mux.HandleFunc("GET /v1/join/{id}", s.handleStatus)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		if host != s.cfg.BootstrapIP {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		select {
		case s.slots <- struct{}{}:
			defer func() { <-s.slots }()
		default:
			writeJSON(w, http.StatusTooManyRequests, proto.ErrorResponse{Error: proto.ErrBusy, RetryAfter: retryAfterSec})
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (s *server) handleJoin(w http.ResponseWriter, r *http.Request) {
	if !s.postRate.allow(s.now()) {
		writeJSON(w, http.StatusTooManyRequests, proto.ErrorResponse{Error: proto.ErrBusy, RetryAfter: retryAfterSec})
		return
	}
	var in proto.JoinRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, proto.MaxBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, proto.ErrorResponse{Error: "bad_request"})
		return
	}
	if !proto.ValidName(in.Name) || in.Name == wgconf.BootstrapName {
		writeJSON(w, http.StatusBadRequest, proto.ErrorResponse{Error: "bad_name"})
		return
	}
	pub, err := proto.ParseKey(in.Pubkey)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, proto.ErrorResponse{Error: "bad_pubkey"})
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	// 같은 공개키는 같은 요청이다 (exe 를 다시 켜도 안전하게)
	for _, req := range s.reqs {
		if req.Pubkey == in.Pubkey {
			writeJSON(w, http.StatusAccepted, proto.JoinAccepted{ID: req.ID, Code: req.Code, PollAfter: 10})
			return
		}
	}
	data, err := s.conf.Read()
	if err != nil {
		serverError(w, err)
		return
	}
	if err := checkFree(data, in.Name, in.Pubkey); err != nil {
		switch {
		case errors.Is(err, errPubkeyTaken):
			writeJSON(w, http.StatusConflict, proto.ErrorResponse{Error: proto.ErrPubkeyTaken})
		case errors.Is(err, errNameTaken):
			writeJSON(w, http.StatusConflict, proto.ErrorResponse{Error: proto.ErrNameTaken})
		default:
			serverError(w, err)
		}
		return
	}
	pending := 0
	for _, req := range s.reqs {
		if req.State != proto.StatePending {
			continue
		}
		pending++
		if req.Name == in.Name {
			writeJSON(w, http.StatusConflict, proto.ErrorResponse{Error: proto.ErrNameTaken})
			return
		}
	}
	if pending >= maxPending {
		writeJSON(w, http.StatusTooManyRequests, proto.ErrorResponse{Error: proto.ErrBusy, RetryAfter: retryAfterSec})
		return
	}

	id, err := newID()
	if err != nil {
		serverError(w, err)
		return
	}
	req := &request{ID: id, Name: in.Name, Pubkey: in.Pubkey, Code: proto.ConfirmCode(pub), State: proto.StatePending, Created: s.now()}
	s.reqs[id] = req
	if err := saveRequests(s.reqsPath, s.reqs); err != nil {
		delete(s.reqs, id)
		serverError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, proto.JoinAccepted{ID: id, Code: req.Code, PollAfter: 10})
}

func (s *server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if !s.getRate.allow(s.now()) {
		writeJSON(w, http.StatusTooManyRequests, proto.ErrorResponse{Error: proto.ErrBusy, RetryAfter: 1})
		return
	}
	s.mu.Lock()
	req := s.reqs[r.PathValue("id")]
	var out proto.JoinStatus
	if req != nil {
		out.State = req.State
		if req.State == proto.StateApproved {
			if req.Fetched.IsZero() {
				req.Fetched = s.now()
				if err := saveRequests(s.reqsPath, s.reqs); err != nil {
					// 못 남기면 다음 GET 때 다시 한다. 기록이 없으면 안 지울 뿐이다
					req.Fetched = time.Time{}
					log.Printf("가져간 때 기록 실패: %v", err)
				}
			}
			out.Config = &proto.PeerConfig{
				Address:      req.Address,
				ServerPubkey: s.cfg.ServerPublicKey,
				Endpoint:     s.cfg.Endpoint,
				AllowedIPs:   []string{wgconf.SubnetPrefix + ".1/32"},
				Keepalive:    keepaliveSec,
				PSKSealed:    req.PSKSealed,
			}
		}
	}
	s.mu.Unlock()
	if req == nil {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func serverError(w http.ResponseWriter, err error) {
	log.Printf("내부 오류: %v", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}
