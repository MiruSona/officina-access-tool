// accessd 는 친구 가입 요청을 받아(접수 API) 사용자 승인(승인 웹)을 거쳐 wg0 피어로 넣는 데몬이다.
// 설계 : Docs/Design/2026-11-04-승인형가입설계.md 3-1·4·6장
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/MiruSona/officina-access-tool/internal/wgctl"
)

func main() {
	if err := run(); err != nil {
		log.Printf("accessd: %v", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := loadConfig(os.Args[1:])
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(cfg.TokenFile)
	if err != nil {
		return err
	}
	token := strings.TrimSpace(string(raw))
	if len(token) < 32 {
		return fmt.Errorf("%s 의 토큰이 32자보다 짧다", cfg.TokenFile)
	}
	s, err := newServer(cfg, wgctl.Device{Name: cfg.Interface}, token)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	intake := &http.Server{
		Handler:           s.intakeHandler(),
		ReadTimeout:       5 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    4096,
	}
	web := &http.Server{
		Handler:           s.webHandler(token),
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    8192,
	}
	errs := make(chan error, 2)
	for _, pair := range []struct {
		srv  *http.Server
		addr string
	}{{intake, cfg.IntakeListen}, {web, cfg.WebListen}} {
		ln, err := listenNoMPTCP(ctx, pair.addr)
		if err != nil {
			return err
		}
		log.Printf("듣는 중 %s", pair.addr)
		go func(srv *http.Server) { errs <- srv.Serve(ln) }(pair.srv)
	}

	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := s.cleanup(); err != nil {
				log.Printf("정리 실패: %v", err)
			}
		case err := <-errs:
			return err
		case <-ctx.Done():
			shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			return errors.Join(intake.Shutdown(shutCtx), web.Shutdown(shutCtx))
		}
	}
}

// listenNoMPTCP 는 MPTCP 를 끈 TCP 리스너다 (Go 1.24 부터 리스너 MPTCP 가 기본으로 켜진다, 설계 3-1).
func listenNoMPTCP(ctx context.Context, addr string) (net.Listener, error) {
	var lc net.ListenConfig
	lc.SetMultipathTCP(false)
	return lc.Listen(ctx, "tcp", addr)
}
