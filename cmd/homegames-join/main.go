//go:build windows

// homegames-join 은 친구 PC 에서 돌리는 가입 exe 다. exe 옆 join.conf 를 읽고 승인형 가입을 끝까지 한다.
// 흐름 원문 : Docs/Design/2026-11-04-승인형가입설계.md 3-2
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/MiruSona/officina-access-tool/internal/joinflow"
	"github.com/MiruSona/officina-access-tool/internal/wgwin"
)

// 종료 코드 : 0 끝(또는 이미 연결됨) · 1 실패 · 2 join.conf 문제
const (
	exitOK     = 0
	exitFail   = 1
	exitConfig = 2
)

var stdin = bufio.NewReader(os.Stdin)

func main() {
	os.Exit(run())
}

func run() int {
	rejoin := flag.Bool("rejoin", false, "이미 연결돼 있어도 가입을 다시 한다")
	flag.Parse()

	// 매니페스트(.syso)를 안 쓰므로 여기서 UAC 를 한 번 받는다. 새 창이 뜨고 이 창은 닫힌다
	if !wgwin.IsAdmin() {
		if err := wgwin.RelaunchAsAdmin(os.Args[1:]); err != nil {
			fmt.Printf("[실패] %v\n", err)
			pause()
			return exitFail
		}
		return exitOK
	}
	defer pause()
	fmt.Println("집 게임 서버 접속 준비를 시작합니다.")

	exe, err := os.Executable()
	if err != nil {
		fmt.Printf("[실패] %v\n", err)
		return exitFail
	}
	cfg, err := joinflow.LoadConfig(filepath.Join(filepath.Dir(exe), "join.conf"))
	if err != nil {
		fmt.Println("[실패] join.conf 를 읽지 못했습니다.")
		fmt.Println("       zip 을 오른쪽 클릭 - 모두 압축 풀기 로 먼저 풀고, 풀린 폴더에서 실행하세요.")
		fmt.Printf("       (%v)\n", err)
		return exitConfig
	}

	sys, err := wgwin.New()
	if err == nil {
		err = sys.PrepareDir()
	}
	if err != nil {
		fmt.Printf("[실패] %v\n", wrapService(err))
		return exitFail
	}

	flow := &joinflow.Flow{
		Cfg:         cfg,
		Dir:         sys.Dir,
		Sys:         sys,
		HTTP:        &http.Client{Timeout: 15 * time.Second},
		AskName:     askName,
		Say:         func(msg string) { fmt.Println(msg) },
		ShowCode:    showCode,
		Sleep:       time.Sleep,
		PollEvery:   10 * time.Second,
		MaxNetTries: 6,
	}
	if err := flow.Run(*rejoin); err != nil {
		fmt.Printf("\n[실패] %v\n", err)
		return exitFail
	}
	fmt.Println()
	fmt.Println("==================================================")
	fmt.Println(" 끝. 이제 아무것도 켤 필요가 없습니다.")
	fmt.Println(" 컴퓨터를 껐다 켜도 알아서 연결됩니다.")
	fmt.Println(" 게임 접속 주소는 서버장이 알려 드립니다.")
	fmt.Println("==================================================")
	return exitOK
}

func wrapService(err error) error {
	if errors.Is(err, wgwin.ErrService) {
		return err
	}
	return fmt.Errorf("%w (%v)", wgwin.ErrService, err)
}

func askName(reason string) (string, error) {
	if reason == "" {
		fmt.Println()
		fmt.Println("서버장이 알아볼 이름을 영어 소문자로 넣어 주세요. (예: chulsoo)")
	} else {
		fmt.Println(reason)
	}
	fmt.Print("이름: ")
	line, err := stdin.ReadString('\n')
	name := strings.ToLower(strings.TrimSpace(line))
	if errors.Is(err, io.EOF) && name != "" {
		err = nil
	}
	if err != nil {
		return "", fmt.Errorf("이름 입력이 끊겼습니다 (%v)", err)
	}
	return name, nil
}

func showCode(code string) {
	fmt.Println()
	fmt.Println("==================================================")
	fmt.Printf("   확인 코드 :   %s\n", code)
	fmt.Println()
	fmt.Println("   이 코드를 디스코드로 서버장에게 알려 주세요.")
	fmt.Println("==================================================")
	fmt.Println()
}

// pause 는 창이 바로 닫히지 않게 Enter 를 기다린다 (관리자로 다시 뜬 창은 새 창이라 특히).
func pause() {
	fmt.Print("\nEnter 를 누르면 창이 닫힙니다.")
	stdin.ReadString('\n')
}
