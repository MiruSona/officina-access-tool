package joinflow

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/MiruSona/officina-access-tool/internal/proto"
)

const (
	clientName   = "homegames-join/0.1"
	maxRespBytes = 64 << 10
	maxWait      = 5 * time.Minute
)

// ErrRejected 는 승인이 거절됐거나 기한이 지났을 때다. 키와 join.json 은 이미 지운 뒤다.
var ErrRejected = errors.New("가입이 거절됐거나 기한이 지났습니다. 서버장에게 물어보세요")

var errUnknownID = errors.New("서버가 이 요청 id 를 모른다")

// System 은 Windows WireGuard 앱과 PC 설정이다. 진짜는 wgwin.System, 시험은 가짜.
type System interface {
	TunnelRunning(name string) bool
	Ping(host string) bool
	EnsureWireGuard(msiSHA256 string) error
	InstallTunnel(confPath string) error // 등록 뒤 RUNNING 까지 기다린다
	RemoveTunnel(name string) error      // 없으면 아무것도 안 한다
}

// Flow 는 설계 3-2 의 2~8단계다. 1단계(관리자 권한)는 main 몫이다.
type Flow struct {
	Cfg  Config
	Dir  string // %ProgramData%\HomeGames — ACL 은 부르는 쪽이 미리 건다
	Sys  System
	HTTP *http.Client
	// AskName 은 이름을 묻는다. reason 은 처음엔 "", 다시 물을 때 까닭이다
	AskName     func(reason string) (string, error)
	Say         func(msg string)
	ShowCode    func(code string)
	Sleep       func(time.Duration)
	PollEvery   time.Duration
	MaxNetTries int // 연결 실패를 연속 몇 번까지 참나
}

// Run 은 가입 흐름 전체다. rejoin 이면 이미 연결돼 있어도 다시 한다.
func (f *Flow) Run(rejoin bool) error {
	if !rejoin && f.Sys.TunnelRunning(MainTunnel) && f.Sys.Ping(f.Cfg.ServerIP.String()) {
		f.Say("이미 연결돼 있습니다. 할 일이 없습니다. (다시 가입하려면 --rejoin 을 붙여 실행)")
		return nil
	}
	f.Say("WireGuard 를 확인하는 중입니다...")
	if err := f.Sys.EnsureWireGuard(f.Cfg.MSISHA256); err != nil {
		return err
	}
	// 받아 간 conf 가 있으면 다시 요청하지 않는다 — 서버는 받아 간 뒤 7일에 요청 기록을 지워 다시 POST 하면 pubkey_taken 이 된다
	if main := filepath.Join(f.Dir, MainTunnel+".conf"); !rejoin && fileExists(main) {
		return f.reconnect(main)
	}
	st, err := f.loadOrCreate()
	if err != nil {
		return err
	}

	status, err := f.requestViaBootstrap(st)
	if err != nil {
		f.restoreMain()
		return err
	}
	if status.State == proto.StateApproved {
		return f.finish(st, status.Config)
	}
	return f.abandon()
}

// requestViaBootstrap 은 진짜 터널을 내리고 부트스트랩으로 요청한다.
// 두 터널 모두 AllowedIPs 가 서버 /32 라 같이 켜면 경로가 겹친다.
func (f *Flow) requestViaBootstrap(st *State) (*proto.JoinStatus, error) {
	f.Say("가입 요청용 연결을 켜는 중입니다...")
	if err := f.Sys.RemoveTunnel(MainTunnel); err != nil {
		return nil, err
	}
	if err := f.installTunnel(BootstrapTunnel, f.Cfg.BootstrapConf()); err != nil {
		return nil, err
	}
	return f.request(st)
}

// restoreMain 은 요청이 실패했을 때 내렸던 진짜 터널을 되살린다 (서버가 잠깐 죽은 동안 다시 실행해도 연결이 남게).
func (f *Flow) restoreMain() {
	path := filepath.Join(f.Dir, MainTunnel+".conf")
	if _, err := os.Stat(path); err != nil {
		return
	}
	err := f.Sys.RemoveTunnel(BootstrapTunnel)
	if err == nil {
		err = f.Sys.InstallTunnel(path)
	}
	if err != nil {
		f.Say(fmt.Sprintf("[경고] 원래 연결을 되살리지 못했습니다. 다시 실행해 주세요. (%v)", err))
	}
}

// reconnect 는 받아 둔 진짜 conf 로 터널을 다시 깔고 ping 만 본다.
func (f *Flow) reconnect(path string) error {
	f.Say("받아 둔 설정으로 다시 연결하는 중입니다...")
	for _, name := range []string{BootstrapTunnel, MainTunnel} {
		if err := f.Sys.RemoveTunnel(name); err != nil {
			return err
		}
	}
	if err := f.Sys.InstallTunnel(path); err != nil {
		return err
	}
	if !f.Sys.Ping(f.Cfg.ServerIP.String()) {
		return errors.New("연결은 다시 켰지만 서버가 대답하지 않습니다. 서버가 꺼져 있거나 이 PC 의 등록이 회수된 것 같습니다. 서버장에게 묻거나 --rejoin 을 붙여 다시 가입하세요")
	}
	f.Say("다시 연결됐습니다.")
	f.sayGameAddr()
	return nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func (f *Flow) loadOrCreate() (*State, error) {
	st, err := LoadState(f.Dir)
	if err != nil || st != nil {
		return st, err
	}
	name, err := f.askValidName("")
	if err != nil {
		return nil, err
	}
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	st = &State{Name: name, PrivateKey: key.String()}
	return st, SaveState(f.Dir, st)
}

func (f *Flow) askValidName(reason string) (string, error) {
	for {
		name, err := f.AskName(reason)
		if err != nil {
			return "", err
		}
		if proto.ValidName(name) {
			return name, nil
		}
		reason = "이름은 영어 소문자·숫자·- 로 20자까지, 첫 글자는 영어나 숫자입니다."
	}
}

func (f *Flow) installTunnel(name, conf string) error {
	if err := f.Sys.RemoveTunnel(name); err != nil {
		return err
	}
	path := filepath.Join(f.Dir, name+".conf")
	if err := WriteAtomic(path, []byte(conf)); err != nil {
		return fmt.Errorf("등록 실패 — 설정 파일을 못 썼습니다. 이 화면을 찍어 서버장에게 보내 주세요 (%v)", err)
	}
	return f.Sys.InstallTunnel(path)
}

// request 는 요청 id 가 있으면 폴링을 잇고, 없거나 서버가 모르면 새로 POST 한다.
func (f *Flow) request(st *State) (*proto.JoinStatus, error) {
	for range 3 {
		if st.RequestID == "" {
			if err := f.postJoin(st); err != nil {
				return nil, err
			}
		}
		f.ShowCode(st.Code)
		status, err := f.poll(st.RequestID)
		if !errors.Is(err, errUnknownID) {
			return status, err
		}
		st.RequestID, st.Code = "", ""
		if err := SaveState(f.Dir, st); err != nil {
			return nil, err
		}
	}
	return nil, errors.New("서버가 가입 요청을 계속 잃어버립니다. 서버장에게 알려 주세요")
}

func (f *Flow) postJoin(st *State) error {
	priv, err := wgtypes.ParseKey(st.PrivateKey)
	if err != nil {
		return err
	}
	pub := priv.PublicKey()
	for {
		body, _ := json.Marshal(proto.JoinRequest{Name: st.Name, Pubkey: pub.String(), Client: clientName})
		code, data, err := f.call(http.MethodPost, "/v1/join", body)
		if err != nil {
			return err
		}
		if code == http.StatusAccepted {
			var acc proto.JoinAccepted
			if err := json.Unmarshal(data, &acc); err != nil || acc.ID == "" {
				return fmt.Errorf("서버 응답을 못 읽었습니다 (%d)", code)
			}
			// 확인 코드는 내 공개키로 직접 셈해 맞춰 본다 — 서버가 준 값만 믿지 않는다
			if acc.Code != proto.ConfirmCode(pub) {
				return errors.New("서버가 준 확인 코드가 이 PC 의 키와 안 맞습니다. 서버장에게 알려 주세요")
			}
			st.RequestID, st.Code = acc.ID, acc.Code
			return SaveState(f.Dir, st)
		}
		var e proto.ErrorResponse
		json.Unmarshal(data, &e)
		switch {
		case code == http.StatusConflict && e.Error == proto.ErrNameTaken:
			st.Name, err = f.askValidName(fmt.Sprintf("'%s' 는 이미 누가 쓰고 있습니다. 다른 이름을 넣어 주세요.", st.Name))
		case code == http.StatusBadRequest && e.Error == "bad_name":
			st.Name, err = f.askValidName(fmt.Sprintf("'%s' 는 쓸 수 없는 이름입니다. 다른 이름을 넣어 주세요.", st.Name))
		case code == http.StatusConflict && e.Error == proto.ErrPubkeyTaken:
			return errors.New("이 PC 의 키는 이미 등록돼 있습니다. 서버장에게 물어보세요")
		default:
			return fmt.Errorf("서버가 요청을 받지 않았습니다 (%d %s). 이 화면을 찍어 서버장에게 보내 주세요", code, e.Error)
		}
		if err != nil {
			return err
		}
		if err := SaveState(f.Dir, st); err != nil {
			return err
		}
	}
}

// poll 은 pending 이 아닐 때까지 기다린다.
func (f *Flow) poll(id string) (*proto.JoinStatus, error) {
	f.Say("서버장이 승인할 때까지 기다리는 중입니다. 창을 닫아도 됩니다 — 다시 실행하면 이어서 기다립니다.")
	for {
		code, data, err := f.call(http.MethodGet, "/v1/join/"+id, nil)
		if err != nil {
			return nil, err
		}
		if code == http.StatusNotFound {
			return nil, errUnknownID
		}
		if code != http.StatusOK {
			return nil, fmt.Errorf("서버 응답이 이상합니다 (%d). 이 화면을 찍어 서버장에게 보내 주세요", code)
		}
		var st proto.JoinStatus
		if err := json.Unmarshal(data, &st); err != nil {
			return nil, fmt.Errorf("서버 응답을 못 읽었습니다: %w", err)
		}
		switch st.State {
		case proto.StatePending:
			f.Sleep(f.PollEvery)
		case proto.StateApproved:
			if st.Config == nil {
				return nil, errors.New("승인 응답에 설정이 없습니다. 서버장에게 알려 주세요")
			}
			return &st, nil
		case proto.StateRejected, proto.StateExpired:
			return &st, nil
		default:
			return nil, fmt.Errorf("모르는 상태 '%s'", st.State)
		}
	}
}

// call 은 접수 API 를 부른다. 연결 실패는 MaxNetTries 번까지, 429 는 retry_after 만큼 쉬고 다시 한다.
func (f *Flow) call(method, path string, body []byte) (int, []byte, error) {
	url := "http://" + netip.AddrPortFrom(f.Cfg.ServerIP, uint16(f.Cfg.IntakePort)).String() + path
	fails := 0
	for {
		req, err := http.NewRequest(method, url, bytes.NewReader(body))
		if err != nil {
			return 0, nil, err
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := f.HTTP.Do(req)
		if err != nil {
			fails++
			if fails >= f.MaxNetTries {
				return 0, nil, fmt.Errorf("서버에 닿지 않습니다. 인터넷을 확인하고 다시 실행하세요. 계속 안 되면 서버장에게 알려 주세요 (%v)", err)
			}
			f.Sleep(f.PollEvery)
			continue
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, maxRespBytes))
		resp.Body.Close()
		if err != nil {
			return 0, nil, err
		}
		if resp.StatusCode != http.StatusTooManyRequests {
			return resp.StatusCode, data, nil
		}
		var e proto.ErrorResponse
		json.Unmarshal(data, &e)
		wait := time.Duration(e.RetryAfter) * time.Second
		wait = max(wait, time.Second)
		wait = min(wait, maxWait)
		f.Say(fmt.Sprintf("서버가 바쁩니다. %d초 뒤 다시 합니다...", int(wait.Seconds())))
		f.Sleep(wait)
	}
}

// finish 는 7단계다 : PSK 열기 → conf → 부트스트랩 내리기 → 진짜 터널 → ping → 접속 주소 알림.
func (f *Flow) finish(st *State, pc *proto.PeerConfig) error {
	priv, err := wgtypes.ParseKey(st.PrivateKey)
	if err != nil {
		return err
	}
	psk, err := proto.OpenPSK(pc.PSKSealed, priv.PublicKey(), priv)
	if err != nil {
		return fmt.Errorf("승인 응답을 열지 못했습니다. 서버장에게 알려 주세요 (%v)", err)
	}
	conf, err := f.Cfg.PeerConf(st.PrivateKey, pc, psk)
	if err != nil {
		return fmt.Errorf("승인 응답이 이상합니다. 서버장에게 알려 주세요 (%v)", err)
	}
	f.Say("승인됐습니다. 연결을 등록하는 중입니다...")
	if err := f.Sys.RemoveTunnel(BootstrapTunnel); err != nil {
		return err
	}
	if err := f.installTunnel(MainTunnel, conf); err != nil {
		return err
	}

	if !f.Sys.Ping(f.Cfg.ServerIP.String()) {
		return errors.New("연결은 등록됐지만 서버가 대답하지 않습니다. 서버가 꺼져 있거나 주소 문제입니다. 서버장에게 알려 주세요")
	}
	f.sayGameAddr()
	return nil
}

// sayGameAddr 는 게임에 칠 주소(터널 서버 IP)를 알린다. hosts 는 안 고친다 — Defender 가 hosts 쓰는 exe 를 잡는다(2026-11-08).
func (f *Flow) sayGameAddr() {
	f.Say(fmt.Sprintf("게임 접속 주소: %s (포트는 서버 안내대로)", f.Cfg.ServerIP))
}

// abandon 은 8단계다 : 거절·만료면 부트스트랩을 내리고 키(join.json)를 지운다. 다음 실행은 처음부터.
func (f *Flow) abandon() error {
	if err := f.Sys.RemoveTunnel(BootstrapTunnel); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(f.Dir, StateFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return ErrRejected
}
