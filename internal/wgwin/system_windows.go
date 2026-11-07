//go:build windows

package wgwin

import (
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// System 은 joinflow.System 의 진짜 구현이다. 모든 경로는 Windows 가 알려 주는 고정 폴더에서 만든다.
type System struct {
	Dir   string // %ProgramData%\HomeGames
	wg    string // %ProgramFiles%\WireGuard\wireguard.exe
	sys32 string // PATH 를 안 거치고 System32 의 exe 를 직접 부른다
	http  *http.Client
}

func New() (*System, error) {
	programData, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		return nil, err
	}
	programFiles, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil {
		return nil, err
	}
	sys32, err := windows.GetSystemDirectory()
	if err != nil {
		return nil, err
	}
	return &System{
		Dir:   filepath.Join(programData, "HomeGames"),
		wg:    filepath.Join(programFiles, "WireGuard", "wireguard.exe"),
		sys32: sys32,
		http:  &http.Client{Timeout: 5 * time.Minute},
	}, nil
}

// PrepareDir 는 상태 폴더를 만들고 주인을 Administrators 로, 권한을 SYSTEM·Administrators 만으로 바꾼다.
// 안의 새 파일은 이 ACL 을 물려받는다. ProgramData 는 일반 사용자도 폴더를 만들 수 있어서 주인부터 바꾼다.
func (s *System) PrepareDir() error {
	// 보통 사용자가 미리 만든 폴더면 join.json 을 심어 둘 수 있으므로, 주인이 관리자·SYSTEM 이 아니면 멈춘다
	if _, err := os.Lstat(s.Dir); err == nil {
		sd, err := windows.GetNamedSecurityInfo(s.Dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
		if err != nil {
			return err
		}
		owner, _, err := sd.Owner()
		if err != nil {
			return err
		}
		if !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) && !owner.IsWellKnown(windows.WinLocalSystemSid) {
			return fmt.Errorf("%s 는 다른 사용자가 만든 폴더입니다. 지우고 다시 실행하세요", s.Dir)
		}
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	fi, err := os.Lstat(s.Dir)
	if err != nil {
		return err
	}
	if fi.Mode().Type() != fs.ModeDir {
		return fmt.Errorf("%s 가 보통 폴더가 아닙니다 (링크·정션). 지우고 다시 실행하세요", s.Dir)
	}
	if err := s.run("icacls.exe", s.Dir, "/setowner", "*S-1-5-32-544"); err != nil {
		return err
	}
	return s.run("icacls.exe", s.Dir, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F")
}

func (s *System) run(exe string, args ...string) error {
	out, err := exec.Command(filepath.Join(s.sys32, exe), args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s 실패: %v %s", exe, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func serviceName(tunnel string) string {
	return "WireGuardTunnel$" + tunnel
}

// queryService 는 서비스가 있는지와 RUNNING 인지 본다.
func queryService(name string) (exists, running bool) {
	m, err := mgr.Connect()
	if err != nil {
		return false, false
	}
	defer m.Disconnect()
	sv, err := m.OpenService(name)
	if err != nil {
		return false, false
	}
	defer sv.Close()
	st, err := sv.Query()
	return true, err == nil && st.State == svc.Running
}

func (s *System) TunnelRunning(name string) bool {
	_, running := queryService(serviceName(name))
	return running
}

func (s *System) Ping(host string) bool {
	out, _ := exec.Command(filepath.Join(s.sys32, "PING.EXE"), "-n", "3", "-w", "1000", host).Output()
	return strings.Contains(string(out), "TTL=")
}

// EnsureWireGuard 는 WireGuard 가 없으면 고정 판 MSI 를 %TEMP% 에 받아 SHA256 대조 뒤 조용히 설치한다.
func (s *System) EnsureWireGuard(msiSHA256 string) error {
	if _, err := os.Stat(s.wg); err == nil {
		return nil
	}
	tmp, err := os.MkdirTemp("", "homegames-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	msi := filepath.Join(tmp, filepath.Base(MSIURL))
	fmt.Println("WireGuard 를 내려받는 중입니다...")
	if err := Download(s.http, MSIURL, msi, msiSHA256); err != nil {
		return err
	}
	fmt.Println("WireGuard 를 설치하는 중입니다...")
	runErr := exec.Command(filepath.Join(s.sys32, "msiexec.exe"), "/i", msi, "/qn", "DO_NOT_LAUNCH=1").Run()
	// msiexec 는 3010(재부팅 필요)처럼 0 아닌 성공 코드가 있어서 exe 가 생겼는지로 판정한다
	if _, err := os.Stat(s.wg); err != nil {
		return fmt.Errorf("%w (%v)", ErrMSI, runErr)
	}
	return nil
}

// InstallTunnel 은 conf 를 터널 서비스로 등록하고 RUNNING 이 될 때까지 최대 10초 기다린다.
func (s *System) InstallTunnel(confPath string) error {
	if out, err := exec.Command(s.wg, "/installtunnelservice", confPath).CombinedOutput(); err != nil {
		return fmt.Errorf("%w (%v %s)", ErrService, err, strings.TrimSpace(string(out)))
	}
	name := serviceName(strings.TrimSuffix(filepath.Base(confPath), ".conf"))
	for range 10 {
		time.Sleep(time.Second)
		if _, running := queryService(name); running {
			return nil
		}
	}
	return fmt.Errorf("%w (%s 가 RUNNING 이 안 됨)", ErrService, name)
}

// RemoveTunnel 은 터널 서비스가 있으면 지우고 사라질 때까지 최대 10초 기다린다.
func (s *System) RemoveTunnel(name string) error {
	if exists, _ := queryService(serviceName(name)); !exists {
		return nil
	}
	if out, err := exec.Command(s.wg, "/uninstalltunnelservice", name).CombinedOutput(); err != nil {
		return fmt.Errorf("%w (%v %s)", ErrService, err, strings.TrimSpace(string(out)))
	}
	for range 10 {
		if exists, _ := queryService(serviceName(name)); !exists {
			return nil
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("%w (%s 가 안 지워짐)", ErrService, name)
}

// IsAdmin 은 지금 프로세스가 UAC 로 올라간 관리자인지 본다.
func IsAdmin() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// RelaunchAsAdmin 은 자신을 'runas' 로 다시 띄운다. 친구가 UAC 에서 '아니요' 를 누르면 ErrNotElevated.
func RelaunchAsAdmin(args []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cwd, _ := os.Getwd()
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = windows.EscapeArg(a)
	}
	err = windows.ShellExecute(0, windows.StringToUTF16Ptr("runas"), windows.StringToUTF16Ptr(exe),
		windows.StringToUTF16Ptr(strings.Join(quoted, " ")), windows.StringToUTF16Ptr(cwd), windows.SW_NORMAL)
	if errors.Is(err, windows.ERROR_CANCELLED) {
		return ErrNotElevated
	}
	return err
}
