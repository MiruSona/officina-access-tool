// Package kvconf 는 `key = value` 줄로 된 설정 파일을 읽는다 (accessd.conf, 친구 쪽 join.conf).
package kvconf

import (
	"fmt"
	"strings"
)

// Parse 는 빈 줄과 #·; 주석, [섹션] 줄을 넘기고 나머지를 key = value 로 읽는다.
// allowed 에 없는 키·같은 키 두 번·= 없는 줄은 오류다 (모르는 설정을 조용히 넘기지 않는다).
func Parse(data []byte, allowed []string) (map[string]string, error) {
	known := make(map[string]bool, len(allowed))
	for _, k := range allowed {
		known[k] = true
	}
	text := strings.TrimPrefix(string(data), "\uFEFF")
	out := map[string]string{}
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' || line[0] == ';' || line[0] == '[' {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("%d번 줄: '=' 이 없다", i+1)
		}
		key = strings.TrimSpace(key)
		if !known[key] {
			return nil, fmt.Errorf("%d번 줄: 모르는 키 '%s'", i+1, key)
		}
		if _, dup := out[key]; dup {
			return nil, fmt.Errorf("%d번 줄: '%s' 가 두 번 나온다", i+1, key)
		}
		out[key] = strings.TrimSpace(val)
	}
	return out, nil
}
