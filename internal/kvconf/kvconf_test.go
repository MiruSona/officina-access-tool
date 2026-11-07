package kvconf

import "testing"

func TestParse(t *testing.T) {
	data := "\uFEFF# 주석\r\n[join]\r\nendpoint = host.example:51820\r\n; 주석\r\nintake_port=7480\r\n\r\n"
	got, err := Parse([]byte(data), []string{"endpoint", "intake_port"})
	if err != nil {
		t.Fatal(err)
	}
	if got["endpoint"] != "host.example:51820" || got["intake_port"] != "7480" {
		t.Errorf("%v", got)
	}
	// base64 키의 끝 = 는 값에 남아야 한다
	got, _ = Parse([]byte("endpoint = abc==\n"), []string{"endpoint"})
	if got["endpoint"] != "abc==" {
		t.Errorf("값 %q", got["endpoint"])
	}
	for _, bad := range []string{"nokey\n", "other = 1\n", "endpoint = a\nendpoint = b\n"} {
		if _, err := Parse([]byte(bad), []string{"endpoint"}); err == nil {
			t.Errorf("%q 는 오류여야 한다", bad)
		}
	}
}
