package parsers

import (
	"bufio"
	"os"
	"testing"
	"time"

	"github.com/devshohag/kella/agent/internal/model"
)

func TestParseAuthLine(t *testing.T) {
	now := time.Date(2026, 11, 8, 2, 14, 0, 0, time.UTC)
	tests := []struct {
		line  string
		typ   string
		ip    string
		user  string
		isNil bool
	}{
		{"Nov  8 02:14:01 mail-02 sshd[1123]: Failed password for root from 45.148.10.92 port 51234 ssh2",
			model.TypeSSHAuthFailed, "45.148.10.92", "root", false},
		{"Nov  8 02:14:02 mail-02 sshd[1124]: Failed password for invalid user admin from 193.32.162.11 port 40022 ssh2",
			model.TypeSSHAuthFailed, "193.32.162.11", "admin", false},
		{"Nov  8 02:15:10 mail-02 sshd[1200]: Accepted publickey for deploy from 203.0.113.5 port 60001 ssh2: ED25519 SHA256:abc",
			model.TypeSSHAuthSuccess, "203.0.113.5", "deploy", false},
		{"Nov  8 02:14:02 mail-02 sshd[1124]: Invalid user admin from 193.32.162.11 port 40022", "", "", "", true},
		{"Nov  8 02:16:00 mail-02 CRON[2000]: pam_unix(cron:session): session opened for user root", "", "", "", true},
	}
	for _, tc := range tests {
		ev := ParseAuthLine(tc.line, now)
		if tc.isNil {
			if ev != nil {
				t.Errorf("expected nil for %q, got %+v", tc.line, ev)
			}
			continue
		}
		if ev == nil {
			t.Fatalf("expected event for %q", tc.line)
		}
		if ev.Type != tc.typ || ev.SourceIP != tc.ip || ev.Attrs["user"] != tc.user {
			t.Errorf("got %s %s %s, want %s %s %s", ev.Type, ev.SourceIP, ev.Attrs["user"], tc.typ, tc.ip, tc.user)
		}
	}
}

// TestAuthLogSample runs the parser over a real-looking log sample and checks the totals.
func TestAuthLogSample(t *testing.T) {
	f, err := os.Open("testdata/auth.log")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	counts := map[string]int{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if ev := ParseAuthLine(sc.Text(), time.Now()); ev != nil {
			counts[ev.Type]++
		}
	}
	if counts[model.TypeSSHAuthFailed] != 6 || counts[model.TypeSSHAuthSuccess] != 1 {
		t.Errorf("counts = %v", counts)
	}
}
