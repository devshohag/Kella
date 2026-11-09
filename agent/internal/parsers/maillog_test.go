package parsers

import (
	"bufio"
	"os"
	"testing"
	"time"

	"github.com/devshohag/kella/agent/internal/model"
)

func TestParseMailLine(t *testing.T) {
	now := time.Date(2026, 11, 8, 2, 14, 0, 0, time.UTC)

	tests := []struct {
		name     string
		line     string
		wantType string
		wantIP   string
		wantUser string
		isNil    bool
	}{
		{
			name:     "Dovecot IMAP failed format 1",
			line:     "Nov  8 02:14:01 mail-01 dovecot: imap-login: Disconnected: Connection closed: auth failed, method=PLAIN, user=<billing@rahmantraders.com>, rip=45.148.10.92, lip=192.168.1.10",
			wantType: model.TypeMailAuthFailed,
			wantIP:   "45.148.10.92",
			wantUser: "billing@rahmantraders.com",
		},
		{
			name:     "Dovecot 2.3 real format - Aborted login",
			line:     "Nov  8 02:14:05 mail-01 dovecot: pop3-login: Aborted login (auth failed, 1 attempts in 4 secs): user=<info@example.com>, method=PLAIN, rip=185.220.101.5, lip=192.168.1.10",
			wantType: model.TypeMailAuthFailed,
			wantIP:   "185.220.101.5",
			wantUser: "info@example.com",
		},
		{
			name:     "Dovecot 2.3 real format - Disconnected auth failed",
			line:     "Nov  8 02:14:08 mail-01 dovecot: imap-login: Disconnected (auth failed, 1 attempts in 2 secs): user=<ceo@victim.com>, method=PLAIN, rip=193.32.162.20, lip=192.168.1.10, TLS",
			wantType: model.TypeMailAuthFailed,
			wantIP:   "193.32.162.20",
			wantUser: "ceo@victim.com",
		},
		{
			name:     "Dovecot login success",
			line:     "Nov  8 02:14:10 mail-01 dovecot: imap-login: Login: user=<sales@acme.com>, method=PLAIN, rip=203.0.113.15, lip=192.168.1.10, mpid=12345, TLS",
			wantType: model.TypeMailAuthSuccess,
			wantIP:   "203.0.113.15",
			wantUser: "sales@acme.com",
		},
		{
			name:     "Postfix smtpd SASL failure",
			line:     "Nov  8 02:14:15 mail-01 postfix/smtpd[4512]: warning: unknown[198.51.100.55]: SASL LOGIN authentication failed: UGFzc3dvcmQ6",
			wantType: model.TypeMailAuthFailed,
			wantIP:   "198.51.100.55",
			wantUser: "",
		},
		{
			name:     "Postfix message queued",
			line:     "Nov  8 02:15:00 mail-01 postfix/qmgr[2345]: 4Sxyz91234z: from=<spammer@badtenant.com>, size=4521, nrcpt=50 (queue active)",
			wantType: model.TypeMailMessageQueue,
			wantUser: "",
		},
		{
			name:  "Postfix cleanup irrelevant line",
			line:  "Nov  8 02:15:02 mail-01 postfix/cleanup[2346]: 4Sxyz95678z: message-id=<20261108021502.1234@mail.badtenant.com>",
			isNil: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev := ParseMailLine(tc.line, now)
			if tc.isNil {
				if ev != nil {
					t.Fatalf("expected nil event, got %+v", ev)
				}
				return
			}
			if ev == nil {
				t.Fatalf("expected event for line %q, got nil", tc.line)
			}
			if ev.Type != tc.wantType {
				t.Errorf("got type %q, want %q", ev.Type, tc.wantType)
			}
			if tc.wantIP != "" && ev.SourceIP != tc.wantIP {
				t.Errorf("got IP %q, want %q", ev.SourceIP, tc.wantIP)
			}
			if tc.wantUser != "" && ev.Attrs["user"] != tc.wantUser {
				t.Errorf("got user %q, want %q", ev.Attrs["user"], tc.wantUser)
			}
		})
	}
}

func TestMailLogSample(t *testing.T) {
	f, err := os.Open("testdata/mail.log")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	counts := map[string]int{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if ev := ParseMailLine(sc.Text(), time.Now()); ev != nil {
			counts[ev.Type]++
		}
	}

	if counts[model.TypeMailAuthFailed] != 4 {
		t.Errorf("expected 4 auth_failed (3 dovecot + 1 postfix SASL), got %d", counts[model.TypeMailAuthFailed])
	}
	if counts[model.TypeMailAuthSuccess] != 1 {
		t.Errorf("expected 1 auth_succeeded, got %d", counts[model.TypeMailAuthSuccess])
	}
	if counts[model.TypeMailMessageQueue] != 2 {
		t.Errorf("expected 2 message_queued, got %d", counts[model.TypeMailMessageQueue])
	}
}

func TestParseMailLine_AuthenticatedVsInbound(t *testing.T) {
	parser := NewMailParser()
	now := time.Date(2026, 11, 8, 2, 14, 0, 0, time.UTC)

	// Real Postfix capture: smtpd client authentication followed by qmgr
	smtpdLine := "Nov  8 02:14:55 mail-01 postfix/smtpd[4512]: 4Sxyz91234z: client=unknown[198.51.100.55], sasl_method=PLAIN, sasl_username=user@domain.com"
	qmgrLineAuth := "Nov  8 02:14:56 mail-01 postfix/qmgr[2345]: 4Sxyz91234z: from=<spoofed@external.com>, size=4521, nrcpt=1 (queue active)"

	ev1 := parser.Parse(smtpdLine, now)
	if ev1 != nil {
		t.Fatalf("expected nil event for smtpd sasl line, got %+v", ev1)
	}

	ev2 := parser.Parse(qmgrLineAuth, now.Add(time.Second))
	if ev2 == nil {
		t.Fatalf("expected event for qmgr line, got nil")
	}
	if ev2.Attrs["authenticated"] != "true" {
		t.Errorf("got authenticated %q, want 'true'", ev2.Attrs["authenticated"])
	}
	if ev2.Attrs["sasl_username"] != "user@domain.com" {
		t.Errorf("got sasl_username %q, want 'user@domain.com'", ev2.Attrs["sasl_username"])
	}
	if ev2.Attrs["sender"] != "spoofed@external.com" {
		t.Errorf("got sender %q, want 'spoofed@external.com'", ev2.Attrs["sender"])
	}

	// Incoming message without SASL authentication
	qmgrLineInbound := "Nov  8 02:15:00 mail-01 postfix/qmgr[2345]: 4Sinbound999z: from=<external@outside.com>, size=1200, nrcpt=1 (queue active)"
	ev3 := parser.Parse(qmgrLineInbound, now.Add(2*time.Second))
	if ev3 == nil {
		t.Fatalf("expected event for inbound qmgr line, got nil")
	}
	if ev3.Attrs["authenticated"] != "false" {
		t.Errorf("got authenticated %q, want 'false'", ev3.Attrs["authenticated"])
	}
	if _, ok := ev3.Attrs["sasl_username"]; ok {
		t.Errorf("expected no sasl_username for inbound mail, got %q", ev3.Attrs["sasl_username"])
	}
}

func TestParseMailLine_SaslDigestMD5(t *testing.T) {
	line := "Nov  8 02:14:15 mail-01 postfix/smtpd[4512]: warning: unknown[198.51.100.55]: SASL DIGEST-MD5 authentication failed: authentication failure"
	ev := ParseMailLine(line, time.Now())
	if ev == nil {
		t.Fatal("expected event for SASL DIGEST-MD5, got nil")
	}
	if ev.Type != model.TypeMailAuthFailed {
		t.Errorf("got type %q, want %q", ev.Type, model.TypeMailAuthFailed)
	}
	if ev.SourceIP != "198.51.100.55" {
		t.Errorf("got IP %q, want '198.51.100.55'", ev.SourceIP)
	}
}
