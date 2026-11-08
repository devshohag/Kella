package parsers

import (
	"regexp"
	"time"

	"github.com/devshohag/kella/agent/internal/model"
)

var (
	// Dovecot authentication failed
	// e.g., dovecot: imap-login: Disconnected: ... auth failed, method=PLAIN, user=<billing@rahmantraders.com>, rip=45.148.10.92, lip=...
	dovecotFailed = regexp.MustCompile(`dovecot: (?:imap|pop3|submission)-login: (?:Disconnected|Aborted login):.*auth failed.*user=<([^>]+)>.*rip=([0-9a-fA-F.:]+)`)

	// Dovecot authentication succeeded
	// e.g., dovecot: imap-login: Login: user=<sales@acme.com>, method=PLAIN, rip=203.0.113.15, lip=...
	dovecotSuccess = regexp.MustCompile(`dovecot: (?:imap|pop3|submission)-login: Login: user=<([^>]+)>.*rip=([0-9a-fA-F.:]+)`)

	// Postfix qmgr queued message
	// e.g., postfix/qmgr[2345]: 4Sxyz91234z: from=<spammer@badtenant.com>, size=4521, nrcpt=50 (queue active)
	postfixQueued = regexp.MustCompile(`postfix/qmgr\[\d+\]: ([A-Za-z0-9]+): from=<([^>]*)>, size=(\d+), nrcpt=(\d+)`)
)

// ParseMailLine parses a line from /var/log/mail.log or journald mail logs (SPEC §7).
func ParseMailLine(line string, now time.Time) *model.Event {
	if m := dovecotFailed.FindStringSubmatch(line); m != nil {
		return &model.Event{
			Ts:       now,
			Module:   "mail",
			Type:     model.TypeMailAuthFailed,
			Severity: "info",
			SourceIP: m[2],
			Attrs: map[string]string{
				"user":    m[1],
				"service": "dovecot",
			},
		}
	}

	if m := dovecotSuccess.FindStringSubmatch(line); m != nil {
		return &model.Event{
			Ts:       now,
			Module:   "mail",
			Type:     model.TypeMailAuthSuccess,
			Severity: "info",
			SourceIP: m[2],
			Attrs: map[string]string{
				"user":    m[1],
				"service": "dovecot",
			},
		}
	}

	if m := postfixQueued.FindStringSubmatch(line); m != nil {
		sender := m[2]
		if sender == "" {
			sender = "MAILER-DAEMON"
		}
		return &model.Event{
			Ts:       now,
			Module:   "mail",
			Type:     model.TypeMailMessageQueue,
			Severity: "info",
			Attrs: map[string]string{
				"queueId":    m[1],
				"sender":     sender,
				"size":       m[3],
				"recipients": m[4],
			},
		}
	}

	return nil
}
