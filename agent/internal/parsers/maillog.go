package parsers

import (
	"regexp"
	"sync"
	"time"

	"github.com/devshohag/kella/agent/internal/model"
)

var (
	// Dovecot authentication failed (covers Dovecot 2.2 / 2.3 formats)
	// Format 1: dovecot: imap-login: Disconnected (auth failed, 1 attempts in 2 secs): user=<billing@rahmantraders.com>, method=PLAIN, rip=45.148.10.92, lip=...
	// Format 2: dovecot: imap-login: Disconnected: Connection closed: auth failed, method=PLAIN, user=<billing@rahmantraders.com>, rip=45.148.10.92, lip=...
	// Format 3: dovecot: pop3-login: Aborted login (auth failed, 1 attempts in 4 secs): user=<info@example.com>, method=PLAIN, rip=185.220.101.5, lip=...
	dovecotFailed = regexp.MustCompile(`dovecot: (?:imap|pop3|submission)-login: (?:Disconnected|Aborted login).*?auth failed.*?user=<([^>]+)>.*?rip=([0-9a-fA-F.:]+)`)

	// Dovecot authentication succeeded
	// e.g., dovecot: imap-login: Login: user=<sales@acme.com>, method=PLAIN, rip=203.0.113.15, lip=...
	dovecotSuccess = regexp.MustCompile(`dovecot: (?:imap|pop3|submission)-login: Login: user=<([^>]+)>.*?rip=([0-9a-fA-F.:]+)`)

	// Postfix smtpd SASL authentication failure
	// e.g., postfix/smtpd[1234]: warning: unknown[198.51.100.55]: SASL LOGIN authentication failed: UGFzc3dvcmQ6
	// e.g., postfix/smtpd[1234]: warning: mail.example.com[198.51.100.55]: SASL PLAIN authentication failed: authentication failure
	// Source: official Postfix documentation
	postfixSaslFailed = regexp.MustCompile(`postfix/(?:submission/)?smtpd\[(\d+)\]: warning: [^\[]*\[([0-9a-fA-F.:]+)\]: SASL (?:LOGIN|PLAIN|DIGEST-MD5|CRAM-MD5) authentication failed(?::\s*(?:.*?(?:user=<([^>]+)>|username=([^\s,]+)))?)?`)

	// Postfix smtpd disconnect with failed authentication or lost connection after AUTH
	// e.g., postfix/smtpd[4512]: disconnect from unknown[198.51.100.55] ehlo=1 auth=0/1 quit=1 commands=2/3
	// e.g., postfix/smtpd[4512]: lost connection after AUTH from unknown[198.51.100.55]
	// Source: official Postfix documentation
	postfixDisconnectAuthFailed = regexp.MustCompile(`postfix/(?:submission/)?smtpd\[(\d+)\]: (?:disconnect from [^\[]*\[([0-9a-fA-F.:]+)\].*?auth=0/\d+|lost connection after AUTH from [^\[]*\[([0-9a-fA-F.:]+)\])`)

	// Postfix smtpd SASL authenticated client line
	// e.g., postfix/smtpd[4512]: 4Sxyz91234z: client=unknown[198.51.100.55], sasl_method=PLAIN, sasl_username=user@domain.com
	postfixSmtpdSaslUser = regexp.MustCompile(`postfix/(?:submission/)?smtpd\[\d+\]: ([A-Za-z0-9]+): .*?sasl_username=([^\s,]+)`)

	// Postfix qmgr queued message
	// e.g., postfix/qmgr[2345]: 4Sxyz91234z: from=<spammer@badtenant.com>, size=4521, nrcpt=50 (queue active)
	postfixQueued = regexp.MustCompile(`postfix/qmgr\[\d+\]: ([A-Za-z0-9]+): from=<([^>]*)>, size=(\d+), nrcpt=(\d+)`)
)

type queueEntry struct {
	saslUser string
	ts       time.Time
}

// MailParser parses mail log lines while tracking SASL authentication context for outbound queues.
type MailParser struct {
	mu         sync.Mutex
	queueUsers map[string]queueEntry
}

// NewMailParser creates a new MailParser instance.
func NewMailParser() *MailParser {
	return &MailParser{
		queueUsers: make(map[string]queueEntry),
	}
}

var defaultMailParser = NewMailParser()

// ParseMailLine parses a line from /var/log/mail.log or journald mail logs (SPEC §7).
func ParseMailLine(line string, now time.Time) *model.Event {
	return defaultMailParser.Parse(line, now)
}

// Parse processes a single log line with queue tracking.
func (p *MailParser) Parse(line string, now time.Time) *model.Event {
	if m := postfixSmtpdSaslUser.FindStringSubmatch(line); m != nil {
		p.mu.Lock()
		if len(p.queueUsers) >= 10000 {
			for qid, entry := range p.queueUsers {
				if now.Sub(entry.ts) > 10*time.Minute {
					delete(p.queueUsers, qid)
				}
			}
			if len(p.queueUsers) >= 10000 {
				for qid := range p.queueUsers {
					delete(p.queueUsers, qid)
					break
				}
			}
		}
		p.queueUsers[m[1]] = queueEntry{
			saslUser: m[2],
			ts:       now,
		}
		p.mu.Unlock()
		return nil
	}

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

	if m := postfixSaslFailed.FindStringSubmatch(line); m != nil {
		attrs := map[string]string{
			"service": "postfix-smtpd",
		}
		user := ""
		if len(m) > 3 && m[3] != "" {
			user = m[3]
		} else if len(m) > 4 && m[4] != "" {
			user = m[4]
		}
		if user != "" {
			attrs["user"] = user
		}
		return &model.Event{
			Ts:       now,
			Module:   "mail",
			Type:     model.TypeMailAuthFailed,
			Severity: "info",
			SourceIP: m[2],
			Attrs:    attrs,
		}
	}

	if m := postfixDisconnectAuthFailed.FindStringSubmatch(line); m != nil {
		ip := m[2]
		if ip == "" && len(m) > 3 {
			ip = m[3]
		}
		return &model.Event{
			Ts:       now,
			Module:   "mail",
			Type:     model.TypeMailAuthFailed,
			Severity: "info",
			SourceIP: ip,
			Attrs: map[string]string{
				"service": "postfix-smtpd",
			},
		}
	}

	if m := postfixQueued.FindStringSubmatch(line); m != nil {
		queueID := m[1]
		sender := m[2]
		if sender == "" {
			sender = "MAILER-DAEMON"
		}

		p.mu.Lock()
		entry, found := p.queueUsers[queueID]
		if found {
			delete(p.queueUsers, queueID)
		}
		p.mu.Unlock()

		authenticated := "false"
		var saslUser string
		if found && now.Sub(entry.ts) <= 10*time.Minute {
			authenticated = "true"
			saslUser = entry.saslUser
		}

		attrs := map[string]string{
			"queueId":       queueID,
			"sender":        sender,
			"size":          m[3],
			"recipients":    m[4],
			"authenticated": authenticated,
		}
		if authenticated == "true" {
			attrs["sasl_username"] = saslUser
		}

		return &model.Event{
			Ts:       now,
			Module:   "mail",
			Type:     model.TypeMailMessageQueue,
			Severity: "info",
			Attrs:    attrs,
		}
	}

	return nil
}
