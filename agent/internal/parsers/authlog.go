// Package parsers turns raw log lines into normalized events (SPEC §7). Raw lines never leave the server.
package parsers

import (
	"regexp"
	"time"

	"github.com/example/shield/agent/internal/model"
)

var (
	sshFailed   = regexp.MustCompile(`sshd\[\d+\]: Failed (?:password|publickey) for (?:invalid user )?(\S+) from (\S+) port \d+`)
	sshInvalid  = regexp.MustCompile(`sshd\[\d+\]: Invalid user (\S*) from (\S+) port \d+`)
	sshAccepted = regexp.MustCompile(`sshd\[\d+\]: Accepted (\S+) for (\S+) from (\S+) port \d+`)
)

// ParseAuthLine parses one line of /var/log/auth.log (Debian/Ubuntu). Returns nil for irrelevant lines.
// "Invalid user" lines are ignored because sshd also logs a "Failed password" line for the same attempt.
func ParseAuthLine(line string, now time.Time) *model.Event {
	if m := sshFailed.FindStringSubmatch(line); m != nil {
		return &model.Event{
			Ts: now, Module: "server", Type: model.TypeSSHAuthFailed, Severity: "info",
			SourceIP: m[2], Attrs: map[string]string{"user": m[1]},
		}
	}
	if m := sshAccepted.FindStringSubmatch(line); m != nil {
		return &model.Event{
			Ts: now, Module: "server", Type: model.TypeSSHAuthSuccess, Severity: "info",
			SourceIP: m[3], Attrs: map[string]string{"user": m[2], "method": m[1]},
		}
	}
	_ = sshInvalid // kept for future "invalid user" statistics
	return nil
}
