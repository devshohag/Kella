// Package actuators executes commands from the cloud (SPEC §8.5) with safety checks.
package actuators

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/devshohag/kella/agent/internal/model"
)

var (
	ErrUnsigned    = errors.New("command is not signed or signature is invalid")
	ErrExpired     = errors.New("command expired")
	ErrUnknownKind = errors.New("unknown command kind")
	ErrAllowlisted = errors.New("ip is allowlisted")
	ErrInvalidSender = errors.New("invalid sender email address")

	// strictEmail matches standard mailbox addresses without quotes, backticks, spaces, or shell metacharacters
	strictEmail = regexp.MustCompile(`^[a-zA-Z0-9.!#$%&'*+/=?^_` + "`" + `{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$`)
)

type Runner struct {
	DryRun        bool
	RequireSigned bool
	PublicKey     ed25519.PublicKey
	allow         []*net.IPNet
	Exec          func(ctx context.Context, name string, args ...string) (string, error)
	Now           func() time.Time
	SenderAccessPath string // default "/etc/postfix/sender_access"
}

// NewRunner builds a runner. cloudHost is always allowlisted so the agent never cuts itself off.
func NewRunner(dryRun, requireSigned bool, pubKeyB64 string, allowlist []string, cloudHost string) (*Runner, error) {
	r := &Runner{
		DryRun:        dryRun,
		RequireSigned: requireSigned,
		Exec:          runCmd,
		Now:           time.Now,
		SenderAccessPath: "/etc/postfix/sender_access",
	}
	if pubKeyB64 != "" {
		k, err := base64.StdEncoding.DecodeString(pubKeyB64)
		if err != nil || len(k) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid commandPublicKey")
		}
		r.PublicKey = k
	}
	entries := append([]string{"127.0.0.0/8", "::1/128"}, allowlist...)
	if ips, err := net.LookupIP(cloudHost); err == nil {
		for _, ip := range ips {
			entries = append(entries, ip.String())
		}
	}
	for _, e := range entries {
		if !strings.Contains(e, "/") {
			if strings.Contains(e, ":") {
				e += "/128"
			} else {
				e += "/32"
			}
		}
		_, n, err := net.ParseCIDR(e)
		if err != nil {
			return nil, fmt.Errorf("allowlist entry %q: %w", e, err)
		}
		r.allow = append(r.allow, n)
	}
	return r, nil
}

// SetPublicKey decodes a base64-encoded Ed25519 public key and stores it on the runner.
func (r *Runner) SetPublicKey(b64 string) error {
	k, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(k) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid commandPublicKey")
	}
	r.PublicKey = k
	return nil
}

// Execute validates and runs one command. The returned string goes into the ack output.
func (r *Runner) Execute(ctx context.Context, c model.Command) (string, error) {
	if !c.ExpiresAt.IsZero() && r.Now().After(c.ExpiresAt) {
		return "", ErrExpired
	}
	if err := r.verify(c); err != nil {
		return "", err
	}
	switch c.Kind {
	case "block_ip":
		return r.blockIP(ctx, c.Params["ip"], c.Params["ttlSec"])
	case "unblock_ip":
		return r.unblockIP(ctx, c.Params["ip"])
	case "hold_sender":
		return r.holdSender(ctx, c.Params["sender"])
	case "release_sender":
		return r.releaseSender(ctx, c.Params["sender"])
	case "cap_site_cpu", "run_check":
		// TODO(Phase 3): implement per SPEC §8.5.
		return "", fmt.Errorf("%s not implemented yet", c.Kind)
	default:
		return "", ErrUnknownKind
	}
}

// CanonicalPayload is what the cloud signs: id|kind|expiresAt(RFC3339)|k1=v1&k2=v2 (keys sorted).
func CanonicalPayload(c model.Command) []byte {
	keys := make([]string, 0, len(c.Params))
	for k := range c.Params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k + "=" + c.Params[k]
	}
	return []byte(fmt.Sprintf("%s|%s|%s|%s", c.ID, c.Kind, c.ExpiresAt.UTC().Format(time.RFC3339), strings.Join(parts, "&")))
}

func (r *Runner) verify(c model.Command) error {
	if !r.RequireSigned {
		return nil
	}
	sig, err := base64.StdEncoding.DecodeString(c.Signature)
	if err != nil || r.PublicKey == nil || !ed25519.Verify(r.PublicKey, CanonicalPayload(c), sig) {
		return ErrUnsigned
	}
	return nil
}

func (r *Runner) allowlisted(ip net.IP) bool {
	for _, n := range r.allow {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (r *Runner) blockIP(ctx context.Context, raw, ttl string) (string, error) {
	ip := net.ParseIP(raw)
	if ip == nil {
		return "", fmt.Errorf("invalid ip %q", raw)
	}
	if r.allowlisted(ip) {
		return "", ErrAllowlisted
	}
	if ttl == "" {
		ttl = "86400"
	}
	set := "kella_block"
	if ip.To4() == nil {
		set = "kella_block6"
	}
	args := []string{"add", "element", "inet", "kella", set, fmt.Sprintf("{ %s timeout %ss }", ip.String(), ttl)}
	return r.run(ctx, "nft", args...)
}

func (r *Runner) unblockIP(ctx context.Context, raw string) (string, error) {
	ip := net.ParseIP(raw)
	if ip == nil {
		return "", fmt.Errorf("invalid ip %q", raw)
	}
	set := "kella_block"
	if ip.To4() == nil {
		set = "kella_block6"
	}
	return r.run(ctx, "nft", "delete", "element", "inet", "kella", set, fmt.Sprintf("{ %s }", ip.String()))
}

// validateSender checks against shell injection and invalid email formats.
func validateSender(sender string) (string, error) {
	sender = strings.TrimSpace(sender)
	if sender == "" || len(sender) > 254 {
		return "", ErrInvalidSender
	}
	// Prohibit any dangerous characters
	if strings.ContainsAny(sender, " \t\r\n'\"`;$|&><()\\") {
		return "", ErrInvalidSender
	}
	if !strictEmail.MatchString(sender) {
		return "", ErrInvalidSender
	}
	return strings.ToLower(sender), nil
}

// holdSender adds the sender to Postfix check_sender_access map with HOLD action (SPEC §8.5).
// Idempotent: if sender already present, skips writing and re-syncing.
func (r *Runner) holdSender(ctx context.Context, rawSender string) (string, error) {
	sender, err := validateSender(rawSender)
	if err != nil {
		return "", err
	}

	accessPath := r.SenderAccessPath
	if accessPath == "" {
		accessPath = "/etc/postfix/sender_access"
	}

	// Read existing file if present
	var lines []string
	alreadyHeld := false
	if data, readErr := os.ReadFile(accessPath); readErr == nil {
		sc := bufio.NewScanner(bytes.NewReader(data))
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				lines = append(lines, sc.Text())
				continue
			}
			parts := strings.Fields(line)
			if len(parts) >= 2 && strings.EqualFold(parts[0], sender) && strings.ToUpper(parts[1]) == "HOLD" {
				alreadyHeld = true
			}
			lines = append(lines, sc.Text())
		}
	}

	if alreadyHeld {
		return "already held", nil
	}

	lines = append(lines, fmt.Sprintf("%s HOLD", sender))
	outContent := strings.Join(lines, "\n") + "\n"

	if !r.DryRun {
		if writeErr := os.WriteFile(accessPath, []byte(outContent), 0644); writeErr != nil {
			return "", fmt.Errorf("write sender_access: %w", writeErr)
		}
	}

	if _, err := r.run(ctx, "postmap", accessPath); err != nil {
		return "", fmt.Errorf("postmap: %w", err)
	}
	if _, err := r.run(ctx, "postfix", "reload"); err != nil {
		return "", fmt.Errorf("postfix reload: %w", err)
	}

	return "sender held", nil
}

type postqueueItem struct {
	QueueID string `json:"queue_id"`
	Sender  string `json:"sender"`
}

// releaseSender removes sender from check_sender_access map and releases held messages via postsuper -H (SPEC §8.5).
func (r *Runner) releaseSender(ctx context.Context, rawSender string) (string, error) {
	sender, err := validateSender(rawSender)
	if err != nil {
		return "", err
	}

	accessPath := r.SenderAccessPath
	if accessPath == "" {
		accessPath = "/etc/postfix/sender_access"
	}

	changed := false
	var newLines []string
	if data, readErr := os.ReadFile(accessPath); readErr == nil {
		sc := bufio.NewScanner(bytes.NewReader(data))
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				newLines = append(newLines, sc.Text())
				continue
			}
			parts := strings.Fields(line)
			if len(parts) >= 1 && strings.EqualFold(parts[0], sender) {
				changed = true
				continue // remove this line
			}
			newLines = append(newLines, sc.Text())
		}
	}

	if changed && !r.DryRun {
		outContent := ""
		if len(newLines) > 0 {
			outContent = strings.Join(newLines, "\n") + "\n"
		}
		if writeErr := os.WriteFile(accessPath, []byte(outContent), 0644); writeErr != nil {
			return "", fmt.Errorf("write sender_access: %w", writeErr)
		}
		if _, err := r.run(ctx, "postmap", accessPath); err != nil {
			return "", fmt.Errorf("postmap: %w", err)
		}
		if _, err := r.run(ctx, "postfix", "reload"); err != nil {
			return "", fmt.Errorf("postfix reload: %w", err)
		}
	}

	// Release queued messages matching exact sender using postqueue -j
	rawJSON, qErr := r.run(ctx, "postqueue", "-j")
	if qErr == nil && rawJSON != "" {
		dec := json.NewDecoder(strings.NewReader(rawJSON))
		for dec.More() {
			var item postqueueItem
			if err := dec.Decode(&item); err == nil {
				if strings.EqualFold(item.Sender, sender) && item.QueueID != "" {
					cleanID := strings.TrimRight(item.QueueID, "*!")
					_, _ = r.run(ctx, "postsuper", "-H", cleanID)
				}
			}
		}
	}

	return "sender released", nil
}

func (r *Runner) run(ctx context.Context, name string, args ...string) (string, error) {
	cmdline := name + " " + strings.Join(args, " ")
	if r.DryRun {
		slog.Info("dry run", "cmd", cmdline)
		return "dry run: " + cmdline, nil
	}
	return r.Exec(ctx, name, args...)
}

func runCmd(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s: %w", name, err)
	}
	return string(out), nil
}
