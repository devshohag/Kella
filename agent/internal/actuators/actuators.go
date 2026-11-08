// Package actuators executes commands from the cloud (SPEC §8.5) with safety checks.
package actuators

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
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
)

type Runner struct {
	DryRun        bool
	RequireSigned bool
	PublicKey     ed25519.PublicKey
	allow         []*net.IPNet
	Exec          func(ctx context.Context, name string, args ...string) (string, error)
	Now           func() time.Time
}

// NewRunner builds a runner. cloudHost is always allowlisted so the agent never cuts itself off.
func NewRunner(dryRun, requireSigned bool, pubKeyB64 string, allowlist []string, cloudHost string) (*Runner, error) {
	r := &Runner{DryRun: dryRun, RequireSigned: requireSigned, Exec: runCmd, Now: time.Now}
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
// Called from ensureEnrolled when the cloud returns a commandPublicKey.
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
// The backend builds the same string in CommandSigner.CanonicalPayload (Kella.Infrastructure.Security).
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

func (r *Runner) holdSender(ctx context.Context, sender string) (string, error) {
	sender = strings.TrimSpace(sender)
	if sender == "" || !strings.Contains(sender, "@") {
		return "", fmt.Errorf("invalid sender email %q", sender)
	}

	// Postfix hold sender implementation (SPEC §8.5):
	// Add HOLD to check_sender_access map, postmap, and postfix reload.
	// We invoke standard helper script or postmap commands.
	accessMap := "/etc/postfix/sender_access"
	if out, err := r.run(ctx, "sh", "-c", fmt.Sprintf("echo '%s HOLD' >> %s && postmap %s && postfix reload", sender, accessMap, accessMap)); err != nil {
		return out, fmt.Errorf("hold_sender: %w", err)
	}
	return "sender held", nil
}

func (r *Runner) releaseSender(ctx context.Context, sender string) (string, error) {
	sender = strings.TrimSpace(sender)
	if sender == "" || !strings.Contains(sender, "@") {
		return "", fmt.Errorf("invalid sender email %q", sender)
	}

	// Postfix release sender implementation (SPEC §8.5):
	// Remove from sender_access map, postmap, postfix reload, and release queued messages.
	accessMap := "/etc/postfix/sender_access"
	cmd := fmt.Sprintf("sed -i '/^%s /d' %s && postmap %s && postfix reload && (postqueue -p | grep -B 2 '%s' | awk '/^[0-9A-Z]/ {print $1}' | postsuper -H - || true)",
		regexp.QuoteMeta(sender), accessMap, accessMap, regexp.QuoteMeta(sender))
	if out, err := r.run(ctx, "sh", "-c", cmd); err != nil {
		return out, fmt.Errorf("release_sender: %w", err)
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
