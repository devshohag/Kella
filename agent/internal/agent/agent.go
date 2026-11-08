// Package agent wires collectors, parsers, the cloud client and actuators together.
package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/example/shield/agent/internal/actuators"
	"github.com/example/shield/agent/internal/client"
	"github.com/example/shield/agent/internal/collect"
	"github.com/example/shield/agent/internal/config"
	"github.com/example/shield/agent/internal/detect"
	"github.com/example/shield/agent/internal/model"
	"github.com/example/shield/agent/internal/parsers"
	"github.com/example/shield/agent/internal/tail"
)

const Version = "0.1.0"

// maxBuffered caps events held in memory while the cloud is unreachable.
// TODO(Phase 1): spill to disk under StatePath/queue (max 100 MB, SPEC §8.6).
const maxBuffered = 50_000

type Agent struct {
	cfg      *config.Config
	api      *client.Client
	runner   *actuators.Runner
	serverID string

	mu  sync.Mutex
	buf []model.Event
}

func New(cfg *config.Config) (*Agent, error) {
	u, err := url.Parse(cfg.CloudURL)
	if err != nil {
		return nil, fmt.Errorf("cloudUrl: %w", err)
	}
	runner, err := actuators.NewRunner(cfg.Actions.DryRun, cfg.Actions.RequireSigned,
		cfg.Actions.CommandPublicKey, cfg.Actions.Allowlist, u.Hostname())
	if err != nil {
		return nil, err
	}
	return &Agent{cfg: cfg, api: client.New(cfg.CloudURL, ""), runner: runner}, nil
}

func (a *Agent) Run(ctx context.Context) error {
	if err := a.ensureEnrolled(ctx); err != nil {
		return err
	}
	a.reportFacts(ctx)

	var wg sync.WaitGroup
	start := func(f func(context.Context)) { wg.Add(1); go func() { defer wg.Done(); f(ctx) }() }
	start(a.heartbeatLoop)
	start(a.flushLoop)
	start(a.commandLoop)
	start(a.factsLoop)
	start(func(ctx context.Context) { a.followLog(ctx, a.cfg.Logs.Auth, parsers.ParseAuthLine) })
	// TODO(Phase 2): mail.log parser (Postfix/Dovecot) → mail.auth_failed, mail.message_queued.

	<-ctx.Done()
	wg.Wait()
	return nil
}

func (a *Agent) ensureEnrolled(ctx context.Context) error {
	if b, err := os.ReadFile(a.cfg.TokenPath); err == nil {
		parts := strings.SplitN(strings.TrimSpace(string(b)), " ", 2)
		if len(parts) == 2 {
			a.serverID = parts[0]
			a.api.SetToken(parts[1])
			return nil
		}
	}
	if a.cfg.EnrollmentKey == "" {
		return errors.New("not enrolled and no enrollmentKey in config")
	}
	host, _ := os.Hostname()
	res, err := a.api.Enroll(ctx, model.EnrollRequest{
		EnrollmentKey: a.cfg.EnrollmentKey,
		Hostname:      host,
		OS:            osName(),
		CPUCount:      runtime.NumCPU(),
		RAMMb:         ramMb(),
		AgentVersion:  Version,
	})
	if err != nil {
		return fmt.Errorf("enroll: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(a.cfg.TokenPath), 0o700); err != nil {
		return fmt.Errorf("token dir: %w", err)
	}
	if err := os.WriteFile(a.cfg.TokenPath, []byte(res.ServerID+" "+res.AgentToken), 0o600); err != nil {
		return fmt.Errorf("save token: %w", err)
	}
	a.serverID = res.ServerID
	a.api.SetToken(res.AgentToken)
	slog.Info("enrolled", "serverId", res.ServerID)
	return nil
}

func (a *Agent) reportFacts(ctx context.Context) {
	d, g := detect.Run("/proc")
	if err := a.api.PutFacts(ctx, model.Facts{Detected: d, Guards: g}); err != nil {
		slog.Warn("report facts", "err", err)
		return
	}
	slog.Info("facts reported", "detected", d, "guards", g)
}

func (a *Agent) factsLoop(ctx context.Context) {
	t := time.NewTicker(6 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.reportFacts(ctx)
		}
	}
}

func (a *Agent) heartbeatLoop(ctx context.Context) {
	var cpu collect.CPUSampler
	cpu.CPUPct() // prime
	t := time.NewTicker(a.cfg.HeartbeatInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			snap := collect.Take(&cpu)
			a.push(model.Event{Ts: time.Now().UTC(), Module: "server", Type: model.TypeHeartbeat, Severity: "info", Attrs: snap.Attrs()})
		}
	}
}

func (a *Agent) followLog(ctx context.Context, path string, parse func(string, time.Time) *model.Event) {
	if path == "" {
		return
	}
	lines := make(chan string, 1024)
	go tail.Follow(ctx, path, lines)
	for {
		select {
		case <-ctx.Done():
			return
		case line := <-lines:
			if ev := parse(line, time.Now().UTC()); ev != nil {
				a.push(*ev)
			}
		}
	}
}

func (a *Agent) push(ev model.Event) {
	if ev.ID == "" {
		ev.ID = newID()
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.buf) >= maxBuffered {
		a.buf = a.buf[1:]
	}
	a.buf = append(a.buf, ev)
}

func (a *Agent) flushLoop(ctx context.Context) {
	t := time.NewTicker(a.cfg.FlushInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.flush(ctx)
		}
	}
}

func (a *Agent) flush(ctx context.Context) {
	a.mu.Lock()
	n := min(len(a.buf), 1000)
	batch := append([]model.Event(nil), a.buf[:n]...)
	a.mu.Unlock()
	if n == 0 {
		return
	}
	err := a.api.SendEvents(ctx, model.EventBatch{AgentVersion: Version, ServerID: a.serverID, SentAt: time.Now().UTC(), Events: batch})
	if err != nil {
		slog.Warn("send events", "err", err, "buffered", n)
		return
	}
	a.mu.Lock()
	a.buf = a.buf[n:]
	a.mu.Unlock()
}

func (a *Agent) commandLoop(ctx context.Context) {
	for ctx.Err() == nil {
		cmds, err := a.api.PollCommands(ctx, 30)
		if err != nil {
			slog.Warn("poll commands", "err", err)
			sleep(ctx, 10*time.Second)
			continue
		}
		for _, c := range cmds {
			out, err := a.runner.Execute(ctx, c)
			ack := model.CommandAck{Ok: err == nil, Output: out}
			if err != nil {
				ack.Output = err.Error()
				slog.Warn("command failed", "kind", c.Kind, "err", err)
			} else {
				slog.Info("command done", "kind", c.Kind, "params", c.Params)
			}
			if err := a.api.Ack(ctx, c.ID, ack); err != nil {
				slog.Warn("ack", "err", err)
			}
		}
	}
}

func sleep(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}

func newID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func osName() string {
	b, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return runtime.GOOS
	}
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(l, "PRETTY_NAME="); ok {
			return strings.Trim(v, `"`)
		}
	}
	return runtime.GOOS
}

func ramMb() int {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	var kb int
	_, _ = fmt.Sscanf(strings.SplitN(string(b), "\n", 2)[0], "MemTotal: %d kB", &kb)
	return kb / 1024
}
