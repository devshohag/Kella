package actuators

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/devshohag/kella/agent/internal/model"
)

func newTestRunner(t *testing.T, requireSigned bool, pub string) (*Runner, *[]string) {
	t.Helper()
	r, err := NewRunner(false, requireSigned, pub, []string{"10.0.0.0/8", "203.0.113.5"}, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	var calls []string
	r.Exec = func(_ context.Context, name string, args ...string) (string, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return "", nil
	}
	return r, &calls
}

func cmd(ip string) model.Command {
	return model.Command{ID: "c1", Kind: "block_ip", Params: map[string]string{"ip": ip, "ttlSec": "3600"}, ExpiresAt: time.Now().Add(time.Minute)}
}

func TestBlockIPRunsNft(t *testing.T) {
	r, calls := newTestRunner(t, false, "")
	if _, err := r.Execute(context.Background(), cmd("45.148.10.92")); err != nil {
		t.Fatal(err)
	}
	want := "nft add element inet kella kella_block { 45.148.10.92 timeout 3600s }"
	if len(*calls) != 1 || (*calls)[0] != want {
		t.Fatalf("calls = %v", *calls)
	}
}

func TestRefusesAllowlistedAndLoopback(t *testing.T) {
	r, calls := newTestRunner(t, false, "")
	for _, ip := range []string{"10.1.2.3", "203.0.113.5", "127.0.0.1"} {
		if _, err := r.Execute(context.Background(), cmd(ip)); !errors.Is(err, ErrAllowlisted) {
			t.Errorf("%s: err = %v, want ErrAllowlisted", ip, err)
		}
	}
	if len(*calls) != 0 {
		t.Fatalf("nothing should run, got %v", *calls)
	}
}

func TestRejectsInvalidIPExpiredAndUnknown(t *testing.T) {
	r, _ := newTestRunner(t, false, "")
	if _, err := r.Execute(context.Background(), cmd("1.2.3.4; rm -rf /")); err == nil {
		t.Error("invalid ip must fail")
	}
	c := cmd("45.148.10.92")
	c.ExpiresAt = time.Now().Add(-time.Second)
	if _, err := r.Execute(context.Background(), c); !errors.Is(err, ErrExpired) {
		t.Errorf("err = %v, want ErrExpired", err)
	}
	if _, err := r.Execute(context.Background(), model.Command{Kind: "format_disk"}); !errors.Is(err, ErrUnknownKind) {
		t.Errorf("err = %v, want ErrUnknownKind", err)
	}
}

func TestSignatureRequired(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	r, calls := newTestRunner(t, true, base64.StdEncoding.EncodeToString(pub))

	c := cmd("45.148.10.92")
	if _, err := r.Execute(context.Background(), c); !errors.Is(err, ErrUnsigned) {
		t.Fatalf("unsigned: err = %v", err)
	}
	c.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, CanonicalPayload(c)))
	if _, err := r.Execute(context.Background(), c); err != nil {
		t.Fatalf("signed: %v", err)
	}
	c.Params["ip"] = "45.148.10.93" // tampered after signing
	if _, err := r.Execute(context.Background(), c); !errors.Is(err, ErrUnsigned) {
		t.Fatalf("tampered: err = %v", err)
	}
	if len(*calls) != 1 {
		t.Fatalf("exactly one command should run, got %v", *calls)
	}
}

func TestHoldSenderRejectsInjectionAndInvalidEmail(t *testing.T) {
	r, _ := newTestRunner(t, false, "")
	badEmails := []string{
		"victim@test.org; rm -rf /",
		"victim@test.org`whoami`",
		"victim@test.org$(id)",
		"\"victim\"@test.org",
		"victim@test.org\nroot HOLD",
		"not-an-email",
		"victim @test.org",
		"",
	}

	for _, bad := range badEmails {
		holdCmd := model.Command{
			ID:        "c_bad",
			Kind:      "hold_sender",
			Params:    map[string]string{"sender": bad},
			ExpiresAt: time.Now().Add(time.Minute),
		}
		if _, err := r.Execute(context.Background(), holdCmd); !errors.Is(err, ErrInvalidSender) {
			t.Errorf("expected ErrInvalidSender for %q, got %v", bad, err)
		}
	}
}

func TestHoldSenderIdempotencyAndNoShell(t *testing.T) {
	tmpDir := t.TempDir()
	accessPath := filepath.Join(tmpDir, "sender_access")

	r, calls := newTestRunner(t, false, "")
	r.SenderAccessPath = accessPath

	holdCmd := model.Command{
		ID:        "c_hold",
		Kind:      "hold_sender",
		Params:    map[string]string{"sender": "spammer@badtenant.com"},
		ExpiresAt: time.Now().Add(time.Minute),
	}

	// First execution adds sender, runs postmap, postfix reload
	res, err := r.Execute(context.Background(), holdCmd)
	if err != nil {
		t.Fatalf("first hold error: %v", err)
	}
	if res != "sender held" {
		t.Fatalf("unexpected res: %s", res)
	}
	for _, call := range *calls {
		if strings.Contains(call, "sh -c") {
			t.Errorf("sh -c must not be used, found %s", call)
		}
	}

	// Verify file content
	content, _ := os.ReadFile(accessPath)
	if !strings.Contains(string(content), "spammer@badtenant.com HOLD") {
		t.Fatalf("sender_access missing entry: %s", string(content))
	}

	// Second execution should be a no-op (idempotent)
	callsCountBefore := len(*calls)
	res2, err := r.Execute(context.Background(), holdCmd)
	if err != nil {
		t.Fatalf("second hold error: %v", err)
	}
	if res2 != "already held" {
		t.Fatalf("expected 'already held', got %s", res2)
	}
	if len(*calls) != callsCountBefore {
		t.Fatalf("no commands should be executed on duplicate hold, calls: %v", *calls)
	}
}

func TestReleaseSenderWithPostqueueJson(t *testing.T) {
	tmpDir := t.TempDir()
	accessPath := filepath.Join(tmpDir, "sender_access")
	_ = os.WriteFile(accessPath, []byte("spammer@badtenant.com HOLD\nother@good.com OK\n"), 0644)

	r, calls := newTestRunner(t, false, "")
	r.SenderAccessPath = accessPath
	r.Exec = func(_ context.Context, name string, args ...string) (string, error) {
		full := name + " " + strings.Join(args, " ")
		*calls = append(*calls, full)
		if name == "postqueue" && len(args) == 1 && args[0] == "-j" {
			// Mock json output with queue items
			return `{"queue_id": "4Sxyz91234z*", "sender": "spammer@badtenant.com"}
{"queue_id": "4Sxyz95678z!", "sender": "other@good.com"}
{"queue_id": "4Sxyz99999z", "sender": "spammer@badtenant.com"}`, nil
		}
		return "", nil
	}

	relCmd := model.Command{
		ID:        "c_rel",
		Kind:      "release_sender",
		Params:    map[string]string{"sender": "spammer@badtenant.com"},
		ExpiresAt: time.Now().Add(time.Minute),
	}

	if _, err := r.Execute(context.Background(), relCmd); err != nil {
		t.Fatalf("releaseSender error: %v", err)
	}

	// Verify file had sender removed
	content, _ := os.ReadFile(accessPath)
	if strings.Contains(string(content), "spammer@badtenant.com") {
		t.Fatalf("spammer should be removed from file, content: %s", string(content))
	}
	if !strings.Contains(string(content), "other@good.com") {
		t.Fatalf("other sender must remain in file, content: %s", string(content))
	}

	// Verify postsuper -H was called for both matching messages and stripped of * or !
	hasId1 := false
	hasId2 := false
	hasBadId := false
	for _, call := range *calls {
		if strings.Contains(call, "sh -c") {
			t.Errorf("sh -c must not be used, found: %s", call)
		}
		if call == "postsuper -H 4Sxyz91234z" {
			hasId1 = true
		}
		if call == "postsuper -H 4Sxyz99999z" {
			hasId2 = true
		}
		if strings.Contains(call, "4Sxyz95678z") {
			hasBadId = true
		}
	}

	if !hasId1 || !hasId2 {
		t.Errorf("postsuper -H not called correctly for matching IDs: %v", *calls)
	}
	if hasBadId {
		t.Errorf("postsuper -H should not be called for non-matching sender: %v", *calls)
	}
}
