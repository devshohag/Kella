package actuators

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
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

func TestHoldAndReleaseSender(t *testing.T) {
	r, calls := newTestRunner(t, false, "")
	holdCmd := model.Command{
		ID:        "c2",
		Kind:      "hold_sender",
		Params:    map[string]string{"sender": "spammer@badtenant.com"},
		ExpiresAt: time.Now().Add(time.Minute),
	}
	if _, err := r.Execute(context.Background(), holdCmd); err != nil {
		t.Fatalf("holdSender error: %v", err)
	}
	if len(*calls) != 1 || !strings.Contains((*calls)[0], "spammer@badtenant.com HOLD") {
		t.Fatalf("unexpected call for hold: %v", *calls)
	}

	relCmd := model.Command{
		ID:        "c3",
		Kind:      "release_sender",
		Params:    map[string]string{"sender": "spammer@badtenant.com"},
		ExpiresAt: time.Now().Add(time.Minute),
	}
	if _, err := r.Execute(context.Background(), relCmd); err != nil {
		t.Fatalf("releaseSender error: %v", err)
	}
	if len(*calls) != 2 || !strings.Contains((*calls)[1], "postsuper -H") {
		t.Fatalf("unexpected call for release: %v", *calls)
	}
}

