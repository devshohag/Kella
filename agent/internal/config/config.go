// Package config loads /etc/shield/agent.yaml.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	// CloudURL is the Shield API base URL, e.g. https://api.shield.example.
	CloudURL string `yaml:"cloudUrl"`
	// EnrollmentKey is used once on first start; the agent then stores a token in TokenPath.
	EnrollmentKey string `yaml:"enrollmentKey"`
	TokenPath     string `yaml:"tokenPath"`
	StatePath     string `yaml:"statePath"`

	HeartbeatInterval time.Duration `yaml:"heartbeatInterval"`
	FlushInterval     time.Duration `yaml:"flushInterval"`

	Logs struct {
		Auth string `yaml:"auth"`
		Mail string `yaml:"mail"`
	} `yaml:"logs"`

	Actions struct {
		// DryRun logs commands instead of executing them. Default true until you trust the setup.
		DryRun bool `yaml:"dryRun"`
		// RequireSigned rejects commands without a valid Ed25519 signature (SPEC §8.5). Must be true in production.
		RequireSigned bool `yaml:"requireSigned"`
		// CommandPublicKey is the base64 Ed25519 public key of the cloud.
		CommandPublicKey string   `yaml:"commandPublicKey"`
		Allowlist        []string `yaml:"allowlist"`
		MaxBlockedIPs    int      `yaml:"maxBlockedIps"`
	} `yaml:"actions"`
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	c := Default()
	if err := yaml.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if c.CloudURL == "" {
		return nil, fmt.Errorf("cloudUrl is required")
	}
	return c, nil
}

func Default() *Config {
	c := &Config{
		TokenPath:         "/etc/shield/token",
		StatePath:         "/var/lib/shield",
		HeartbeatInterval: 60 * time.Second,
		FlushInterval:     5 * time.Second,
	}
	c.Logs.Auth = "/var/log/auth.log"
	c.Logs.Mail = "/var/log/mail.log"
	c.Actions.DryRun = true
	c.Actions.RequireSigned = true
	c.Actions.MaxBlockedIPs = 5000
	return c
}
