// Package model holds the wire types shared with the cloud (SPEC §7). Field names are an API contract.
package model

import "time"

type Event struct {
	ID       string            `json:"id"`
	Ts       time.Time         `json:"ts"`
	Module   string            `json:"module"`
	Type     string            `json:"type"`
	Severity string            `json:"severity"`
	SourceIP string            `json:"sourceIp,omitempty"`
	Attrs    map[string]string `json:"attrs,omitempty"`
}

type EventBatch struct {
	AgentVersion string    `json:"agentVersion"`
	ServerID     string    `json:"serverId"`
	SentAt       time.Time `json:"sentAt"`
	Events       []Event   `json:"events"`
}

type EnrollRequest struct {
	EnrollmentKey string `json:"enrollmentKey"`
	Hostname      string `json:"hostname"`
	OS            string `json:"os"`
	CPUCount      int    `json:"cpuCount"`
	RAMMb         int    `json:"ramMb"`
	PublicIP      string `json:"publicIp,omitempty"`
	AgentVersion  string `json:"agentVersion"`
}

type EnrollResponse struct {
	ServerID         string `json:"serverId"`
	AgentToken       string `json:"agentToken"`
	CommandPublicKey string `json:"commandPublicKey"`
}

type Facts struct {
	Detected []string `json:"detected"`
	Guards   []string `json:"guards"`
}

type Command struct {
	ID        string            `json:"id"`
	Kind      string            `json:"kind"`
	Params    map[string]string `json:"params"`
	ExpiresAt time.Time         `json:"expiresAt"`
	Signature string            `json:"signature"`
}

type CommandAck struct {
	Ok     bool   `json:"ok"`
	Output string `json:"output,omitempty"`
}

// Event type names (SPEC §7). Never rename.
const (
	TypeHeartbeat        = "server.heartbeat"
	TypeSSHAuthFailed    = "server.ssh_auth_failed"
	TypeSSHAuthSuccess   = "server.ssh_auth_succeeded"
	TypeMailAuthFailed   = "mail.auth_failed"
	TypeMailAuthSuccess  = "mail.auth_succeeded"
	TypeMailMessageQueue = "mail.message_queued"
	TypeMailQueueSize    = "mail.queue_size"
)
