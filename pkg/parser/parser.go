// Package parser provides log parsing functionality for the openclaw Falco plugin.
// Supports JSON (JSONL) and plaintext log formats from OpenClaw AI assistant.
package parser

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// SecurityThreatType represents the type of security threat detected.
type SecurityThreatType int

const (
	NoThreat SecurityThreatType = iota
	DangerousCommand
	DataExfiltration
	AgentRunaway
	WorkspaceEscape
	SuspiciousConfig
	UnauthorizedModelChange
	ShellInjection
)

func (t SecurityThreatType) String() string {
	switch t {
	case DangerousCommand:
		return "dangerous_command"
	case DataExfiltration:
		return "data_exfiltration"
	case AgentRunaway:
		return "agent_runaway"
	case WorkspaceEscape:
		return "workspace_escape"
	case SuspiciousConfig:
		return "suspicious_config"
	case UnauthorizedModelChange:
		return "unauthorized_model"
	case ShellInjection:
		return "shell_injection"
	default:
		return "none"
	}
}

// LogEntry represents a parsed log line from OpenClaw.
type LogEntry struct {
	Type           string
	Tool           string
	Args           string
	SessionID      string
	Timestamp      time.Time
	SourceFile     string
	UserMessage    string
	Model          string
	ConfigPath     string
	SecurityThreat SecurityThreatType
	Headers        map[string]string
	Raw            string
}

// jsonLogEntry represents a JSON log line structure for unmarshaling.
type jsonLogEntry struct {
	Type        string            `json:"type"`
	Tool        string            `json:"tool"`
	Args        string            `json:"args"`
	SessionID   string            `json:"session_id"`
	Timestamp   string            `json:"timestamp"`
	SourceFile  string            `json:"source_file"`
	UserMessage string            `json:"user_message"`
	Model       string            `json:"model"`
	ConfigPath  string            `json:"config_path"`
	Headers     map[string]string `json:"headers"`
}

// Parser is the main log parser.
type Parser struct {
	config           Config
	securityDetector *SimpleSecurityDetector
}

// Regex pattern for plaintext log lines:
// 2026-02-27T10:00:00Z [LEVEL] session=abc123 key=value message...
var plaintextPattern = regexp.MustCompile(
	`^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[Z\d:+-]*)\s+\[(\w+)\]\s+(.*)$`)

// New creates a new Parser with the given configuration.
func New(cfg Config) *Parser {
	p := &Parser{
		config: cfg,
	}

	// Enable security detection if configured
	if cfg.SecurityPatterns {
		p.securityDetector = NewSimpleSecurityDetector()
	}

	return p
}

// Parse parses a single log line and returns a LogEntry.
func (p *Parser) Parse(line string) (*LogEntry, error) {
	if line == "" {
		return nil, fmt.Errorf("empty line")
	}

	var entry *LogEntry
	var err error

	// Auto-detect format: try JSON first, fall back to plaintext
	if strings.HasPrefix(strings.TrimSpace(line), "{") {
		entry, err = p.parseJSON(line)
	} else {
		entry, err = p.parsePlaintext(line)
	}

	if err != nil {
		return nil, err
	}

	entry.Raw = line

	// Initialize Headers map (P004: prevent nil map panic)
	if entry.Headers == nil {
		entry.Headers = make(map[string]string)
	}

	// Detect security patterns
	if p.securityDetector != nil {
		p.detectSecurityPatterns(entry)
	}

	return entry, nil
}

// parseJSON parses a JSON format log line.
func (p *Parser) parseJSON(line string) (*LogEntry, error) {
	var jEntry jsonLogEntry
	if err := json.Unmarshal([]byte(line), &jEntry); err != nil {
		return nil, fmt.Errorf("JSON parse error: %w", err)
	}

	entry := &LogEntry{
		Type:        jEntry.Type,
		Tool:        jEntry.Tool,
		Args:        jEntry.Args,
		SessionID:   jEntry.SessionID,
		SourceFile:  jEntry.SourceFile,
		UserMessage: jEntry.UserMessage,
		Model:       jEntry.Model,
		ConfigPath:  jEntry.ConfigPath,
		Headers:     jEntry.Headers,
	}

	// Parse timestamp
	if jEntry.Timestamp != "" {
		t, err := time.Parse(time.RFC3339, jEntry.Timestamp)
		if err != nil {
			// Try alternative formats
			t, err = time.Parse("2006-01-02T15:04:05Z", jEntry.Timestamp)
			if err != nil {
				t, err = time.Parse("2006-01-02 15:04:05", jEntry.Timestamp)
				if err != nil {
					entry.Timestamp = time.Now()
				} else {
					entry.Timestamp = t
				}
			} else {
				entry.Timestamp = t
			}
		} else {
			entry.Timestamp = t
		}
	} else {
		entry.Timestamp = time.Now()
	}

	return entry, nil
}

// parsePlaintext parses a plaintext format log line.
// Format: TIMESTAMP [LEVEL] session=ID key=value message...
func (p *Parser) parsePlaintext(line string) (*LogEntry, error) {
	matches := plaintextPattern.FindStringSubmatch(line)
	if matches == nil {
		// Fallback: treat entire line as a system message
		return &LogEntry{
			Type:      "system",
			Args:      line,
			Timestamp: time.Now(),
		}, nil
	}

	entry := &LogEntry{
		Type: "system",
	}

	// Parse timestamp
	t, err := time.Parse(time.RFC3339, matches[1])
	if err != nil {
		t, err = time.Parse("2006-01-02T15:04:05Z", matches[1])
		if err != nil {
			t, err = time.Parse("2006-01-02 15:04:05", matches[1])
			if err != nil {
				t = time.Now()
			}
		}
	}
	entry.Timestamp = t

	// Parse key=value pairs from the rest of the line
	rest := matches[3]
	entry.Args = rest

	// Extract known key=value patterns
	if idx := strings.Index(rest, "session="); idx >= 0 {
		val := extractValue(rest[idx+8:])
		entry.SessionID = val
	}
	if idx := strings.Index(rest, "tool="); idx >= 0 {
		val := extractValue(rest[idx+5:])
		entry.Tool = val
	}
	if idx := strings.Index(rest, "model="); idx >= 0 {
		val := extractValue(rest[idx+6:])
		entry.Model = val
	}

	// Detect event type from log content
	lower := strings.ToLower(rest)
	switch {
	case strings.Contains(lower, "tool execution") || strings.Contains(lower, "tool_call"):
		entry.Type = "tool_call"
	case strings.Contains(lower, "config"):
		entry.Type = "config_change"
	case strings.Contains(lower, "message") || strings.Contains(lower, "user"):
		entry.Type = "message"
	}

	return entry, nil
}

// extractValue extracts the next whitespace-delimited value from a string.
func extractValue(s string) string {
	s = strings.TrimSpace(s)
	idx := strings.IndexAny(s, " \t\n")
	if idx >= 0 {
		return s[:idx]
	}
	return s
}

// detectSecurityPatterns checks for security threats in the log entry.
func (p *Parser) detectSecurityPatterns(entry *LogEntry) {
	if p.securityDetector == nil {
		return
	}

	threatType, found := p.securityDetector.DetectThreat(
		entry.Type, entry.Tool, entry.Args,
		entry.Model, entry.ConfigPath, entry.UserMessage,
	)

	if found {
		switch threatType {
		case "dangerous_command":
			entry.SecurityThreat = DangerousCommand
		case "data_exfiltration":
			entry.SecurityThreat = DataExfiltration
		case "agent_runaway":
			entry.SecurityThreat = AgentRunaway
		case "workspace_escape":
			entry.SecurityThreat = WorkspaceEscape
		case "suspicious_config":
			entry.SecurityThreat = SuspiciousConfig
		case "unauthorized_model":
			entry.SecurityThreat = UnauthorizedModelChange
		case "shell_injection":
			entry.SecurityThreat = ShellInjection
		}
	}
}
