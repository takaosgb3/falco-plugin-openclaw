package parser

import (
	"strings"
)

const maxInputSize = 10 * 1024 // 10KB input size limit (NFR-021)

// SimpleSecurityDetector provides string-matching based security detection
// for OpenClaw AI assistant activity logs.
// No regex is used (ReDoS safe).
// Uses strings.Contains / strings.ToLower for pattern matching.
type SimpleSecurityDetector struct {
	maxInputLength int
}

// NewSimpleSecurityDetector creates a new SimpleSecurityDetector.
func NewSimpleSecurityDetector() *SimpleSecurityDetector {
	return &SimpleSecurityDetector{
		maxInputLength: maxInputSize,
	}
}

// DetectThreat checks for security threats across all 7 categories.
// Returns the threat type string and whether a threat was found.
func (d *SimpleSecurityDetector) DetectThreat(eventType, tool, args, model, configPath, userMessage string) (string, bool) {
	if len(args) > d.maxInputLength {
		args = args[:d.maxInputLength]
	}

	// Check in priority order
	if d.DetectDangerousCommand(tool, args) {
		return "dangerous_command", true
	}
	if d.DetectDataExfiltration(tool, args) {
		return "data_exfiltration", true
	}
	if d.DetectWorkspaceEscape(tool, args) {
		return "workspace_escape", true
	}
	if d.DetectShellInjection(tool, args) {
		return "shell_injection", true
	}
	if d.DetectSuspiciousConfig(eventType, args, configPath) {
		return "suspicious_config", true
	}
	if d.DetectUnauthorizedModelChange(eventType, model) {
		return "unauthorized_model", true
	}
	if d.DetectAgentRunaway(args, userMessage) {
		return "agent_runaway", true
	}

	return "", false
}

// DetectDangerousCommand checks for dangerous shell commands.
func (d *SimpleSecurityDetector) DetectDangerousCommand(tool, args string) bool {
	if tool == "" {
		return false
	}
	lowerTool := strings.ToLower(tool)
	if lowerTool != "bash" && lowerTool != "shell" && lowerTool != "exec" && lowerTool != "terminal" {
		return false
	}

	lower := strings.ToLower(args)

	// Destructive file operations
	destructivePatterns := []string{
		"rm -rf /",
		"rm -rf /*",
		"rm -rf ~",
		"rm -rf .",
		"chmod 777 /",
		"chmod -r 777",
		"chown root",
		"mkfs",
		"dd if=",
		"> /dev/sd",
		"> /dev/nvme",
		"shutdown",
		"reboot",
		"halt",
		"init 0",
		"init 6",
		"kill -9 1",
		"killall",
		"pkill -9",
		":(){:|:&};:",    // Fork bomb
		":(){ :|:& };:", // Fork bomb variant
	}

	for _, pattern := range destructivePatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}

	// Dangerous system modifications
	sysModPatterns := []string{
		"iptables -f",
		"iptables --flush",
		"systemctl disable",
		"launchctl unload",
		"defaults delete",
		"crontab -r",
		"visudo",
		"useradd",
		"userdel",
		"groupdel",
	}

	for _, pattern := range sysModPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}

	// Check for passwd command (not /etc/passwd path)
	if strings.HasPrefix(lower, "passwd ") || lower == "passwd" {
		return true
	}

	return false
}

// DetectDataExfiltration checks for data exfiltration attempts.
func (d *SimpleSecurityDetector) DetectDataExfiltration(tool, args string) bool {
	lower := strings.ToLower(args)

	// Network transfer tools combined with sensitive data indicators
	transferTools := []string{"curl", "wget", "nc ", "ncat", "scp ", "rsync", "ftp "}
	sensitiveData := []string{
		"/etc/passwd", "/etc/shadow", "/etc/hosts",
		".ssh/id_", ".ssh/authorized_keys",
		".env", "credentials", "secret", "token",
		".aws/credentials", ".kube/config",
		"keychain", "login.keychain",
		".gnupg/", ".npmrc", ".pypirc",
		"openclaw.json",
	}

	hasTransfer := false
	for _, t := range transferTools {
		if strings.Contains(lower, t) {
			hasTransfer = true
			break
		}
	}

	if hasTransfer {
		for _, s := range sensitiveData {
			if strings.Contains(lower, s) {
				return true
			}
		}
	}

	// Base64 encoding of sensitive files
	if strings.Contains(lower, "base64") {
		for _, s := range sensitiveData {
			if strings.Contains(lower, s) {
				return true
			}
		}
	}

	// Direct piping sensitive data to network
	if strings.Contains(lower, "| curl") || strings.Contains(lower, "| nc ") ||
		strings.Contains(lower, "| wget") {
		for _, s := range sensitiveData {
			if strings.Contains(lower, s) {
				return true
			}
		}
	}

	return false
}

// DetectAgentRunaway checks for agent runaway indicators.
func (d *SimpleSecurityDetector) DetectAgentRunaway(args, userMessage string) bool {
	lower := strings.ToLower(args)

	runawayPatterns := []string{
		"infinite loop",
		"while true",
		"while :;",
		"for (;;)",
		"runaway",
		"max retries exceeded",
		"recursion depth",
		"stack overflow",
		"too many requests",
		"rate limit",
	}

	for _, pattern := range runawayPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}

	return false
}

// DetectWorkspaceEscape checks for attempts to access files outside the workspace.
func (d *SimpleSecurityDetector) DetectWorkspaceEscape(tool, args string) bool {
	if tool == "" {
		return false
	}
	lower := strings.ToLower(args)

	// Critical system directories
	escapePaths := []string{
		"/etc/passwd",
		"/etc/shadow",
		"/etc/sudoers",
		"/root/",
		"/var/log/",
		"/proc/",
		"/sys/",
		"/dev/",
		"/boot/",
		"/sbin/",
		"/usr/sbin/",
	}

	for _, path := range escapePaths {
		if strings.Contains(lower, path) {
			return true
		}
	}

	// Path traversal attempts
	return strings.Contains(lower, "../../")
}

// DetectSuspiciousConfig checks for suspicious configuration changes.
func (d *SimpleSecurityDetector) DetectSuspiciousConfig(eventType, args, configPath string) bool {
	if strings.ToLower(eventType) != "config_change" {
		return false
	}

	lower := strings.ToLower(args)

	suspiciousPatterns := []string{
		"dm_policy",
		"allow_all",
		"disable_auth",
		"skip_verification",
		"no_verify",
		"trust_all",
		"insecure",
		"disable_security",
		"admin_override",
		"bypass",
	}

	for _, pattern := range suspiciousPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}

	// Modifying security-relevant config files
	if configPath != "" {
		lowerPath := strings.ToLower(configPath)
		sensitiveConfigs := []string{
			"sshd_config", "sudoers", "pam.d",
			".bashrc", ".zshrc", ".profile",
			"launchd", "crontab",
		}
		for _, cfg := range sensitiveConfigs {
			if strings.Contains(lowerPath, cfg) {
				return true
			}
		}
	}

	return false
}

// DetectUnauthorizedModelChange checks for unauthorized AI model changes.
func (d *SimpleSecurityDetector) DetectUnauthorizedModelChange(eventType, model string) bool {
	if eventType != "config_change" || model == "" {
		return false
	}

	// Any model change in a config_change event is suspicious
	return true
}

// DetectShellInjection checks for shell injection in non-bash tool arguments.
func (d *SimpleSecurityDetector) DetectShellInjection(tool, args string) bool {
	if tool == "" {
		return false
	}
	lowerTool := strings.ToLower(tool)
	// Shell injection is only relevant for non-shell tools
	if lowerTool == "bash" || lowerTool == "shell" || lowerTool == "exec" || lowerTool == "terminal" {
		return false
	}

	lower := strings.ToLower(args)

	// Shell metacharacters in non-bash tools
	shellPatterns := []string{
		"$(", "`",
		"; ", "&&", "||",
		"| ", "> ", ">> ",
		"%0a", "%0d",
		"\n", "\r",
	}

	for _, pattern := range shellPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}

	return false
}
