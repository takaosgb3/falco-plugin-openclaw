// Falco Plugin: openclaw
// Monitors OpenClaw AI assistant logs for security threats.
// Watches 3 log files simultaneously (JSONL + plaintext).

package main

import (
	"bufio"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/alecthomas/jsonschema"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/extractor"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
	"github.com/fsnotify/fsnotify"

	"github.com/takaos/falco-openclaw-plugin/pkg/parser"
)

// --- Debug Log System ---
// Controlled by environment variable: FALCO_OPENCLAW_DEBUG=true
var debugEnabled = false

func debugLog(format string, args ...interface{}) {
	if debugEnabled {
		log.Printf("[openclaw-debug] "+format, args...)
	}
}

// --- Configuration ---
type OpenclawConfig struct {
	LogPaths        []string `json:"log_paths"`
	EventBufferSize int      `json:"event_buffer_size"`
}

// --- Plugin Event ---
// C-001: This struct is separate from LogEntry (parser output).
type OpenclawEvent struct {
	Type        string            `json:"type"`
	Tool        string            `json:"tool"`
	Args        string            `json:"args"`
	SessionID   string            `json:"session_id"`
	Timestamp   time.Time         `json:"timestamp"`
	SourceFile  string            `json:"source_file"`
	UserMessage string            `json:"user_message"`
	Model       string            `json:"model"`
	ConfigPath  string            `json:"config_path"`
	Suspicious  string            `json:"suspicious"`
	LogPath     string            `json:"log_path"`
	Raw         string            `json:"raw"`
	Headers     map[string]string `json:"headers"` // P004: Must be initialized with make()
}

// --- Plugin Struct ---
type OpenclawPlugin struct {
	plugins.BasePlugin
	config OpenclawConfig
	parser *parser.Parser
}

// --- Instance Struct ---
type OpenclawInstance struct {
	source.BaseInstance
	eventCh       chan *OpenclawEvent
	watcher       *fsnotify.Watcher
	files         map[string]*TailFile
	droppedEvents uint64
}

// TailFile: File tail-following struct
type TailFile struct {
	file   *os.File
	path   string
	reader *bufio.Reader
}

// --- Plugin Factory Registration ---
func init() {
	plugins.SetFactory(func() plugins.Plugin {
		p := &OpenclawPlugin{}
		source.Register(p)
		extractor.Register(p)
		return p
	})
}

// --- 1. Info() - Plugin Metadata ---
func (p *OpenclawPlugin) Info() *plugins.Info {
	return &plugins.Info{
		ID:          999,
		Name:        "openclaw",
		Description: "OpenClaw AI assistant log monitoring plugin for Falco",
		Contact:     "github.com/takaos/falco-openclaw-plugin",
		Version:     "0.1.0",
		EventSource: "openclaw",
	}
}

// --- 2. InitSchema() - Configuration Schema ---
func (p *OpenclawPlugin) InitSchema() *sdk.SchemaInfo {
	schema, err := jsonschema.Reflect(&OpenclawConfig{}).MarshalJSON()
	if err == nil {
		return &sdk.SchemaInfo{Schema: string(schema)}
	}
	return nil
}

// --- 3. Init() - Plugin Initialization ---
func (p *OpenclawPlugin) Init(config string) error {
	// Debug mode initialization
	if os.Getenv("FALCO_OPENCLAW_DEBUG") == "true" {
		debugEnabled = true
		debugLog("Debug mode enabled")
	}

	// Parse JSON configuration
	if config != "" {
		if err := json.Unmarshal([]byte(config), &p.config); err != nil {
			return fmt.Errorf("failed to parse config: %w", err)
		}
	}

	// Buffer size validation (1-100000)
	if p.config.EventBufferSize < 1 || p.config.EventBufferSize > 100000 {
		p.config.EventBufferSize = 1000 // Default
	}

	// Default log paths
	if len(p.config.LogPaths) == 0 {
		home, _ := os.UserHomeDir()
		p.config.LogPaths = []string{
			filepath.Join(home, ".openclaw/logs/agent.jsonl"),
			filepath.Join(home, ".openclaw/logs/tools.jsonl"),
			filepath.Join(home, ".openclaw/logs/system.log"),
		}
	}

	// Initialize parser
	p.parser = parser.New(parser.Config{
		LogFormat:        "json",
		SecurityPatterns: true,
	})

	debugLog("Initialized with %d log paths, buffer size %d",
		len(p.config.LogPaths), p.config.EventBufferSize)

	return nil
}

// --- 4. Open() - Instance Creation & File Watch Start ---
func (p *OpenclawPlugin) Open(params string) (source.Instance, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create watcher: %w", err)
	}

	instance := &OpenclawInstance{
		eventCh: make(chan *OpenclawEvent, p.config.EventBufferSize),
		watcher: watcher,
		files:   make(map[string]*TailFile),
	}

	// Open and watch each log file
	for _, logPath := range p.config.LogPaths {
		// Expand ~ to home directory
		if strings.HasPrefix(logPath, "~/") {
			home, _ := os.UserHomeDir()
			logPath = filepath.Join(home, logPath[2:])
		}

		// Ensure parent directory exists
		dir := filepath.Dir(logPath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			debugLog("Warning: failed to create directory %s: %v", dir, err)
		}

		// Open or create the log file
		f, err := os.OpenFile(logPath, os.O_RDONLY|os.O_CREATE, 0644)
		if err != nil {
			debugLog("Warning: failed to open %s: %v", logPath, err)
			continue
		}

		// Seek to end to read only new entries (P014)
		if _, err := f.Seek(0, 2); err != nil { // io.SeekEnd = 2
			debugLog("Warning: failed to seek %s: %v", logPath, err)
		}

		reader := bufio.NewReader(f)
		instance.files[logPath] = &TailFile{
			file:   f,
			path:   logPath,
			reader: reader,
		}

		// Watch the directory for file changes
		if err := watcher.Add(dir); err != nil {
			debugLog("Warning: failed to watch %s: %v", dir, err)
		}

		debugLog("Watching: %s", logPath)
	}

	// Start background file reader
	go instance.readLoop(p.parser)

	return instance, nil
}

// readLoop: Background goroutine for reading new log lines
func (inst *OpenclawInstance) readLoop(p *parser.Parser) {
	for {
		select {
		case event, ok := <-inst.watcher.Events:
			if !ok {
				return
			}
			if event.Has(fsnotify.Write) {
				inst.readNewLines(event.Name, p)
			}
		case err, ok := <-inst.watcher.Errors:
			if !ok {
				return
			}
			debugLog("Watcher error: %v", err)
		}
	}
}

// readNewLines: Read and parse new lines from the log file
func (inst *OpenclawInstance) readNewLines(path string, p *parser.Parser) {
	tf, ok := inst.files[path]
	if !ok {
		return
	}

	for {
		line, err := tf.reader.ReadString('\n')
		if err != nil {
			break
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		event := parseLine(line, path, p)
		if event == nil {
			continue
		}

		// Non-blocking channel send (channel overflow handling)
		select {
		case inst.eventCh <- event:
			// Successfully sent
		default:
			// Channel full - drop event and track
			dropped := atomic.AddUint64(&inst.droppedEvents, 1)
			if dropped%100 == 0 {
				log.Printf("[openclaw] WARNING: %d events dropped (channel full)", dropped)
			}
		}
	}
}

// parseLine: Parse a log line into an OpenclawEvent
// C-001: LogEntry (parser output) -> OpenclawEvent (plugin event) mapping
func parseLine(line, path string, p *parser.Parser) *OpenclawEvent {
	entry, err := p.Parse(line)
	if err != nil {
		debugLog("Parse error for line: %v", err)
		return nil
	}

	event := &OpenclawEvent{
		Type:        entry.Type,
		Tool:        entry.Tool,
		Args:        entry.Args,
		SessionID:   entry.SessionID,
		Timestamp:   entry.Timestamp,
		SourceFile:  filepath.Base(path),
		UserMessage: entry.UserMessage,
		Model:       entry.Model,
		ConfigPath:  entry.ConfigPath,
		Suspicious:  entry.SecurityThreat.String(),
		LogPath:     path,
		Raw:         line,
		Headers:     make(map[string]string), // P004: Must initialize
	}

	// Copy headers if present
	if entry.Headers != nil {
		for k, v := range entry.Headers {
			event.Headers[k] = v
		}
	}

	return event
}

// --- 5. Fields() - Extractable Field Definitions ---
// P010: All fields defined here must be handled in Extract()
func (p *OpenclawPlugin) Fields() []sdk.FieldEntry {
	return []sdk.FieldEntry{
		{Type: "string", Name: "openclaw.type", Desc: "Event type (tool_call, message, config_change, system)"},
		{Type: "string", Name: "openclaw.tool", Desc: "Tool name (bash, read, write, etc.)"},
		{Type: "string", Name: "openclaw.args", Desc: "Tool arguments"},
		{Type: "string", Name: "openclaw.session_id", Desc: "Session identifier"},
		{Type: "string", Name: "openclaw.timestamp", Desc: "Event timestamp"},
		{Type: "string", Name: "openclaw.source_file", Desc: "Source log file name"},
		{Type: "string", Name: "openclaw.user_message", Desc: "User message content"},
		{Type: "string", Name: "openclaw.model", Desc: "AI model name"},
		{Type: "string", Name: "openclaw.config_path", Desc: "Configuration file path"},
		{Type: "string", Name: "openclaw.suspicious", Desc: "Security threat type detected"},
		{Type: "string", Name: "openclaw.log_path", Desc: "Log file path"},
		{Type: "string", Name: "openclaw.raw", Desc: "Raw log line"},
		{Type: "string", Name: "openclaw.headers", Desc: "Extra metadata (map field)",
			IsList: false, Arg: sdk.FieldEntryArg{IsRequired: true, IsKey: true}},
	}
}

// --- 6. Extract() - Field Value Extraction ---
// P010: Must handle all fields defined in Fields()
func (p *OpenclawPlugin) Extract(req sdk.ExtractRequest, evt sdk.EventReader) error {
	// GOB decode the event
	var event OpenclawEvent
	decoder := gob.NewDecoder(evt.Reader())
	if err := decoder.Decode(&event); err != nil {
		return fmt.Errorf("failed to decode event: %w", err)
	}

	// Field extraction via switch
	switch req.Field() {
	case "openclaw.type":
		req.SetValue(event.Type)
	case "openclaw.tool":
		req.SetValue(event.Tool)
	case "openclaw.args":
		req.SetValue(event.Args)
	case "openclaw.session_id":
		req.SetValue(event.SessionID)
	case "openclaw.timestamp":
		req.SetValue(event.Timestamp.Format(time.RFC3339))
	case "openclaw.source_file":
		req.SetValue(event.SourceFile)
	case "openclaw.user_message":
		req.SetValue(event.UserMessage)
	case "openclaw.model":
		req.SetValue(event.Model)
	case "openclaw.config_path":
		req.SetValue(event.ConfigPath)
	case "openclaw.suspicious":
		req.SetValue(event.Suspicious)
	case "openclaw.log_path":
		req.SetValue(event.LogPath)
	case "openclaw.raw":
		req.SetValue(event.Raw)
	case "openclaw.headers":
		// P012: Header keys must be lowercase
		headerName := strings.ToLower(req.ArgKey())
		if event.Headers != nil {
			if value, ok := event.Headers[headerName]; ok {
				req.SetValue(value)
			}
		}
	default:
		return fmt.Errorf("unknown field: %s", req.Field())
	}

	return nil
}

// --- 7. NextBatch() - Event Batch Delivery ---
func (inst *OpenclawInstance) NextBatch(pState sdk.PluginState, evts sdk.EventWriters) (int, error) {
	n := 0
	timeout := time.After(30 * time.Millisecond)

	for n < evts.Len() {
		select {
		case event, ok := <-inst.eventCh:
			if !ok {
				if n == 0 {
					return 0, sdk.ErrEOF
				}
				return n, nil
			}

			// GOB encode the event
			writer := evts.Get(n)
			encoder := gob.NewEncoder(writer.Writer())
			if err := encoder.Encode(event); err != nil {
				debugLog("GOB encode error: %v (event: %+v)", err, event)
				continue
			}
			writer.SetTimestamp(uint64(event.Timestamp.UnixNano()))
			n++

		case <-timeout:
			if n == 0 {
				return 0, sdk.ErrTimeout
			}
			return n, nil
		}
	}

	return n, nil
}

// --- Close() - Resource Cleanup ---
func (inst *OpenclawInstance) Close() {
	// 1. Close fsnotify Watcher
	if inst.watcher != nil {
		inst.watcher.Close()
	}

	// 2. Close all open file handles
	for _, f := range inst.files {
		if f.file != nil {
			f.file.Close()
		}
	}

	// 3. Close event channel
	close(inst.eventCh)

	debugLog("Instance closed. Dropped events: %d",
		atomic.LoadUint64(&inst.droppedEvents))
}

// main() is required but empty for -buildmode=c-shared
func main() {}
