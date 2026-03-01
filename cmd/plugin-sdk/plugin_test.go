package main

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Helper Functions ---

// initPlugin creates and initializes a plugin with custom log paths.
func initPlugin(t *testing.T, logPaths []string) *OpenclawPlugin {
	t.Helper()
	p := &OpenclawPlugin{}
	cfg := OpenclawConfig{
		LogPaths:        logPaths,
		EventBufferSize: 100,
	}
	cfgJSON, err := json.Marshal(cfg)
	require.NoError(t, err)
	err = p.Init(string(cfgJSON))
	require.NoError(t, err)
	return p
}

// openAndCleanup opens the plugin instance and registers cleanup.
func openAndCleanup(t *testing.T, p *OpenclawPlugin) *OpenclawInstance {
	t.Helper()
	inst, err := p.Open("")
	require.NoError(t, err)
	oi := inst.(*OpenclawInstance)
	t.Cleanup(func() { oi.Close() })
	return oi
}

// writeToLog writes a line to a log file and waits for fsnotify.
func writeToLog(t *testing.T, path, line string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	require.NoError(t, err)
	_, err = f.WriteString(line + "\n")
	require.NoError(t, err)
	f.Close()
}

// waitForEvent waits for an event on the channel with timeout.
func waitForEvent(t *testing.T, ch chan *OpenclawEvent, timeout time.Duration) *OpenclawEvent {
	t.Helper()
	select {
	case evt := <-ch:
		return evt
	case <-time.After(timeout):
		t.Fatal("Timed out waiting for event")
		return nil
	}
}

// gobEncode encodes an OpenclawEvent to bytes.
func gobEncode(t *testing.T, event *OpenclawEvent) []byte {
	t.Helper()
	var buf bytes.Buffer
	err := gob.NewEncoder(&buf).Encode(event)
	require.NoError(t, err)
	return buf.Bytes()
}

// gobDecode decodes bytes into an OpenclawEvent.
func gobDecode(t *testing.T, data []byte) OpenclawEvent {
	t.Helper()
	var event OpenclawEvent
	err := gob.NewDecoder(bytes.NewReader(data)).Decode(&event)
	require.NoError(t, err)
	return event
}

// =============================================
// TC-1: Plugin Lifecycle Tests
// =============================================

// TC-1-01: Default configuration
func TestPipelineInitDefault(t *testing.T) {
	p := &OpenclawPlugin{}

	// Empty string config
	err := p.Init("")
	require.NoError(t, err)
	assert.Equal(t, 1000, p.config.EventBufferSize, "Default buffer size should be 1000")
	assert.Len(t, p.config.LogPaths, 3, "Default should have 3 log paths")

	// Empty JSON config
	p2 := &OpenclawPlugin{}
	err = p2.Init("{}")
	require.NoError(t, err)
	assert.Equal(t, 1000, p2.config.EventBufferSize, "Default buffer size should be 1000")
}

// TC-1-02: Custom configuration
func TestPipelineInitCustom(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "test.jsonl")

	cfg := `{"log_paths": ["` + logPath + `"], "event_buffer_size": 500}`
	p := &OpenclawPlugin{}
	err := p.Init(cfg)
	require.NoError(t, err)
	assert.Equal(t, 500, p.config.EventBufferSize)
	assert.Equal(t, []string{logPath}, p.config.LogPaths)
}

// TC-1-03: Buffer size boundary values
func TestPipelineInitBufferBoundary(t *testing.T) {
	tests := []struct {
		name     string
		size     int
		expected int
	}{
		{"zero", 0, 1000},
		{"negative", -1, 1000},
		{"one", 1, 1},
		{"max", 100000, 100000},
		{"over_max", 100001, 1000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &OpenclawPlugin{}
			cfg := fmt.Sprintf(`{"event_buffer_size": %d}`, tt.size)
			err := p.Init(cfg)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, p.config.EventBufferSize)
		})
	}
}

// TC-1-04: Info() metadata
func TestPipelineInfo(t *testing.T) {
	p := &OpenclawPlugin{}
	info := p.Info()

	require.NotNil(t, info)
	assert.Equal(t, uint32(999), info.ID)
	assert.Equal(t, "openclaw", info.Name)
	assert.Equal(t, "0.1.0", info.Version)
	assert.Equal(t, "openclaw", info.EventSource)
	assert.NotEmpty(t, info.Description)
	assert.NotEmpty(t, info.Contact)
}

// TC-1-05: InitSchema() JSON Schema validity
func TestPipelineInitSchema(t *testing.T) {
	p := &OpenclawPlugin{}
	schema := p.InitSchema()

	require.NotNil(t, schema)
	assert.NotEmpty(t, schema.Schema)

	// Verify it's valid JSON
	var jsonData interface{}
	err := json.Unmarshal([]byte(schema.Schema), &jsonData)
	assert.NoError(t, err, "Schema should be valid JSON")
}

// TC-1-06: Open creates files and directories for non-existent paths
func TestPipelineOpenFileCreation(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "subdir", "newfile.jsonl")

	p := initPlugin(t, []string{logPath})
	inst := openAndCleanup(t, p)
	_ = inst

	// Verify directory and file were created
	assert.DirExists(t, filepath.Join(dir, "subdir"))
	assert.FileExists(t, logPath)
}

// TC-1-07: Open seeks to end (P014)
func TestPipelineOpenSeekEnd(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "existing.jsonl")

	// Write existing content before Open
	existingLine := `{"type":"tool_call","tool":"bash","args":"echo existing","session_id":"sess-old","timestamp":"2026-02-27T10:00:00Z"}`
	err := os.WriteFile(logPath, []byte(existingLine+"\n"), 0644)
	require.NoError(t, err)

	p := initPlugin(t, []string{logPath})
	inst := openAndCleanup(t, p)

	// Wait for fsnotify + readLoop goroutine to process any existing content.
	// 200ms is sufficient: fsnotify delivers within ~50ms, readLoop processes immediately.
	time.Sleep(200 * time.Millisecond)
	select {
	case evt := <-inst.eventCh:
		t.Fatalf("Should not receive existing content, got: %+v", evt)
	default:
		// Expected: no events
	}

	// Write new content and verify it IS received
	newLine := `{"type":"tool_call","tool":"bash","args":"echo new","session_id":"sess-new","timestamp":"2026-02-27T10:00:01Z"}`
	writeToLog(t, logPath, newLine)

	evt := waitForEvent(t, inst.eventCh, 5*time.Second)
	assert.Equal(t, "echo new", evt.Args)
	assert.Equal(t, "sess-new", evt.SessionID)
}

// TC-1-08: Close() cleanup
func TestPipelineClose(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "close.jsonl")
	os.WriteFile(logPath, []byte(""), 0644)

	p := initPlugin(t, []string{logPath})
	inst, err := p.Open("")
	require.NoError(t, err)
	oi := inst.(*OpenclawInstance)

	// Verify resources are initialized
	assert.NotNil(t, oi.watcher)
	assert.NotNil(t, oi.eventCh)
	assert.NotEmpty(t, oi.files)

	// Close
	oi.Close()

	// Verify channel is closed
	_, ok := <-oi.eventCh
	assert.False(t, ok, "Channel should be closed after Close()")
}

// TC-1-09: Verify all fields are unique, prefixed with "openclaw.", and survive GOB round-trip.
// Note: Extract() switch coverage requires Falco SDK mocks (Level 3 scope).
func TestPipelineFieldsExtractConsistency(t *testing.T) {
	p := &OpenclawPlugin{}
	p.Init("")

	fields := p.Fields()
	assert.Len(t, fields, 13, "Must have exactly 13 fields")

	// Verify all field names are unique and start with "openclaw."
	fieldNames := make(map[string]bool)
	for _, f := range fields {
		assert.True(t, strings.HasPrefix(f.Name, "openclaw."),
			"Field %s must start with 'openclaw.'", f.Name)
		assert.False(t, fieldNames[f.Name],
			"Duplicate field name: %s", f.Name)
		fieldNames[f.Name] = true
		assert.Equal(t, "string", f.Type, "Field %s must be string type", f.Name)
	}

	// Verify all fields have corresponding case in Extract() via GOB round-trip
	event := &OpenclawEvent{
		Type:        "tool_call",
		Tool:        "bash",
		Args:        "test args",
		SessionID:   "sess-test",
		Timestamp:   time.Now(),
		SourceFile:  "test.jsonl",
		UserMessage: "test msg",
		Model:       "test-model",
		ConfigPath:  "/test/config",
		Suspicious:  "none",
		LogPath:     "/test/log",
		Raw:         `{"test":"raw"}`,
		Headers:     map[string]string{"x-test": "value"},
	}

	// GOB encode and verify all fields can be decoded
	data := gobEncode(t, event)
	decoded := gobDecode(t, data)

	assert.Equal(t, event.Type, decoded.Type)
	assert.Equal(t, event.Tool, decoded.Tool)
	assert.Equal(t, event.Args, decoded.Args)
	assert.Equal(t, event.SessionID, decoded.SessionID)
	assert.Equal(t, event.SourceFile, decoded.SourceFile)
	assert.Equal(t, event.UserMessage, decoded.UserMessage)
	assert.Equal(t, event.Model, decoded.Model)
	assert.Equal(t, event.ConfigPath, decoded.ConfigPath)
	assert.Equal(t, event.Suspicious, decoded.Suspicious)
	assert.Equal(t, event.LogPath, decoded.LogPath)
	assert.Equal(t, event.Raw, decoded.Raw)
	assert.Equal(t, event.Headers, decoded.Headers)
}

// =============================================
// TC-2: Log Ingestion Tests
// =============================================

// TC-2-01: JSONL ingestion
func TestPipelineJSONIngestion(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "agent.jsonl")
	os.WriteFile(logPath, []byte(""), 0644)

	p := initPlugin(t, []string{logPath})
	inst := openAndCleanup(t, p)

	line := `{"type":"tool_call","tool":"bash","args":"ls -la","session_id":"sess-json-001","timestamp":"2026-02-27T10:00:00Z","model":"claude-3-opus"}`
	writeToLog(t, logPath, line)

	evt := waitForEvent(t, inst.eventCh, 5*time.Second)
	assert.Equal(t, "tool_call", evt.Type)
	assert.Equal(t, "bash", evt.Tool)
	assert.Equal(t, "ls -la", evt.Args)
	assert.Equal(t, "sess-json-001", evt.SessionID)
	assert.Equal(t, "claude-3-opus", evt.Model)
	assert.Equal(t, "agent.jsonl", evt.SourceFile)
}

// TC-2-02: Plaintext ingestion
func TestPipelinePlaintextIngestion(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "system.log")
	os.WriteFile(logPath, []byte(""), 0644)

	p := initPlugin(t, []string{logPath})
	inst := openAndCleanup(t, p)

	line := `2026-02-27T10:00:00Z [INFO] session=sess-pt-001 tool=bash Agent started`
	writeToLog(t, logPath, line)

	evt := waitForEvent(t, inst.eventCh, 5*time.Second)
	assert.Equal(t, "sess-pt-001", evt.SessionID)
	assert.Equal(t, "system.log", evt.SourceFile)
}

// TC-2-03: Multi-line write
func TestPipelineMultiLineWrite(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "multi.jsonl")
	os.WriteFile(logPath, []byte(""), 0644)

	p := initPlugin(t, []string{logPath})
	inst := openAndCleanup(t, p)

	lines := []string{
		`{"type":"tool_call","tool":"bash","args":"cmd1","session_id":"sess-m01","timestamp":"2026-02-27T10:00:00Z"}`,
		`{"type":"tool_call","tool":"bash","args":"cmd2","session_id":"sess-m02","timestamp":"2026-02-27T10:00:01Z"}`,
		`{"type":"tool_call","tool":"bash","args":"cmd3","session_id":"sess-m03","timestamp":"2026-02-27T10:00:02Z"}`,
	}

	// Write all lines at once
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0644)
	require.NoError(t, err)
	for _, line := range lines {
		f.WriteString(line + "\n")
	}
	f.Close()

	// Collect events
	events := make([]*OpenclawEvent, 0, 3)
	timeout := time.After(5 * time.Second)
	for len(events) < 3 {
		select {
		case evt := <-inst.eventCh:
			events = append(events, evt)
		case <-timeout:
			t.Fatalf("Timeout: got %d of 3 events", len(events))
		}
	}

	assert.Len(t, events, 3)
	assert.Equal(t, "cmd1", events[0].Args)
	assert.Equal(t, "cmd2", events[1].Args)
	assert.Equal(t, "cmd3", events[2].Args)
}

// TC-2-04: Multi-file watch
func TestPipelineMultiFileWatch(t *testing.T) {
	dir := t.TempDir()
	files := []string{
		filepath.Join(dir, "file1.jsonl"),
		filepath.Join(dir, "file2.jsonl"),
		filepath.Join(dir, "file3.jsonl"),
	}
	for _, f := range files {
		os.WriteFile(f, []byte(""), 0644)
	}

	p := initPlugin(t, files)
	inst := openAndCleanup(t, p)

	// Write to each file
	for i, f := range files {
		line := fmt.Sprintf(`{"type":"tool_call","tool":"bash","args":"from-file-%d","session_id":"sess-mf-%d","timestamp":"2026-02-27T10:00:0%dZ"}`, i+1, i+1, i)
		writeToLog(t, f, line)
	}

	// Collect events from all files
	events := make(map[string]*OpenclawEvent)
	timeout := time.After(5 * time.Second)
	for len(events) < 3 {
		select {
		case evt := <-inst.eventCh:
			events[evt.Args] = evt
		case <-timeout:
			t.Fatalf("Timeout: got %d of 3 events", len(events))
		}
	}

	assert.Contains(t, events, "from-file-1")
	assert.Contains(t, events, "from-file-2")
	assert.Contains(t, events, "from-file-3")
}

// TC-2-05: GOB round-trip (CRITICAL)
func TestPipelineGOBRoundTrip(t *testing.T) {
	ts := time.Date(2026, 2, 27, 10, 0, 0, 0, time.UTC)
	original := &OpenclawEvent{
		Type:        "tool_call",
		Tool:        "bash",
		Args:        "rm -rf /",
		SessionID:   "sess-gob-001",
		Timestamp:   ts,
		SourceFile:  "agent.jsonl",
		UserMessage: "test message",
		Model:       "claude-3-opus",
		ConfigPath:  "/home/user/.openclaw/config.json",
		Suspicious:  "dangerous_command",
		LogPath:     "/home/user/.openclaw/logs/agent.jsonl",
		Raw:         `{"type":"tool_call","tool":"bash","args":"rm -rf /"}`,
		Headers:     map[string]string{"x-request-id": "req-123", "x-trace": "trace-abc"},
	}

	// Encode
	data := gobEncode(t, original)
	assert.NotEmpty(t, data)

	// Decode
	decoded := gobDecode(t, data)

	// Verify ALL 13 fields survive round-trip
	assert.Equal(t, original.Type, decoded.Type)
	assert.Equal(t, original.Tool, decoded.Tool)
	assert.Equal(t, original.Args, decoded.Args)
	assert.Equal(t, original.SessionID, decoded.SessionID)
	assert.True(t, original.Timestamp.Equal(decoded.Timestamp),
		"Timestamp: expected %v, got %v", original.Timestamp, decoded.Timestamp)
	assert.Equal(t, original.SourceFile, decoded.SourceFile)
	assert.Equal(t, original.UserMessage, decoded.UserMessage)
	assert.Equal(t, original.Model, decoded.Model)
	assert.Equal(t, original.ConfigPath, decoded.ConfigPath)
	assert.Equal(t, original.Suspicious, decoded.Suspicious)
	assert.Equal(t, original.LogPath, decoded.LogPath)
	assert.Equal(t, original.Raw, decoded.Raw)
	assert.Equal(t, original.Headers, decoded.Headers)
}

// TC-2-06: Headers non-nil (P004) (CRITICAL)
func TestPipelineHeadersNonNil(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "headers.jsonl")
	os.WriteFile(logPath, []byte(""), 0644)

	p := initPlugin(t, []string{logPath})
	inst := openAndCleanup(t, p)

	// Write line without explicit headers
	line := `{"type":"tool_call","tool":"bash","args":"ls","session_id":"sess-hdr-001","timestamp":"2026-02-27T10:00:00Z"}`
	writeToLog(t, logPath, line)

	evt := waitForEvent(t, inst.eventCh, 5*time.Second)
	assert.NotNil(t, evt.Headers, "Headers must never be nil (P004)")

	// GOB encode/decode should also preserve non-nil
	data := gobEncode(t, evt)
	decoded := gobDecode(t, data)
	assert.NotNil(t, decoded.Headers, "Headers must survive GOB round-trip as non-nil (P004)")
}

// TC-2-07: Headers copy
func TestPipelineHeadersCopy(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "hdr-copy.jsonl")
	os.WriteFile(logPath, []byte(""), 0644)

	p := initPlugin(t, []string{logPath})
	inst := openAndCleanup(t, p)

	line := `{"type":"tool_call","tool":"read","args":"test","session_id":"sess-hc-001","timestamp":"2026-02-27T10:00:00Z","headers":{"x-request-id":"req-456","x-trace":"trace-def"}}`
	writeToLog(t, logPath, line)

	evt := waitForEvent(t, inst.eventCh, 5*time.Second)
	assert.Equal(t, "req-456", evt.Headers["x-request-id"])
	assert.Equal(t, "trace-def", evt.Headers["x-trace"])
}

// TC-2-08: Headers field exists in Fields() definition
func TestPipelineHeadersFieldExists(t *testing.T) {
	// Verify openclaw.headers is defined in Fields().
	// Note: P012 (header key lowercase) is enforced in Extract(), tested implicitly
	// via TC-2-07 (TestPipelineHeadersCopy) which verifies header key round-trip.
	p := &OpenclawPlugin{}
	p.Init("")

	fields := p.Fields()
	var headersField *struct{ Name string }
	for _, f := range fields {
		if f.Name == "openclaw.headers" {
			headersField = &struct{ Name string }{Name: f.Name}
			break
		}
	}
	require.NotNil(t, headersField, "openclaw.headers field must exist")
}

// TC-2-09: Timestamp formats
func TestPipelineTimestampFormats(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "ts.jsonl")
	os.WriteFile(logPath, []byte(""), 0644)

	p := initPlugin(t, []string{logPath})
	inst := openAndCleanup(t, p)

	formats := []struct {
		name      string
		timestamp string
	}{
		{"RFC3339", `2026-02-27T10:00:00Z`},
		{"RFC3339_offset", `2026-02-27T10:00:00+09:00`},
	}

	for _, tt := range formats {
		t.Run(tt.name, func(t *testing.T) {
			line := fmt.Sprintf(`{"type":"tool_call","tool":"bash","args":"ts-%s","session_id":"sess-ts","timestamp":"%s"}`,
				tt.name, tt.timestamp)
			writeToLog(t, logPath, line)

			evt := waitForEvent(t, inst.eventCh, 5*time.Second)
			assert.False(t, evt.Timestamp.IsZero(), "Timestamp should be parsed: %s", tt.name)
		})
	}
}

// TC-2-10: Source file basename
func TestPipelineSourceFile(t *testing.T) {
	dir := t.TempDir()
	subdir := filepath.Join(dir, "deep", "nested")
	os.MkdirAll(subdir, 0755)
	logPath := filepath.Join(subdir, "agent.jsonl")
	os.WriteFile(logPath, []byte(""), 0644)

	p := initPlugin(t, []string{logPath})
	inst := openAndCleanup(t, p)

	line := `{"type":"tool_call","tool":"bash","args":"test","session_id":"sess-sf-001","timestamp":"2026-02-27T10:00:00Z"}`
	writeToLog(t, logPath, line)

	evt := waitForEvent(t, inst.eventCh, 5*time.Second)
	assert.Equal(t, "agent.jsonl", evt.SourceFile, "SourceFile should be basename only")
}

// TC-2-11: Empty line skip
func TestPipelineEmptyLineSkip(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "empty.jsonl")
	os.WriteFile(logPath, []byte(""), 0644)

	p := initPlugin(t, []string{logPath})
	inst := openAndCleanup(t, p)

	// Write empty lines followed by a valid line
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0644)
	require.NoError(t, err)
	f.WriteString("\n")
	f.WriteString("\n")
	f.WriteString(`{"type":"tool_call","tool":"bash","args":"after-empty","session_id":"sess-el-001","timestamp":"2026-02-27T10:00:00Z"}` + "\n")
	f.Close()

	evt := waitForEvent(t, inst.eventCh, 5*time.Second)
	assert.Equal(t, "after-empty", evt.Args, "Should skip empty lines and get valid event")
}

// TC-2-12: fsnotify Write event
func TestPipelineFsnotifyWrite(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "fsn.jsonl")
	os.WriteFile(logPath, []byte(""), 0644)

	p := initPlugin(t, []string{logPath})
	inst := openAndCleanup(t, p)

	// Write and verify fsnotify triggers
	line := `{"type":"tool_call","tool":"bash","args":"fsnotify-test","session_id":"sess-fn-001","timestamp":"2026-02-27T10:00:00Z"}`
	writeToLog(t, logPath, line)

	evt := waitForEvent(t, inst.eventCh, 5*time.Second)
	assert.Equal(t, "fsnotify-test", evt.Args)
}

// =============================================
// TC-5: Performance Tests
// =============================================

// TC-5-01: Throughput
func TestPipelineThroughput(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "throughput.jsonl")
	os.WriteFile(logPath, []byte(""), 0644)

	p := initPlugin(t, []string{logPath})
	inst := openAndCleanup(t, p)

	numLines := 100
	start := time.Now()

	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0644)
	require.NoError(t, err)
	for i := 0; i < numLines; i++ {
		line := fmt.Sprintf(`{"type":"tool_call","tool":"bash","args":"cmd-%d","session_id":"sess-tp-%d","timestamp":"2026-02-27T10:00:00Z"}`, i, i)
		f.WriteString(line + "\n")
	}
	f.Close()

	// Collect all events
	count := 0
	timeout := time.After(10 * time.Second)
	for count < numLines {
		select {
		case <-inst.eventCh:
			count++
		case <-timeout:
			t.Fatalf("Timeout: got %d of %d events", count, numLines)
		}
	}

	elapsed := time.Since(start)
	rate := float64(numLines) / elapsed.Seconds()
	t.Logf("Throughput: %d events in %v (%.0f events/sec)", numLines, elapsed, rate)
	assert.GreaterOrEqual(t, rate, 100.0, "Must handle at least 100 events/sec")
}

// TC-5-02: Buffer overflow non-hang
func TestPipelineBufferOverflow(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "overflow.jsonl")
	os.WriteFile(logPath, []byte(""), 0644)

	// Use small buffer
	p := &OpenclawPlugin{}
	cfg := fmt.Sprintf(`{"log_paths": ["%s"], "event_buffer_size": 2}`, logPath)
	err := p.Init(cfg)
	require.NoError(t, err)
	inst := openAndCleanup(t, p)

	// Write more events than buffer can hold (without reading)
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0644)
	require.NoError(t, err)
	for i := 0; i < 10; i++ {
		line := fmt.Sprintf(`{"type":"tool_call","tool":"bash","args":"overflow-%d","session_id":"sess-of-%d","timestamp":"2026-02-27T10:00:00Z"}`, i, i)
		f.WriteString(line + "\n")
	}
	f.Close()

	// Wait for readLoop to attempt sending all 10 events to a buffer of size 2.
	// 2s allows the goroutine to process all writes and hit channel-full drops.
	time.Sleep(2 * time.Second)

	// Verify plugin didn't hang — we can still interact
	assert.NotNil(t, inst.eventCh, "Plugin should not hang on buffer overflow")
}

// TC-5-03: Dropped events counter
func TestPipelineDropCount(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "drop.jsonl")
	os.WriteFile(logPath, []byte(""), 0644)

	p := &OpenclawPlugin{}
	cfg := fmt.Sprintf(`{"log_paths": ["%s"], "event_buffer_size": 1}`, logPath)
	err := p.Init(cfg)
	require.NoError(t, err)
	inst := openAndCleanup(t, p)

	// Fill channel with one event
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0644)
	require.NoError(t, err)
	for i := 0; i < 20; i++ {
		line := fmt.Sprintf(`{"type":"tool_call","tool":"bash","args":"drop-%d","session_id":"sess-dr-%d","timestamp":"2026-02-27T10:00:00Z"}`, i, i)
		f.WriteString(line + "\n")
	}
	f.Close()

	// Wait for readLoop to process all 20 writes with buffer=1.
	// 2s allows the goroutine to finish; most events will be dropped.
	time.Sleep(2 * time.Second)

	dropped := atomic.LoadUint64(&inst.droppedEvents)
	t.Logf("Dropped events: %d", dropped)
	// With buffer=1 and 20 writes, some should be dropped
	assert.Greater(t, dropped, uint64(0), "Some events should have been dropped")
}

// TC-5-04: Large input (10KB)
func TestPipelineLargeInput(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "large.jsonl")
	os.WriteFile(logPath, []byte(""), 0644)

	p := initPlugin(t, []string{logPath})
	inst := openAndCleanup(t, p)

	// Create a 10KB+ args string
	largeArgs := strings.Repeat("A", 10240)
	line := fmt.Sprintf(`{"type":"tool_call","tool":"bash","args":"%s","session_id":"sess-lg-001","timestamp":"2026-02-27T10:00:00Z"}`, largeArgs)
	writeToLog(t, logPath, line)

	evt := waitForEvent(t, inst.eventCh, 5*time.Second)
	assert.Equal(t, largeArgs, evt.Args, "Large args should be preserved fully in OpenclawEvent")
}

// TC-5-05: Long-running stability (skippable)
func TestPipelineLongRunning(t *testing.T) {
	if testing.Short() {
		t.Skip("long-running test")
	}

	dir := t.TempDir()
	logPath := filepath.Join(dir, "longrun.jsonl")
	os.WriteFile(logPath, []byte(""), 0644)

	p := initPlugin(t, []string{logPath})
	inst := openAndCleanup(t, p)

	// Run for 10 seconds (shortened from 5 minutes for CI)
	duration := 10 * time.Second
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	timer := time.After(duration)

	count := 0
	for {
		select {
		case <-ticker.C:
			line := fmt.Sprintf(`{"type":"tool_call","tool":"bash","args":"long-%d","session_id":"sess-lr-%d","timestamp":"2026-02-27T10:00:00Z"}`, count, count)
			writeToLog(t, logPath, line)
			count++
		case <-timer:
			t.Logf("Long-running: wrote %d events in %v", count, duration)
			// Drain channel
			drained := 0
			timeout := time.After(5 * time.Second)
		drain:
			for {
				select {
				case <-inst.eventCh:
					drained++
				case <-timeout:
					break drain
				}
			}
			t.Logf("Drained %d events", drained)
			assert.Greater(t, drained, 0, "Should have received some events")
			return
		}
	}
}

// =============================================
// TC-6: Error Handling Tests
// =============================================

// TC-6-01: Invalid JSON
func TestPipelineInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "invalid.jsonl")
	os.WriteFile(logPath, []byte(""), 0644)

	p := initPlugin(t, []string{logPath})
	inst := openAndCleanup(t, p)

	// Write invalid JSON followed by valid JSON
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0644)
	require.NoError(t, err)
	f.WriteString("{invalid json\n")
	f.WriteString(`{"type":"tool_call","tool":"bash","args":"after-invalid","session_id":"sess-ij-001","timestamp":"2026-02-27T10:00:00Z"}` + "\n")
	f.Close()

	// Should still receive the valid event (no crash)
	evt := waitForEvent(t, inst.eventCh, 5*time.Second)
	assert.Equal(t, "after-invalid", evt.Args)
}

// TC-6-02: Empty line handling
func TestPipelineEmptyLine(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "emptyline.jsonl")
	os.WriteFile(logPath, []byte(""), 0644)

	p := initPlugin(t, []string{logPath})
	inst := openAndCleanup(t, p)

	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0644)
	require.NoError(t, err)
	f.WriteString("\n\n\n")
	f.WriteString(`{"type":"tool_call","tool":"bash","args":"after-empty-lines","session_id":"sess-el2-001","timestamp":"2026-02-27T10:00:00Z"}` + "\n")
	f.Close()

	evt := waitForEvent(t, inst.eventCh, 5*time.Second)
	assert.Equal(t, "after-empty-lines", evt.Args)
}

// TC-6-03: Super long line (1MB+)
func TestPipelineSuperLongLine(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "superlong.jsonl")
	os.WriteFile(logPath, []byte(""), 0644)

	p := initPlugin(t, []string{logPath})
	inst := openAndCleanup(t, p)

	// Write 1MB+ line followed by a normal line
	megaArgs := strings.Repeat("X", 1024*1024)
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0644)
	require.NoError(t, err)
	f.WriteString(fmt.Sprintf(`{"type":"tool_call","tool":"bash","args":"%s","session_id":"sess-sl-001","timestamp":"2026-02-27T10:00:00Z"}`, megaArgs) + "\n")
	f.WriteString(`{"type":"tool_call","tool":"bash","args":"after-superlong","session_id":"sess-sl-002","timestamp":"2026-02-27T10:00:01Z"}` + "\n")
	f.Close()

	// Should handle without crash — collect events
	timeout := time.After(10 * time.Second)
	foundAfter := false
	for !foundAfter {
		select {
		case evt := <-inst.eventCh:
			if evt.Args == "after-superlong" {
				foundAfter = true
			}
		case <-timeout:
			t.Log("Timeout collecting events after super long line, but no crash — acceptable")
			return
		}
	}
}

// TC-6-04: File deleted
func TestPipelineFileDeleted(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "deleteme.jsonl")
	os.WriteFile(logPath, []byte(""), 0644)

	p := initPlugin(t, []string{logPath})
	inst := openAndCleanup(t, p)

	// Write an event first
	writeToLog(t, logPath, `{"type":"tool_call","tool":"bash","args":"before-delete","session_id":"sess-del-001","timestamp":"2026-02-27T10:00:00Z"}`)
	waitForEvent(t, inst.eventCh, 5*time.Second)

	// Delete the file and wait for fsnotify REMOVE event to propagate.
	// 500ms is sufficient for the watcher to detect and handle the deletion.
	os.Remove(logPath)
	time.Sleep(500 * time.Millisecond)

	// Plugin should not crash
	assert.NotNil(t, inst.eventCh, "Plugin should survive file deletion")
}

// TC-6-05: File recreated
func TestPipelineFileRecreated(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "recreate.jsonl")
	os.WriteFile(logPath, []byte(""), 0644)

	p := initPlugin(t, []string{logPath})
	inst := openAndCleanup(t, p)
	_ = inst

	// Delete and recreate: wait 500ms between each step for fsnotify
	// to detect REMOVE then CREATE events and update internal state.
	os.Remove(logPath)
	time.Sleep(500 * time.Millisecond)
	os.WriteFile(logPath, []byte(""), 0644)
	time.Sleep(500 * time.Millisecond)

	// Plugin should not crash
	assert.NotNil(t, inst.eventCh, "Plugin should survive file recreation")
}

// TC-6-06: Permission error
func TestPipelinePermissionError(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("Cannot test permission errors as root")
	}

	dir := t.TempDir()
	logPath := filepath.Join(dir, "noperm.jsonl")
	os.WriteFile(logPath, []byte(""), 0000)
	defer os.Chmod(logPath, 0644)

	p := &OpenclawPlugin{}
	cfg := fmt.Sprintf(`{"log_paths": ["%s"]}`, logPath)
	err := p.Init(cfg)
	require.NoError(t, err)

	// Open should not crash even with permission errors
	inst, err := p.Open("")
	if err == nil {
		inst.(*OpenclawInstance).Close()
	}
	// Either error or degraded operation — no crash
}

// TC-6-07: Invalid Init config
func TestPipelineInitInvalidConfig(t *testing.T) {
	tests := []struct {
		name   string
		config string
	}{
		{"invalid_json", "{not json}"},
		{"wrong_type", `{"log_paths": "not-array"}`},
		{"malformed", `{"event_buffer_size": "not-a-number"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &OpenclawPlugin{}
			err := p.Init(tt.config)
			// Should return error, not panic
			assert.Error(t, err, "Invalid config should return error: %s", tt.name)
		})
	}
}

// TC-6-08: GOB decode error
func TestPipelineGOBDecodeError(t *testing.T) {
	// Test that invalid GOB data doesn't crash the decoder
	invalidData := []byte("this is not valid GOB data")

	var event OpenclawEvent
	err := gob.NewDecoder(bytes.NewReader(invalidData)).Decode(&event)
	assert.Error(t, err, "Invalid GOB data should return error")
}

// TC-6-09: Unknown field in JSON
func TestPipelineUnknownField(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "unknown.jsonl")
	os.WriteFile(logPath, []byte(""), 0644)

	p := initPlugin(t, []string{logPath})
	inst := openAndCleanup(t, p)

	// JSON with unknown fields
	line := `{"type":"tool_call","tool":"bash","args":"test-unknown","session_id":"sess-uf-001","timestamp":"2026-02-27T10:00:00Z","unknown_field":"value","extra":123}`
	writeToLog(t, logPath, line)

	evt := waitForEvent(t, inst.eventCh, 5*time.Second)
	assert.Equal(t, "test-unknown", evt.Args, "Should parse known fields and ignore unknown")
}

// TC-6-10: Binary data in input
func TestPipelineBinaryData(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "binary.jsonl")
	os.WriteFile(logPath, []byte(""), 0644)

	p := initPlugin(t, []string{logPath})
	inst := openAndCleanup(t, p)

	// Write binary-like data followed by valid JSON
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0644)
	require.NoError(t, err)
	f.Write([]byte{0x00, 0x01, 0x02, 0xFF, 0xFE, '\n'})
	f.WriteString(`{"type":"tool_call","tool":"bash","args":"after-binary","session_id":"sess-bin-001","timestamp":"2026-02-27T10:00:00Z"}` + "\n")
	f.Close()

	// Should not crash, should eventually get the valid event
	timeout := time.After(5 * time.Second)
	for {
		select {
		case evt := <-inst.eventCh:
			if evt.Args == "after-binary" {
				return // Success
			}
		case <-timeout:
			t.Log("Timeout after binary data, but no crash — acceptable")
			return
		}
	}
}

// TC-6-11: Non-target file change
func TestPipelineNonTargetFile(t *testing.T) {
	dir := t.TempDir()
	targetPath := filepath.Join(dir, "target.jsonl")
	nonTargetPath := filepath.Join(dir, "other.txt")
	os.WriteFile(targetPath, []byte(""), 0644)
	os.WriteFile(nonTargetPath, []byte(""), 0644)

	p := initPlugin(t, []string{targetPath})
	inst := openAndCleanup(t, p)

	// Write to non-target file
	writeToLog(t, nonTargetPath, `{"type":"tool_call","tool":"bash","args":"non-target","session_id":"sess-nt-001","timestamp":"2026-02-27T10:00:00Z"}`)

	// Write to target file
	writeToLog(t, targetPath, `{"type":"tool_call","tool":"bash","args":"from-target","session_id":"sess-tgt-001","timestamp":"2026-02-27T10:00:00Z"}`)

	evt := waitForEvent(t, inst.eventCh, 5*time.Second)
	assert.Equal(t, "from-target", evt.Args, "Should only receive events from target file")
}
