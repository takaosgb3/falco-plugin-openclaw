package parser

// Config holds the parser configuration.
type Config struct {
	LogFormat              string // "json", "plaintext", "auto" (default: auto-detect)
	SecurityPatterns       bool   // Enable security threat detection
	LargeResponseThreshold int    // Threshold for large response detection (bytes)
}
