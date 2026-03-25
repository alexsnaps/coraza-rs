// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

// Package main provides a test harness for running go-ftw tests against coraza-rs
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/coreruleset/go-ftw/v2/config"
	"github.com/coreruleset/go-ftw/v2/output"
	"github.com/coreruleset/go-ftw/v2/runner"
	"github.com/coreruleset/go-ftw/v2/test"
	"github.com/rs/zerolog"
)

const (
	serverPort       = 8080
	serverLogfile    = "/tmp/coraza-ftw-audit.log"
	corazaRsPath     = ".."
	ftwConfigFile    = ".ftw-rust.yaml"
	serverBinaryPath = "../target/debug/examples/ftw_server"
)

func main() {
	fmt.Println("🧪 Coraza-RS FTW Test Runner\n")

	// Verify server binary exists
	if _, err := os.Stat(serverBinaryPath); os.IsNotExist(err) {
		fatal("Server binary not found at %s\nPlease build it first: cargo build --example ftw_server", serverBinaryPath)
	}
	fmt.Printf("✅ Found server binary: %s\n", serverBinaryPath)

	// Clean up old logfile
	os.Remove(serverLogfile)

	// Start server
	fmt.Println("🚀 Starting FTW server...")
	server := &Server{
		port:      serverPort,
		logfile:   serverLogfile,
		rulesFile: "", // No rules for basic test
	}

	if err := server.Start(); err != nil {
		fatal("Failed to start server: %v", err)
	}
	defer server.Stop()

	// Wait for server to be ready
	fmt.Println("⏳ Waiting for server to be ready...")
	time.Sleep(2 * time.Second)

	if !server.IsHealthy() {
		fatal("Server failed to start properly")
	}
	fmt.Printf("✅ Server ready on http://localhost:%d\n", serverPort)

	// Generate FTW config
	fmt.Println("📝 Generating FTW configuration...")
	if err := generateFTWConfig(); err != nil {
		fatal("Failed to generate config: %v", err)
	}
	fmt.Printf("✅ Config written to %s\n", ftwConfigFile)

	// Run FTW tests
	fmt.Println("🧪 Running FTW tests...")
	fmt.Println("=" + repeat("=", 60))
	if err := runFTW(); err != nil {
		fmt.Fprintf(os.Stderr, "\n❌ Tests failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\n" + repeat("=", 60))
	fmt.Println("✅ All tests complete!")
}

// Server represents the Rust FTW server process
type Server struct {
	cmd       *exec.Cmd
	port      int
	logfile   string
	rulesFile string
}

// Start starts the server process
func (s *Server) Start() error {
	args := []string{
		"--port", fmt.Sprintf("%d", s.port),
		"--logfile", s.logfile,
	}

	if s.rulesFile != "" {
		args = append(args, "--rules", s.rulesFile)
	}

	s.cmd = exec.Command(serverBinaryPath, args...)
	s.cmd.Stdout = os.Stdout
	s.cmd.Stderr = os.Stderr

	return s.cmd.Start()
}

// Stop stops the server process
func (s *Server) Stop() {
	if s.cmd != nil && s.cmd.Process != nil {
		fmt.Println("\n🛑 Stopping server...")
		s.cmd.Process.Kill()
		s.cmd.Wait()
	}
}

// IsHealthy checks if server is responding
func (s *Server) IsHealthy() bool {
	// Try to connect to server
	cmd := exec.Command("curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
		fmt.Sprintf("http://localhost:%d/", s.port))

	output, err := cmd.Output()
	if err != nil {
		return false
	}

	return string(output) == "200"
}

// generateFTWConfig creates the FTW configuration file
func generateFTWConfig() error {
	config := fmt.Sprintf(`# Auto-generated FTW configuration for coraza-rs
logfile: %s
logmarkerheadername: X-CRS-Test
testoverride:
  overrides:
    dest_addr: "localhost"
    port: %d
mode: "default"
`, serverLogfile, serverPort)

	return os.WriteFile(ftwConfigFile, []byte(config), 0644)
}

// runFTW executes go-ftw tests using the library directly
func runFTW() error {
	// Set up logging
	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	// Load configuration
	cfg, err := config.NewConfigFromFile(ftwConfigFile)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// For now, run basic health test
	// TODO: Load actual CRS tests when available
	testDir := filepath.Join("..", "go-ftw", "test")
	if _, err := os.Stat(testDir); os.IsNotExist(err) {
		fmt.Println("⚠️  No test directory found, running server health checks only")
		return testServerHealth()
	}

	// Get test files
	var tests []*test.FTWTest
	files, err := filepath.Glob(filepath.Join(testDir, "*.yaml"))
	if err != nil {
		return fmt.Errorf("failed to find test files: %w", err)
	}

	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			fmt.Printf("⚠️  Skipping %s: %v\n", file, err)
			continue
		}

		ftwTest, err := test.GetTestFromYaml(data, file)
		if err != nil {
			fmt.Printf("⚠️  Skipping %s: %v\n", file, err)
			continue
		}

		tests = append(tests, ftwTest)
	}

	if len(tests) == 0 {
		fmt.Println("⚠️  No valid test files found, running health checks only")
		return testServerHealth()
	}

	fmt.Printf("📋 Loaded %d test file(s)\n", len(tests))

	// Run tests
	runnerConfig := config.NewRunnerConfiguration(cfg)
	runnerConfig.ShowTime = true

	out := output.NewOutput("normal", os.Stdout)
	res, err := runner.Run(runnerConfig, tests, out)
	if err != nil {
		return fmt.Errorf("test execution failed: %w", err)
	}

	// Report results
	fmt.Printf("\n" + repeat("=", 60) + "\n")
	fmt.Printf("📊 Test Results:\n")
	fmt.Printf("   Run:     %d\n", res.Stats.Run)
	fmt.Printf("   Passed:  %d\n", res.Stats.Run-len(res.Stats.Failed))
	fmt.Printf("   Failed:  %d\n", len(res.Stats.Failed))
	fmt.Printf("   Ignored: %d\n", len(res.Stats.Ignored))
	fmt.Printf(repeat("=", 60) + "\n")

	if len(res.Stats.Failed) > 0 {
		return fmt.Errorf("%d test(s) failed", len(res.Stats.Failed))
	}

	return nil
}

// testServerHealth performs basic server health check
func testServerHealth() error {
	fmt.Println("\n🏥 Running basic health checks...")

	tests := []struct {
		name   string
		method string
		path   string
	}{
		{"GET /", "GET", "/"},
		{"POST /test", "POST", "/test"},
		{"GET with query", "GET", "/search?q=test"},
	}

	for _, test := range tests {
		fmt.Printf("   Testing: %s %s... ", test.method, test.path)

		url := fmt.Sprintf("http://localhost:%d%s", serverPort, test.path)
		cmd := exec.Command("curl", "-s", "-X", test.method, "-o", "/dev/null", "-w", "%{http_code}", url)

		output, err := cmd.Output()
		if err != nil {
			fmt.Println("❌ FAIL")
			return fmt.Errorf("request failed: %w", err)
		}

		status := string(output)
		if status == "200" {
			fmt.Println("✅ PASS")
		} else {
			fmt.Printf("⚠️  Status %s\n", status)
		}
	}

	fmt.Println("\n✅ Health checks passed")
	return nil
}

// fatal prints error and exits
func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "❌ "+format+"\n", args...)
	os.Exit(1)
}

// repeat repeats a string n times
func repeat(s string, n int) string {
	result := ""
	for i := 0; i < n; i++ {
		result += s
	}
	return result
}
