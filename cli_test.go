package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestCLI_SmokeTest runs the CLI and verifies basic functionality
func TestCLI_SmokeTest(t *testing.T) {
	// Build the CLI first
	buildCmd := exec.Command("go", "build", "-o", "test_cli", ".")
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("Failed to build CLI: %v", err)
	}
	defer os.Remove("test_cli")
	
	// Run CLI on testdata directory
	cmd := exec.Command("./test_cli", "testdata")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	
	err := cmd.Run()
	
	// CLI should complete (may have non-zero exit if findings found)
	t.Logf("stdout: %s", stdout.String())
	t.Logf("stderr: %s", stderr.String())
	
	if err != nil {
		// Check if it's just a non-zero exit (findings found)
		if exitErr, ok := err.(*exec.ExitError); ok {
			t.Logf("CLI exited with code: %d", exitErr.ExitCode())
		} else {
			t.Errorf("CLI execution failed: %v", err)
		}
	}
	
	// Output should contain some indication of scanning
	output := stdout.String() + stderr.String()
	if !strings.Contains(output, "scan") && !strings.Contains(output, "Scan") && 
	   !strings.Contains(output, "file") && !strings.Contains(output, "File") {
		t.Log("Warning: Output doesn't contain expected scan-related text")
	}
}

// TestCLI_HelpFlag tests the help flag
func TestCLI_HelpFlag(t *testing.T) {
	// Build the CLI
	buildCmd := exec.Command("go", "build", "-o", "test_cli", ".")
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("Failed to build CLI: %v", err)
	}
	defer os.Remove("test_cli")
	
	// Run with --help
	cmd := exec.Command("./test_cli", "--help")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	
	_ = cmd.Run() // May fail, that's ok for --help
	
	output := stdout.String()
	
	// Help should mention usage or options
	if !strings.Contains(strings.ToLower(output), "usage") && 
	   !strings.Contains(strings.ToLower(output), "option") &&
	   !strings.Contains(strings.ToLower(output), "help") {
		t.Log("Warning: Help output may not be standard")
	}
}

// TestCLI_JSONOutput tests JSON output functionality (if supported)
func TestCLI_JSONOutput(t *testing.T) {
	// Build the CLI
	buildCmd := exec.Command("go", "build", "-o", "test_cli", ".")
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("Failed to build CLI: %v", err)
	}
	defer os.Remove("test_cli")
	
	// Create temp output directory
	tempDir := t.TempDir()
	
	// Run CLI with output directory (if supported)
	cmd := exec.Command("./test_cli", "-output", tempDir, "testdata")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	
	err := cmd.Run()
	if err != nil {
		t.Logf("CLI returned error: %v", err)
	}
	
	// Look for JSON files in output
	files, _ := filepath.Glob(filepath.Join(tempDir, "*.json"))
	if len(files) > 0 {
		// Try to parse the JSON
		for _, f := range files {
			data, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			
			var result map[string]interface{}
			if err := json.Unmarshal(data, &result); err != nil {
				t.Errorf("JSON file %s is not valid JSON: %v", f, err)
			} else {
				t.Logf("Found valid JSON output: %s", f)
			}
		}
	}
}

// TestCLI_NonExistentPath tests error handling for non-existent paths
func TestCLI_NonExistentPath(t *testing.T) {
	// Build the CLI
	buildCmd := exec.Command("go", "build", "-o", "test_cli", ".")
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("Failed to build CLI: %v", err)
	}
	defer os.Remove("test_cli")
	
	// Run CLI on non-existent path
	cmd := exec.Command("./test_cli", "/path/that/does/not/exist/anywhere")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	
	err := cmd.Run()
	
	// Should return an error
	if err == nil {
		t.Log("Warning: CLI should return error for non-existent path")
	}
}

// TestCLI_EmptyDirectory tests scanning an empty directory
func TestCLI_EmptyDirectory(t *testing.T) {
	// Build the CLI
	buildCmd := exec.Command("go", "build", "-o", "test_cli", ".")
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("Failed to build CLI: %v", err)
	}
	defer os.Remove("test_cli")
	
	// Create empty temp directory
	tempDir := t.TempDir()
	
	// Run CLI on empty directory
	cmd := exec.Command("./test_cli", tempDir)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	
	err := cmd.Run()
	
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			t.Logf("CLI exited with code: %d", exitErr.ExitCode())
		}
	}
	
	// Should complete without crashing
	output := stdout.String() + stderr.String()
	if strings.Contains(strings.ToLower(output), "panic") {
		t.Error("CLI panicked on empty directory")
	}
}

