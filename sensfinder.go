package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sync"
)

// Patterns to detect sensitive data, including PII relevant under GDPR
var patterns = map[string]*regexp.Regexp{
	// Secrets & Tokens
	"Generic API Key/Secret/Token": regexp.MustCompile(`(?i)(?:api[_-]?key|api[_-]?secret|token|bearer)["'=:\s]+([A-Za-z0-9\-_.{}=+/]{16,})`),
	"AWS Access Key":               regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	"Firebase API Key":             regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
	"JWT Token":                    regexp.MustCompile(`eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+`),
	"Hex/blob secret":              regexp.MustCompile(`(?i)secret["'=:\s]+([A-Fa-f0-9]{32,})`),

	// Personally Identifiable Information (PII)
	"Email Address":      regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`),
	"US Phone Number":    regexp.MustCompile(`(?:(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})`),
	"IP Address":         regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`),
	"Credit Card Number": regexp.MustCompile(`\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b`),
	"SSN (US)":           regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
}

// Result holds findings for a single URL
type Result struct {
	URL      string              `json:"url"`
	Findings map[string][]string `json:"findings"`
}

// FinalOutput holds the complete report structure
type FinalOutput struct {
	TaskName string   `json:"taskname"`
	Output   []Result `json:"output"`
}

func main() {
	// Add an output flag
	output := flag.String("o", "report.json", "output report file (JSON)")
	debug := flag.Bool("debug", false, "show debug output for each scan")
	flag.Parse()

	args := flag.Args()
	if len(args) != 1 {
		fmt.Printf("Usage: %s [flags] <urls_file>\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}
	filePath := args[0]

	// Read all URLs
	file, err := os.Open(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening file: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var urls []string
	for scanner.Scan() {
		if line := scanner.Text(); line != "" {
			urls = append(urls, line)
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
		os.Exit(1)
	}

	// Prepare for concurrent scanning
	var wg sync.WaitGroup
	results := make([]Result, 0)
	var mu sync.Mutex

	for _, url := range urls {
		wg.Add(1)
		if *debug {
			fmt.Printf("[*] Scheduling scan for %s\n", url)
		}
		go func(u string) {
			defer wg.Done()
			if *debug {
				fmt.Printf("[*] Scanning %s...\n", u)
			}
			res := scanURL(u)
			if *debug {
				fmt.Printf("[*] Completed scan for %s\n", u)
			}
			if len(res.Findings) > 0 {
				mu.Lock()
				results = append(results, res)
				mu.Unlock()
			}
		}(url)
	}
	wg.Wait()

	// Create final output structure
	finalOutput := FinalOutput{
		TaskName: "jsleaks",
		Output:   results,
	}

	// Write report
	data, err := json.MarshalIndent(finalOutput, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling report: %v\n", err)
		os.Exit(1)
	}

	// Ensure output directory exists
	outDir := filepath.Dir(*output)
	if err := os.MkdirAll(outDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating output directory: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(*output, data, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing report file: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Report written to %s with %d entries\n", *output, len(results))
}

func scanURL(url string) Result {
	res := Result{URL: url, Findings: map[string][]string{}}
	tpResp, err := http.Get(url)
	if err != nil || tpResp.StatusCode != http.StatusOK {
		return res
	}
	defer tpResp.Body.Close()

	bodyBytes, err := io.ReadAll(tpResp.Body)
	if err != nil {
		return res
	}
	body := string(bodyBytes)

	for name, re := range patterns {
		matches := re.FindAllString(body, -1)
		if len(matches) > 0 {
			unique := uniqueStrings(matches)
			res.Findings[name] = unique
		}
	}
	return res
}

func uniqueStrings(input []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, s := range input {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}
