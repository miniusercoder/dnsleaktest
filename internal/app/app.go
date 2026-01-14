package app

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"dnsleaktest/internal/analysis"
	"dnsleaktest/internal/api"
	"dnsleaktest/internal/httpclient"
	"dnsleaktest/internal/model"
	"dnsleaktest/internal/probe"
)

const (
	waitTimeSeconds      = 69
	fetchIntervalSeconds = 13
)

// RunTest orchestrates the end-to-end flow.
func RunTest(short bool) error {
	httpCli := httpclient.New(30 * time.Second)
	apiClient := api.New(httpCli)

	if short {
		fmt.Println("== BigDig DNS leak test (short) ==")
	} else {
		fmt.Println("== BigDig DNS leak + DNS rebinding test ==")
	}

	fmt.Println("Request for client IP data...")
	clientData, err := apiClient.FetchClientIPData()
	if err != nil {
		fmt.Printf("  Unable to obtain client data: %v (this is not critical, continuing)\n\n", err)
	} else {
		analysis.PrintClientData(os.Stdout, clientData)
	}

	fmt.Println("Starting test...")
	startResp, err := apiClient.StartFullTest(short)
	if err != nil {
		return fmt.Errorf("test start error: %w", err)
	}
	fmt.Printf("Received test_id=%s, subdomains count: %d\n\n", startResp.TestID, len(startResp.Subdomains))

	if len(startResp.Subdomains) == 0 {
		return fmt.Errorf("no list of subdomains received from API")
	}

	fmt.Println("Phase 1: initial requests to subdomains...")
	phase1 := probe.RunPhase(httpCli.HTTP, startResp.Subdomains, 1)
	fmt.Printf("Phase 1 complete: %d requests completed.\n\n", len(phase1))

	var phase2 []model.RequestResult

	if !short {
		fmt.Printf("Waiting %d seconds, during which periodic requests to /probe are made...\n", waitTimeSeconds)
		deadline := time.Now().Add(time.Duration(waitTimeSeconds) * time.Second)
		iteration := 0

		for {
			now := time.Now()
			if !now.Before(deadline) {
				break
			}
			iteration++
			fmt.Printf("  Iteration %d (phase 2: /probe)...\n", iteration)
			batch := probe.RunPhase(httpCli.HTTP, startResp.Subdomains, 2)
			phase2 = append(phase2, batch...)

			remaining := time.Until(deadline)
			if remaining <= 0 {
				break
			}
			sleep := time.Duration(fetchIntervalSeconds) * time.Second
			if sleep > remaining {
				sleep = remaining
			}
			time.Sleep(sleep)
		}

		fmt.Printf("Phase 2 completed, total intermediate requests: %d\n\n", len(phase2))
	} else {
		fmt.Println("Short test: phase 2 skip...")
		time.Sleep(1 * time.Second)
	}

	fmt.Println("Receiving test results from the BigDig server...")
	results, err := apiClient.FetchResults(startResp.TestID)
	if err != nil {
		return fmt.Errorf("terror receiving results: %w", err)
	}

	fmt.Println()
	analysis.PrintDNSAnalysis(os.Stdout, phase1, phase2, results, clientData)

	if !short {
		fmt.Println()
		status, msg := analysis.DetectRebindingVulnerability(phase1, phase2)
		fmt.Printf("== DNS rebinding ==\nStatus: %s\n%s\n", strings.ToUpper(status), msg)
	}

	totalRequests := len(phase1) + len(phase2)
	fmt.Printf("\nTotal HTTP requests in the test: %d\n", totalRequests)

	return nil
}

func Main(short bool) {
	log.SetFlags(0)

	if err := RunTest(short); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
