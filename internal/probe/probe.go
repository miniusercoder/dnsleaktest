package probe

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"dnsleaktest/internal/httpclient"
	"dnsleaktest/internal/model"
)

const (
	requestTimeout   = 5 * time.Second
	concurrencyLimit = 10
)

// DoSubdomainRequest performs a single phase request.
func DoSubdomainRequest(httpCli *http.Client, subdomain string, phase int) model.RequestResult {
	path := "/probe"
	if phase == 1 {
		path = "/get_data"
	}
	cb := time.Now().UnixNano()
	urlStr := fmt.Sprintf("https://%s%s?cb=%d", subdomain, path, cb)

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return model.RequestResult{Subdomain: subdomain, Status: "error", Phase: phase, Error: err.Error()}
	}

	start := time.Now()
	resp, err := httpCli.Do(req)
	elapsed := time.Since(start)

	if err != nil {
		status := "error"
		if httpclient.IsTimeout(err) {
			status = "timeout"
		} else if httpclient.IsTLSError(err) {
			status = "tls_error"
		}
		return model.RequestResult{Subdomain: subdomain, Status: status, Phase: phase, Error: err.Error(), RequestTime: elapsed}
	}
	resp.Body.Close()

	return model.RequestResult{Subdomain: subdomain, Status: "success", Phase: phase, RequestTime: elapsed}
}

// RunPhase executes requests concurrently for a set of subdomains.
func RunPhase(httpCli *http.Client, subdomains []string, phase int) []model.RequestResult {
	results := make([]model.RequestResult, 0, len(subdomains))
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrencyLimit)

	for _, sub := range subdomains {
		subdomain := sub
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			res := DoSubdomainRequest(httpCli, subdomain, phase)
			mu.Lock()
			results = append(results, res)
			mu.Unlock()
		}()
	}

	wg.Wait()
	return results
}
