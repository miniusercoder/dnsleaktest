package analysis

import (
	"fmt"
	"io"
	"strings"
	"time"

	"dnsleaktest/internal/model"
)

// PrintClientData renders client IP data to writer.
func PrintClientData(w io.Writer, data *model.ClientIPData) {
	if data == nil {
		fmt.Fprintln(w, "Client data: no data.")
		return
	}

	fmt.Fprintln(w, "== Client data ==")
	fmt.Fprintf(w, "IP: %s", data.IP)
	if data.IsVPN {
		fmt.Fprint(w, "  (VPN detected)")
	}
	fmt.Fprintln(w)

	var locParts []string
	if data.City != "" {
		locParts = append(locParts, data.City)
	}
	if data.Country != "" {
		locParts = append(locParts, data.Country)
	}
	if len(locParts) > 0 {
		fmt.Fprintf(w, "Location: %s\n", strings.Join(locParts, ", "))
	}
	if data.ISP != "" {
		fmt.Fprintf(w, "ISP: %s\n", data.ISP)
	}
	if data.ASN != "" {
		fmt.Fprintf(w, "ASN: %s\n", data.ASN)
	}
	if data.GPSLat != nil && data.GPSLong != nil {
		fmt.Fprintf(w, "GPS: %.4f, %.4f\n", *data.GPSLat, *data.GPSLong)
	}
	fmt.Fprintln(w)
}

// PrintDNSAnalysis outputs DNS leak analysis.
func PrintDNSAnalysis(w io.Writer, phase1, phase2 []model.RequestResult, results *model.ResultsResponse, client *model.ClientIPData) {
	fmt.Fprintln(w, "== DNS leak / DNS-servers ==")

	if results == nil || len(results.DNSServers) == 0 {
		fmt.Fprintln(w, "The server did not return a list of DNS servers. DNS leaks cannot be assessed..")
		return
	}

	uniqueServers := map[string]model.DNSServer{}
	for _, s := range results.DNSServers {
		if s.IP == "" {
			continue
		}
		if _, ok := uniqueServers[s.IP]; !ok {
			uniqueServers[s.IP] = s
		}
	}

	uniqueISPs := map[string]struct{}{}
	for _, s := range uniqueServers {
		isp := strings.TrimSpace(s.ISP)
		if isp == "" {
			continue
		}
		if isp == "NetActuate" { // normalize like JS version
			isp = "CONTROLD"
		}
		uniqueISPs[isp] = struct{}{}
	}

	fmt.Fprintf(w, "Found %d unique DNS server(s), DNS providers: %d\n\n", len(uniqueServers), len(uniqueISPs))

	for _, s := range uniqueServers {
		fmt.Fprintf(w, "- %s", s.IP)
		if s.IsVPN {
			fmt.Fprint(w, "  [VPN / proxy]")
		}
		fmt.Fprintln(w)

		var locParts []string
		if s.City != "" {
			locParts = append(locParts, s.City)
		}
		if s.Country != "" {
			locParts = append(locParts, s.Country)
		}
		if len(locParts) > 0 {
			fmt.Fprintf(w, "    Location: %s\n", strings.Join(locParts, ", "))
		}
		if s.ISP != "" {
			fmt.Fprintf(w, "    ISP: %s\n", s.ISP)
		}
		if s.ASN != "" {
			fmt.Fprintf(w, "    ASN: %s\n", s.ASN)
		}
		if s.GPSLat != nil && s.GPSLong != nil {
			fmt.Fprintf(w, "    GPS: %.4f, %.4f\n", *s.GPSLat, *s.GPSLong)
		}
	}

	allResults := append([]model.RequestResult{}, phase1...)
	allResults = append(allResults, phase2...)

	var sum time.Duration
	var count int
	for _, r := range allResults {
		if r.Status == "success" && r.RequestTime > 0 {
			sum += r.RequestTime
			count++
		}
	}
	if count > 0 {
		avg := sum / time.Duration(count)
		fmt.Fprintf(w, "\nAverage time for a successful HTTP request: %v\n", avg)
	}

	if len(uniqueISPs) > 1 {
		fmt.Fprintf(w, "\nDNS leak verdict: LEAKS DETECTED ( %d different DNS providers involved).\n", len(uniqueISPs))
		if client != nil && client.IsVPN {
			fmt.Fprintln(w, "It seems that some DNS requests bypass the VPN (or the system is configured in a non-standard way).")
		}
	} else {
		fmt.Fprintln(w, "\nVerdict on DNS leaks: NO LEAKS DETECTED (all DNS servers belong to the same provider).")
		if client != nil && client.IsVPN {
			fmt.Fprintln(w, "The VPN appears to be routing DNS requests correctly.")
		}
	}
}

// DetectRebindingVulnerability evaluates rebinding heuristics.
func DetectRebindingVulnerability(phase1, phase2 []model.RequestResult) (string, string) {
	isVulnerable := false
	var reasons []string

	var phase1Timeouts, phase2Timeouts int
	tlsErrorCount := 0

	for _, r := range phase1 {
		if r.Status == "timeout" {
			phase1Timeouts++
		}
		if r.Status == "tls_error" || strings.Contains(strings.ToLower(r.Error), "certificate") {
			tlsErrorCount++
		}
	}
	for _, r := range phase2 {
		if r.Status == "timeout" {
			phase2Timeouts++
		}
		if r.Status == "tls_error" || strings.Contains(strings.ToLower(r.Error), "certificate") {
			tlsErrorCount++
		}
	}

	if phase2Timeouts > 0 {
		isVulnerable = true
		reasons = append(reasons, fmt.Sprintf("%d request(s) in the second phase timed out — possible hit on unavailable internal addresses", phase2Timeouts))
	}

	if tlsErrorCount > 0 {
		isVulnerable = true
		reasons = append(reasons, fmt.Sprintf("%d request(s) resulted in TLS/certificate errors — internal HTTPS services with invalid certificates may be accessible", tlsErrorCount))
	}

	var timings []float64
	for _, r := range phase2 {
		if r.RequestTime <= 0 {
			continue
		}
		ms := float64(r.RequestTime.Milliseconds())
		if ms > 0 {
			timings = append(timings, ms)
		}
	}

	if len(timings) > 1 {
		fastest := timings[0]
		slowest := timings[0]
		for _, t := range timings[1:] {
			if t < fastest {
				fastest = t
			}
			if t > slowest {
				slowest = t
			}
		}
		diff := slowest - fastest
		var ratio float64
		if fastest > 0 {
			ratio = slowest / fastest
		}

		if diff > 3000 {
			isVulnerable = true
			reasons = append(reasons, fmt.Sprintf("large variation in response times in the second phase (%.2f–%.2f ms, difference %.2f ms)", fastest, slowest, diff))
		} else if ratio > 30 {
			isVulnerable = true
			reasons = append(reasons, fmt.Sprintf("significant difference in response times in the second phase (in %.2f times)", ratio))
		}
	}

	var timeoutTimings []float64
	for _, r := range phase2 {
		if r.Status == "timeout" && r.RequestTime > 0 {
			timeoutTimings = append(timeoutTimings, float64(r.RequestTime.Milliseconds()))
		}
	}
	if len(timeoutTimings) > 1 && isVulnerable && len(reasons) == 1 && strings.Contains(reasons[0], "timeout") {
		fastest := timeoutTimings[0]
		slowest := timeoutTimings[0]
		for _, t := range timeoutTimings[1:] {
			if t < fastest {
				fastest = t
			}
			if t > slowest {
				slowest = t
			}
		}
		diff := slowest - fastest
		allAroundFiveSec := true
		for _, t := range timeoutTimings {
			if t < 4900 || t > 6100 {
				allAroundFiveSec = false
				break
			}
		}
		if diff < 100 || allAroundFiveSec {
			isVulnerable = false
			reasons = nil
		}
	}

	if isVulnerable {
		return "vulnerable", "The DNS resolver appears vulnerable to DNS rebinding attacks. " + strings.Join(reasons, ". ") + ". Please note: the conclusion is based on heuristics and is not a formal guarantee."
	}

	return "protected", "No obvious signs of successful DNS rebinding were found. This does not provide a 100% guarantee, but based on the metrics collected, the resolver appears to be secure."
}
