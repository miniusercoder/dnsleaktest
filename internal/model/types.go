package model

import "time"

// StartTestResponse represents server response for starting the test.
type StartTestResponse struct {
	TestID     string   `json:"test_id"`
	Subdomains []string `json:"subdomains"`
}

// ClientIPData describes the detected client endpoint.
type ClientIPData struct {
	IP      string   `json:"ip"`
	IsVPN   bool     `json:"is_vpn"`
	Country string   `json:"country"`
	City    string   `json:"city"`
	ISP     string   `json:"isp"`
	ASN     string   `json:"asn"`
	GPSLat  *float64 `json:"gps_lat"`
	GPSLong *float64 `json:"gps_long"`
}

// DNSServer describes a single DNS server in results.
type DNSServer struct {
	IP      string   `json:"ip"`
	IsVPN   bool     `json:"is_vpn"`
	Country string   `json:"country"`
	City    string   `json:"city"`
	ISP     string   `json:"isp"`
	ASN     string   `json:"asn"`
	GPSLat  *float64 `json:"gps_lat"`
	GPSLong *float64 `json:"gps_long"`
}

// ResultsResponse is the payload with DNS servers.
type ResultsResponse struct {
	DNSServers []DNSServer `json:"dns_servers"`
}

// RequestResult captures a single subdomain request outcome.
type RequestResult struct {
	Subdomain   string
	Status      string        // success, timeout, tls_error, error
	Phase       int           // 1 or 2
	Error       string        // error text if any
	RequestTime time.Duration // request duration
}
