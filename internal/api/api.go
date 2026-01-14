package api

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"dnsleaktest/internal/httpclient"
	"dnsleaktest/internal/model"
)

const apiBaseURL = "https://bigdig.energy"

// Client wraps BigDig API access.
type Client struct {
	HTTP    *httpclient.Client
	BaseURL string
}

// New creates API client with default base URL.
func New(httpCli *httpclient.Client) *Client {
	return &Client{HTTP: httpCli, BaseURL: apiBaseURL}
}

func (c *Client) FetchClientIPData() (*model.ClientIPData, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var data model.ClientIPData
	if err := c.HTTP.DoJSON(ctx, "GET", c.BaseURL+"/get_data", &data); err != nil {
		return nil, err
	}
	return &data, nil
}

func (c *Client) StartFullTest(short bool) (*model.StartTestResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var resp model.StartTestResponse
	var isNoFail string
	if short {
		isNoFail = "0"
	} else {
		isNoFail = "1"
	}
	if err := c.HTTP.DoJSON(ctx, "POST", c.BaseURL+fmt.Sprintf("/start_test?no_fail=%v", isNoFail), &resp); err != nil {
		return nil, err
	}
	if resp.TestID == "" {
		return nil, fmt.Errorf("empty test_id in response")
	}
	return &resp, nil
}

func (c *Client) FetchResults(testID string) (*model.ResultsResponse, error) {
	const maxRetries = 3
	var lastErr error
	var result *model.ResultsResponse

	urlStr := fmt.Sprintf("%s/get_results/%s", c.BaseURL, url.PathEscape(testID))

	for attempt := 1; attempt <= maxRetries; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := c.HTTP.DoJSON(ctx, "GET", urlStr, &result)
		cancel()

		if err == nil && result != nil {
			return result, nil
		}

		if err != nil {
			lastErr = err
		}

		if attempt < maxRetries {
			time.Sleep(2 * time.Second)
		}
	}

	return nil, fmt.Errorf("failed to fetch results for test %s: %v", testID, lastErr)
}
