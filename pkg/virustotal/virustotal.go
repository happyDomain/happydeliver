// This file is part of the happyDeliver (R) project.
// Copyright (c) 2025 happyDomain
// Authors: Pierre-Olivier Mercier, et al.
//
// This program is offered under a commercial and under the AGPL license.
// For commercial licensing, contact us at <contact@happydomain.org>.
//
// For AGPL licensing:
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

// Package virustotal asks VirusTotal what it knows about a payload, by the
// hash of its content and, when the caller allows it, by handing over the file
// itself.
//
// It knows nothing of email: what is looked up and what a verdict is worth are
// the caller's business, as they are for the other services happyDeliver asks
// about a message.
package virustotal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"time"
)

// maxUploadSize is VirusTotal's direct-upload limit (32 MB)
const maxUploadSize = 32 << 20

// Client queries the VirusTotal API v3
type Client struct {
	apiKey       string
	baseURL      string // overridable in tests
	upload       bool   // upload files unknown to VirusTotal
	httpClient   *http.Client
	scanTimeout  time.Duration
	pollInterval time.Duration // delay between two analysis-status polls after upload
}

// Scan is the outcome of checking one payload against VirusTotal
type Scan struct {
	Status    string // clean, suspicious, malicious, unknown, pending, error
	Positives int    // engines flagging the file as malicious or suspicious
	Total     int    // engines that analyzed the file
	Permalink string // link to the VirusTotal report
	Error     string // error detail when status is error
}

// New creates a VirusTotal API client.
// Returns nil for an empty API key (disabled).
func New(apiKey string, upload bool, scanTimeout time.Duration) *Client {
	if apiKey == "" {
		return nil
	}

	return &Client{
		apiKey:       apiKey,
		baseURL:      "https://www.virustotal.com/api/v3",
		upload:       upload,
		httpClient:   &http.Client{Timeout: scanTimeout},
		scanTimeout:  scanTimeout,
		pollInterval: 5 * time.Second,
	}
}

// analysisStats is the last_analysis_stats / analysis stats object
type analysisStats struct {
	Malicious  int `json:"malicious"`
	Suspicious int `json:"suspicious"`
	Harmless   int `json:"harmless"`
	Undetected int `json:"undetected"`
}

func (s *analysisStats) toScan(sha256 string) *Scan {
	scan := &Scan{
		Positives: s.Malicious + s.Suspicious,
		Total:     s.Malicious + s.Suspicious + s.Harmless + s.Undetected,
		Permalink: "https://www.virustotal.com/gui/file/" + sha256,
	}
	switch {
	case s.Malicious > 0:
		scan.Status = "malicious"
	case s.Suspicious > 0:
		scan.Status = "suspicious"
	case scan.Total == 0:
		// No engine has produced a verdict yet (freshly submitted sample):
		// this is not the same as a verified-clean result.
		scan.Status = "pending"
	default:
		scan.Status = "clean"
	}
	return scan
}

// CheckHash looks up a file by SHA-256. When the hash is unknown and upload is
// enabled, the file content is submitted for analysis and polled until the
// context expires.
func (c *Client) CheckHash(ctx context.Context, sha256 string, content []byte) *Scan {
	scan := c.lookupHash(ctx, sha256)

	if scan.Status == "unknown" && c.upload && content != nil && len(content) <= maxUploadSize {
		return c.uploadAndPoll(ctx, sha256, content)
	}

	return scan
}

func (c *Client) lookupHash(ctx context.Context, sha256 string) *Scan {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/files/"+sha256, nil)
	if err != nil {
		return &Scan{Status: "error", Error: err.Error()}
	}
	req.Header.Set("x-apikey", c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return &Scan{Status: "error", Error: fmt.Sprintf("VirusTotal request failed: %v", err)}
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		var payload struct {
			Data struct {
				Attributes struct {
					LastAnalysisStats analysisStats `json:"last_analysis_stats"`
				} `json:"attributes"`
			} `json:"data"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
			return &Scan{Status: "error", Error: fmt.Sprintf("failed to decode VirusTotal response: %v", err)}
		}
		return payload.Data.Attributes.LastAnalysisStats.toScan(sha256)
	case http.StatusNotFound:
		return &Scan{Status: "unknown"}
	case http.StatusUnauthorized:
		return &Scan{Status: "error", Error: "invalid VirusTotal API key"}
	case http.StatusTooManyRequests:
		return &Scan{Status: "error", Error: "VirusTotal rate limit exceeded"}
	default:
		return &Scan{Status: "error", Error: fmt.Sprintf("unexpected VirusTotal response: %s", resp.Status)}
	}
}

// uploadAndPoll submits a file for analysis and polls for the verdict until
// the context expires, in which case the scan is reported as pending
func (c *Client) uploadAndPoll(ctx context.Context, sha256 string, content []byte) *Scan {
	analysisID, err := c.uploadFile(ctx, content)
	if err != nil {
		return &Scan{Status: "error", Error: fmt.Sprintf("VirusTotal upload failed: %v", err)}
	}

	pending := &Scan{
		Status:    "pending",
		Permalink: "https://www.virustotal.com/gui/file/" + sha256,
	}

	for {
		select {
		case <-ctx.Done():
			return pending
		case <-time.After(c.pollInterval):
		}

		scan, completed := c.pollAnalysis(ctx, analysisID, sha256)
		if completed {
			return scan
		}
	}
}

func (c *Client) uploadFile(ctx context.Context, content []byte) (string, error) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	fileWriter, err := writer.CreateFormFile("file", "attachment")
	if err != nil {
		return "", err
	}
	if _, err := fileWriter.Write(content); err != nil {
		return "", err
	}
	if err := writer.Close(); err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/files", &body)
	if err != nil {
		return "", err
	}
	req.Header.Set("x-apikey", c.apiKey)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		responseBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", fmt.Errorf("unexpected status %s: %s", resp.Status, responseBody)
	}

	var payload struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", err
	}
	return payload.Data.ID, nil
}

// pollAnalysis fetches an analysis status; completed is false while the
// analysis is still queued or running
func (c *Client) pollAnalysis(ctx context.Context, analysisID, sha256 string) (scan *Scan, completed bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/analyses/"+analysisID, nil)
	if err != nil {
		return &Scan{Status: "error", Error: err.Error()}, true
	}
	req.Header.Set("x-apikey", c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		// Transient failure: keep polling until the context expires
		return nil, false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, false
	}

	var payload struct {
		Data struct {
			Attributes struct {
				Status string        `json:"status"`
				Stats  analysisStats `json:"stats"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return &Scan{Status: "error", Error: fmt.Sprintf("failed to decode VirusTotal analysis: %v", err)}, true
	}

	if payload.Data.Attributes.Status != "completed" {
		return nil, false
	}
	return payload.Data.Attributes.Stats.toScan(sha256), true
}
