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

package app

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"strings"

	"github.com/google/uuid"

	"git.happydns.org/happyDeliver/internal/config"
	"git.happydns.org/happyDeliver/pkg/analyzer"
)

// RunAnalyzer runs the standalone email analyzer (from stdin)
func RunAnalyzer(cfg *config.Config, args []string, reader io.Reader, writer io.Writer) error {
	// Parse command-line flags
	fs := flag.NewFlagSet("analyze", flag.ExitOnError)
	jsonOutput := fs.Bool("json", false, "Output results as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if err := cfg.Validate(); err != nil {
		return err
	}

	log.Printf("Email analyzer ready, reading from stdin...")

	// Read email from stdin
	emailData, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("failed to read email from stdin: %w", err)
	}

	// Create analyzer with configuration
	emailAnalyzer := analyzer.NewEmailAnalyzer(cfg)

	// Analyze the email (using a dummy test ID for standalone mode)
	result, err := emailAnalyzer.AnalyzeEmailBytes(emailData, uuid.New())
	if err != nil {
		return fmt.Errorf("failed to analyze email: %w", err)
	}

	log.Printf("Analyzing email from: %s", result.Email.From)

	// Output results
	if *jsonOutput {
		return outputJSON(result, writer)
	}
	return outputHumanReadable(result, emailAnalyzer, writer)
}

// outputJSON outputs the report as JSON
func outputJSON(result *analyzer.AnalysisResult, writer io.Writer) error {
	reportJSON, err := json.MarshalIndent(result.Report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal report: %w", err)
	}
	fmt.Fprintln(writer, string(reportJSON))
	return nil
}

// outputHumanReadable outputs a human-readable summary
func outputHumanReadable(result *analyzer.AnalysisResult, emailAnalyzer *analyzer.EmailAnalyzer, writer io.Writer) error {
	report := result.Report

	// Header with overall score
	fmt.Fprintln(writer, "\n"+strings.Repeat("=", 70))
	fmt.Fprintln(writer, "EMAIL DELIVERABILITY ANALYSIS REPORT")
	fmt.Fprintln(writer, strings.Repeat("=", 70))
	fmt.Fprintf(writer, "\nOverall Score: %d/100 (Grade: %s)\n", report.Score, report.Grade)
	fmt.Fprintf(writer, "Test ID: %s\n", report.TestId)
	fmt.Fprintf(writer, "Generated: %s\n", report.CreatedAt.Format("2006-01-02 15:04:05 MST"))

	// Score Summary
	if report.Summary != nil {
		fmt.Fprintln(writer, "\n"+strings.Repeat("-", 70))
		fmt.Fprintln(writer, "SCORE BREAKDOWN")
		fmt.Fprintln(writer, strings.Repeat("-", 70))

		summary := report.Summary
		fmt.Fprintf(writer, "  DNS Configuration:              %3d%% (%s)\n",
			summary.DnsScore, summary.DnsGrade)
		fmt.Fprintf(writer, "  Authentication:                 %3d%% (%s)\n",
			summary.AuthenticationScore, summary.AuthenticationGrade)
		fmt.Fprintf(writer, "  Blacklist Status:               %3d%% (%s)\n",
			summary.BlacklistScore, summary.BlacklistGrade)
		fmt.Fprintf(writer, "  Header Quality:                 %3d%% (%s)\n",
			summary.HeaderScore, summary.HeaderGrade)
		fmt.Fprintf(writer, "  Spam Score:                     %3d%% (%s)\n",
			summary.SpamScore, summary.SpamGrade)
		fmt.Fprintf(writer, "  Content Quality:                %3d%% (%s)\n",
			summary.ContentScore, summary.ContentGrade)
	}

	// DNS Results
	if report.DnsResults != nil {
		fmt.Fprintln(writer, "\n"+strings.Repeat("-", 70))
		fmt.Fprintln(writer, "DNS CONFIGURATION")
		fmt.Fprintln(writer, strings.Repeat("-", 70))

		dns := report.DnsResults
		fmt.Fprintf(writer, "\nFrom Domain: %s\n", dns.FromDomain)
		if dns.RpDomain != nil && *dns.RpDomain != dns.FromDomain {
			fmt.Fprintf(writer, "Return-Path Domain: %s\n", *dns.RpDomain)
		}

		// MX Records
		if dns.FromMxRecords != nil && len(*dns.FromMxRecords) > 0 {
			fmt.Fprintln(writer, "\n  MX Records (From Domain):")
			for _, mx := range *dns.FromMxRecords {
				status := "✓"
				if !mx.Valid {
					status = "✗"
				}
				fmt.Fprintf(writer, "    %s [%d] %s", status, mx.Priority, mx.Host)
				if mx.Error != nil {
					fmt.Fprintf(writer, " - ERROR: %s", *mx.Error)
				}
				fmt.Fprintln(writer)
			}
		}

		// SPF Records
		if dns.SpfRecords != nil && len(*dns.SpfRecords) > 0 {
			fmt.Fprintln(writer, "\n  SPF Records:")
			for _, spf := range *dns.SpfRecords {
				status := "✓"
				if !spf.Valid {
					status = "✗"
				}
				fmt.Fprintf(writer, "    %s ", status)
				if spf.Domain != nil {
					fmt.Fprintf(writer, "Domain: %s", *spf.Domain)
				}
				if spf.AllQualifier != nil {
					fmt.Fprintf(writer, " (all: %s)", *spf.AllQualifier)
				}
				fmt.Fprintln(writer)
				if spf.Record != nil {
					fmt.Fprintf(writer, "      %s\n", *spf.Record)
				}
				if spf.Error != nil {
					fmt.Fprintf(writer, "      ERROR: %s\n", *spf.Error)
				}
			}
		}

		// DKIM Records
		if dns.DkimRecords != nil && len(*dns.DkimRecords) > 0 {
			fmt.Fprintln(writer, "\n  DKIM Records:")
			for _, dkim := range *dns.DkimRecords {
				status := "✓"
				if !dkim.Valid {
					status = "✗"
				}
				fmt.Fprintf(writer, "    %s Selector: %s, Domain: %s\n", status, dkim.Selector, dkim.Domain)
				if dkim.Record != nil {
					fmt.Fprintf(writer, "      %s\n", *dkim.Record)
				}
				if dkim.Error != nil {
					fmt.Fprintf(writer, "      ERROR: %s\n", *dkim.Error)
				}
			}
		}

		// DMARC Record
		if dns.DmarcRecord != nil {
			fmt.Fprintln(writer, "\n  DMARC Record:")
			status := "✓"
			if !dns.DmarcRecord.Valid {
				status = "✗"
			}
			fmt.Fprintf(writer, "    %s Valid: %t", status, dns.DmarcRecord.Valid)
			if dns.DmarcRecord.Policy != nil {
				fmt.Fprintf(writer, ", Policy: %s", *dns.DmarcRecord.Policy)
			}
			if dns.DmarcRecord.SubdomainPolicy != nil {
				fmt.Fprintf(writer, ", Subdomain Policy: %s", *dns.DmarcRecord.SubdomainPolicy)
			}
			fmt.Fprintln(writer)
			if dns.DmarcRecord.Record != nil {
				fmt.Fprintf(writer, "      %s\n", *dns.DmarcRecord.Record)
			}
			if dns.DmarcRecord.Error != nil {
				fmt.Fprintf(writer, "      ERROR: %s\n", *dns.DmarcRecord.Error)
			}
		}

		// BIMI Record
		if dns.BimiRecord != nil {
			fmt.Fprintln(writer, "\n  BIMI Record:")
			status := "✓"
			if !dns.BimiRecord.Valid {
				status = "✗"
			}
			fmt.Fprintf(writer, "    %s Valid: %t, Selector: %s, Domain: %s\n",
				status, dns.BimiRecord.Valid, dns.BimiRecord.Selector, dns.BimiRecord.Domain)
			if dns.BimiRecord.LogoUrl != nil {
				fmt.Fprintf(writer, "      Logo URL: %s\n", *dns.BimiRecord.LogoUrl)
			}
			if dns.BimiRecord.VmcUrl != nil {
				fmt.Fprintf(writer, "      VMC URL: %s\n", *dns.BimiRecord.VmcUrl)
			}
			if dns.BimiRecord.Record != nil {
				fmt.Fprintf(writer, "      %s\n", *dns.BimiRecord.Record)
			}
			if dns.BimiRecord.Error != nil {
				fmt.Fprintf(writer, "      ERROR: %s\n", *dns.BimiRecord.Error)
			}
		}

		// PTR Records
		if dns.PtrRecords != nil && len(*dns.PtrRecords) > 0 {
			fmt.Fprintln(writer, "\n  PTR (Reverse DNS) Records:")
			for _, ptr := range *dns.PtrRecords {
				fmt.Fprintf(writer, "    %s\n", ptr)
			}
		}

		// DNS Errors
		if dns.Errors != nil && len(*dns.Errors) > 0 {
			fmt.Fprintln(writer, "\n  DNS Errors:")
			for _, err := range *dns.Errors {
				fmt.Fprintf(writer, "    ! %s\n", err)
			}
		}
	}

	// Authentication Results
	if report.Authentication != nil {
		fmt.Fprintln(writer, "\n"+strings.Repeat("-", 70))
		fmt.Fprintln(writer, "AUTHENTICATION RESULTS")
		fmt.Fprintln(writer, strings.Repeat("-", 70))

		auth := report.Authentication

		// SPF
		if auth.Spf != nil {
			fmt.Fprintf(writer, "\n  SPF: %s", strings.ToUpper(string(auth.Spf.Result)))
			if auth.Spf.Domain != nil {
				fmt.Fprintf(writer, " (domain: %s)", *auth.Spf.Domain)
			}
			if auth.Spf.Details != nil {
				fmt.Fprintf(writer, "\n    Details: %s", *auth.Spf.Details)
			}
			fmt.Fprintln(writer)
		}

		// DKIM
		if auth.Dkim != nil && len(*auth.Dkim) > 0 {
			fmt.Fprintln(writer, "\n  DKIM:")
			for i, dkim := range *auth.Dkim {
				fmt.Fprintf(writer, "    [%d] %s", i+1, strings.ToUpper(string(dkim.Result)))
				if dkim.Domain != nil {
					fmt.Fprintf(writer, " (domain: %s", *dkim.Domain)
					if dkim.Selector != nil {
						fmt.Fprintf(writer, ", selector: %s", *dkim.Selector)
					}
					fmt.Fprintf(writer, ")")
				}
				if dkim.Details != nil {
					fmt.Fprintf(writer, "\n      Details: %s", *dkim.Details)
				}
				fmt.Fprintln(writer)
			}
		}

		// DMARC
		if auth.Dmarc != nil {
			fmt.Fprintf(writer, "\n  DMARC: %s", strings.ToUpper(string(auth.Dmarc.Result)))
			if auth.Dmarc.Domain != nil {
				fmt.Fprintf(writer, " (domain: %s)", *auth.Dmarc.Domain)
			}
			if auth.Dmarc.Details != nil {
				fmt.Fprintf(writer, "\n    Details: %s", *auth.Dmarc.Details)
			}
			fmt.Fprintln(writer)
		}

		// ARC
		if auth.Arc != nil {
			fmt.Fprintf(writer, "\n  ARC: %s", strings.ToUpper(string(auth.Arc.Result)))
			if auth.Arc.ChainLength != nil {
				fmt.Fprintf(writer, " (chain length: %d)", *auth.Arc.ChainLength)
			}
			if auth.Arc.ChainValid != nil {
				fmt.Fprintf(writer, " [valid: %t]", *auth.Arc.ChainValid)
			}
			if auth.Arc.Details != nil {
				fmt.Fprintf(writer, "\n    Details: %s", *auth.Arc.Details)
			}
			fmt.Fprintln(writer)
		}

		// BIMI
		if auth.Bimi != nil {
			fmt.Fprintf(writer, "\n  BIMI: %s", strings.ToUpper(string(auth.Bimi.Result)))
			if auth.Bimi.Domain != nil {
				fmt.Fprintf(writer, " (domain: %s)", *auth.Bimi.Domain)
			}
			if auth.Bimi.Details != nil {
				fmt.Fprintf(writer, "\n    Details: %s", *auth.Bimi.Details)
			}
			fmt.Fprintln(writer)
		}

		// IP Reverse
		if auth.Iprev != nil {
			fmt.Fprintf(writer, "\n  IP Reverse DNS: %s", strings.ToUpper(string(auth.Iprev.Result)))
			if auth.Iprev.Ip != nil {
				fmt.Fprintf(writer, " (ip: %s", *auth.Iprev.Ip)
				if auth.Iprev.Hostname != nil {
					fmt.Fprintf(writer, " -> %s", *auth.Iprev.Hostname)
				}
				fmt.Fprintf(writer, ")")
			}
			if auth.Iprev.Details != nil {
				fmt.Fprintf(writer, "\n    Details: %s", *auth.Iprev.Details)
			}
			fmt.Fprintln(writer)
		}
	}

	// Blacklist Results
	if report.Blacklists != nil && len(*report.Blacklists) > 0 {
		fmt.Fprintln(writer, "\n"+strings.Repeat("-", 70))
		fmt.Fprintln(writer, "BLACKLIST CHECKS")
		fmt.Fprintln(writer, strings.Repeat("-", 70))

		totalChecks := 0
		totalListed := 0
		for ip, checks := range *report.Blacklists {
			totalChecks += len(checks)
			fmt.Fprintf(writer, "\n  IP Address: %s\n", ip)
			for _, check := range checks {
				status := "✓"
				if check.Listed {
					status = "✗"
					totalListed++
				}
				fmt.Fprintf(writer, "    %s %s", status, check.Rbl)
				if check.Listed {
					fmt.Fprintf(writer, " - LISTED")
					if check.Response != nil {
						fmt.Fprintf(writer, " (%s)", *check.Response)
					}
				} else {
					fmt.Fprintf(writer, " - OK")
				}
				fmt.Fprintln(writer)
				if check.Error != nil {
					fmt.Fprintf(writer, "      ERROR: %s\n", *check.Error)
				}
			}
		}
		fmt.Fprintf(writer, "\n  Summary: %d/%d blacklists triggered\n", totalListed, totalChecks)
	}

	// Header Analysis
	if report.HeaderAnalysis != nil {
		fmt.Fprintln(writer, "\n"+strings.Repeat("-", 70))
		fmt.Fprintln(writer, "HEADER ANALYSIS")
		fmt.Fprintln(writer, strings.Repeat("-", 70))

		header := report.HeaderAnalysis

		// Domain Alignment
		if header.DomainAlignment != nil {
			fmt.Fprintln(writer, "\n  Domain Alignment:")
			align := header.DomainAlignment
			if align.FromDomain != nil {
				fmt.Fprintf(writer, "    From Domain: %s", *align.FromDomain)
				if align.FromOrgDomain != nil {
					fmt.Fprintf(writer, " (org: %s)", *align.FromOrgDomain)
				}
				fmt.Fprintln(writer)
			}
			if align.ReturnPathDomain != nil {
				fmt.Fprintf(writer, "    Return-Path Domain: %s", *align.ReturnPathDomain)
				if align.ReturnPathOrgDomain != nil {
					fmt.Fprintf(writer, " (org: %s)", *align.ReturnPathOrgDomain)
				}
				fmt.Fprintln(writer)
			}
			if align.Aligned != nil {
				fmt.Fprintf(writer, "    Strict Alignment: %t\n", *align.Aligned)
			}
			if align.RelaxedAligned != nil {
				fmt.Fprintf(writer, "    Relaxed Alignment: %t\n", *align.RelaxedAligned)
			}
			if align.Issues != nil && len(*align.Issues) > 0 {
				fmt.Fprintln(writer, "    Issues:")
				for _, issue := range *align.Issues {
					fmt.Fprintf(writer, "      - %s\n", issue)
				}
			}
		}

		// Required/Important Headers
		if header.Headers != nil {
			fmt.Fprintln(writer, "\n  Standard Headers:")
			importantHeaders := []string{"from", "to", "subject", "date", "message-id", "dkim-signature"}
			for _, hdrName := range importantHeaders {
				if hdr, ok := (*header.Headers)[hdrName]; ok {
					status := "✗"
					if hdr.Present {
						status = "✓"
					}
					fmt.Fprintf(writer, "    %s %s: ", status, strings.ToUpper(hdrName))
					if hdr.Present {
						if hdr.Valid != nil && !*hdr.Valid {
							fmt.Fprintf(writer, "INVALID")
						} else {
							fmt.Fprintf(writer, "OK")
						}
						if hdr.Importance != nil {
							fmt.Fprintf(writer, " [%s]", *hdr.Importance)
						}
					} else {
						fmt.Fprintf(writer, "MISSING")
					}
					fmt.Fprintln(writer)
					if hdr.Issues != nil && len(*hdr.Issues) > 0 {
						for _, issue := range *hdr.Issues {
							fmt.Fprintf(writer, "      - %s\n", issue)
						}
					}
				}
			}
		}

		// Header Issues
		if header.Issues != nil && len(*header.Issues) > 0 {
			fmt.Fprintln(writer, "\n  Header Issues:")
			for _, issue := range *header.Issues {
				fmt.Fprintf(writer, "    [%s] %s: %s\n",
					strings.ToUpper(string(issue.Severity)), issue.Header, issue.Message)
				if issue.Advice != nil {
					fmt.Fprintf(writer, "      Advice: %s\n", *issue.Advice)
				}
			}
		}

		// Received Chain
		if header.ReceivedChain != nil && len(*header.ReceivedChain) > 0 {
			fmt.Fprintln(writer, "\n  Email Path (Received Chain):")
			for i, hop := range *header.ReceivedChain {
				fmt.Fprintf(writer, "    [%d] ", i+1)
				if hop.From != nil {
					fmt.Fprintf(writer, "%s", *hop.From)
					if hop.Ip != nil {
						fmt.Fprintf(writer, " (%s)", *hop.Ip)
					}
				}
				if hop.By != nil {
					fmt.Fprintf(writer, " -> %s", *hop.By)
				}
				fmt.Fprintln(writer)
				if hop.Timestamp != nil {
					fmt.Fprintf(writer, "        Time: %s\n", hop.Timestamp.Format("2006-01-02 15:04:05 MST"))
				}
			}
		}
	}

	// SpamAssassin Results
	if report.Spamassassin != nil {
		fmt.Fprintln(writer, "\n"+strings.Repeat("-", 70))
		fmt.Fprintln(writer, "SPAMASSASSIN ANALYSIS")
		fmt.Fprintln(writer, strings.Repeat("-", 70))

		sa := report.Spamassassin
		fmt.Fprintf(writer, "\n  Score: %.2f / %.2f", sa.Score, sa.RequiredScore)
		if sa.IsSpam {
			fmt.Fprintf(writer, " (SPAM)")
		} else {
			fmt.Fprintf(writer, " (HAM)")
		}
		fmt.Fprintln(writer)

		if sa.Version != nil {
			fmt.Fprintf(writer, "  Version: %s\n", *sa.Version)
		}

		if len(sa.TestDetails) > 0 {
			fmt.Fprintln(writer, "\n  Triggered Tests:")
			for _, test := range sa.TestDetails {
				scoreStr := "+"
				if test.Score < 0 {
					scoreStr = ""
				}
				fmt.Fprintf(writer, "    [%s%.2f] %s", scoreStr, test.Score, test.Name)
				if test.Description != nil {
					fmt.Fprintf(writer, "\n            %s", *test.Description)
				}
				fmt.Fprintln(writer)
			}
		}
	}

	// Content Analysis
	if report.ContentAnalysis != nil {
		fmt.Fprintln(writer, "\n"+strings.Repeat("-", 70))
		fmt.Fprintln(writer, "CONTENT ANALYSIS")
		fmt.Fprintln(writer, strings.Repeat("-", 70))

		content := report.ContentAnalysis

		// Basic content info
		fmt.Fprintln(writer, "\n  Content Structure:")
		if content.HasPlaintext != nil {
			fmt.Fprintf(writer, "    Has Plaintext: %t\n", *content.HasPlaintext)
		}
		if content.HasHtml != nil {
			fmt.Fprintf(writer, "    Has HTML: %t\n", *content.HasHtml)
		}
		if content.TextToImageRatio != nil {
			fmt.Fprintf(writer, "    Text-to-Image Ratio: %.2f\n", *content.TextToImageRatio)
		}

		// Unsubscribe
		if content.HasUnsubscribeLink != nil {
			fmt.Fprintf(writer, "    Has Unsubscribe Link: %t\n", *content.HasUnsubscribeLink)
			if *content.HasUnsubscribeLink && content.UnsubscribeMethods != nil && len(*content.UnsubscribeMethods) > 0 {
				fmt.Fprintf(writer, "    Unsubscribe Methods: ")
				for i, method := range *content.UnsubscribeMethods {
					if i > 0 {
						fmt.Fprintf(writer, ", ")
					}
					fmt.Fprintf(writer, "%s", method)
				}
				fmt.Fprintln(writer)
			}
		}

		// Links
		if content.Links != nil && len(*content.Links) > 0 {
			fmt.Fprintf(writer, "\n  Links (%d total):\n", len(*content.Links))
			for _, link := range *content.Links {
				status := ""
				switch link.Status {
				case "valid":
					status = "✓"
				case "broken":
					status = "✗"
				case "suspicious":
					status = "⚠"
				case "redirected":
					status = "→"
				case "timeout":
					status = "⏱"
				}
				fmt.Fprintf(writer, "    %s [%s] %s", status, link.Status, link.Url)
				if link.HttpCode != nil {
					fmt.Fprintf(writer, " (HTTP %d)", *link.HttpCode)
				}
				fmt.Fprintln(writer)
				if link.RedirectChain != nil && len(*link.RedirectChain) > 0 {
					fmt.Fprintln(writer, "      Redirect chain:")
					for _, url := range *link.RedirectChain {
						fmt.Fprintf(writer, "        -> %s\n", url)
					}
				}
			}
		}

		// Images
		if content.Images != nil && len(*content.Images) > 0 {
			fmt.Fprintf(writer, "\n  Images (%d total):\n", len(*content.Images))
			missingAlt := 0
			trackingPixels := 0
			for _, img := range *content.Images {
				if !img.HasAlt {
					missingAlt++
				}
				if img.IsTrackingPixel != nil && *img.IsTrackingPixel {
					trackingPixels++
				}
			}
			fmt.Fprintf(writer, "    Images with ALT text: %d/%d\n",
				len(*content.Images)-missingAlt, len(*content.Images))
			if trackingPixels > 0 {
				fmt.Fprintf(writer, "    Tracking pixels detected: %d\n", trackingPixels)
			}
		}

		// HTML Issues
		if content.HtmlIssues != nil && len(*content.HtmlIssues) > 0 {
			fmt.Fprintln(writer, "\n  Content Issues:")
			for _, issue := range *content.HtmlIssues {
				fmt.Fprintf(writer, "    [%s] %s: %s\n",
					strings.ToUpper(string(issue.Severity)), issue.Type, issue.Message)
				if issue.Location != nil {
					fmt.Fprintf(writer, "      Location: %s\n", *issue.Location)
				}
				if issue.Advice != nil {
					fmt.Fprintf(writer, "      Advice: %s\n", *issue.Advice)
				}
			}
		}
	}

	// Footer
	fmt.Fprintln(writer, "\n"+strings.Repeat("=", 70))
	fmt.Fprintf(writer, "Report generated by happyDeliver - https://happydeliver.org\n")
	fmt.Fprintln(writer, strings.Repeat("=", 70))

	return nil
}
