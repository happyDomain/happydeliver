// This file is part of the happyDeliver (R) project.
// Copyright (c) 2025-2026 happyDomain
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

// Package rspamd talks to an rspamd daemon: it hands it a message and reads
// back the verdict, in the shape the rest of happyDeliver reasons about.
//
// What a verdict is worth - which symbols weigh on a score, what a sender is
// told about them - is a judgement, and lives with the analysis that makes it.
package rspamd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
)

const (
	// rspamdScanTimeout is how long a scan may take when no timeout was
	// configured.
	rspamdScanTimeout = 10 * time.Second

	// rspamdScanReplyLimit caps what is read of a reply. A scan is aimed at
	// whatever address the operator configured, and a misconfigured one
	// answering an endless stream must not be able to exhaust this process.
	rspamdScanReplyLimit = 8 << 20

	// rspamdScanErrorInterval is how often a scan that keeps failing is
	// allowed to say so. Every upload triggers a scan, so an unreachable
	// rspamd would otherwise write a line per analysis.
	rspamdScanErrorInterval = time.Minute
)

// checkReply is what /checkv2 answers. Only the fields read here are
// declared; rspamd sends a good deal more (urls, emails, milter directives)
// that says nothing about the content.
type checkReply struct {
	// IsSkipped is true when rspamd's own settings told it not to look at this
	// message, in which case the empty result it returns is not a verdict.
	IsSkipped bool `json:"is_skipped"`

	Score         float32 `json:"score"`
	RequiredScore float32 `json:"required_score"`
	Action        string  `json:"action"`

	Symbols map[string]struct {
		Name        string   `json:"name"`
		Score       float32  `json:"score"`
		Options     []string `json:"options"`
		Description string   `json:"description"`
	} `json:"symbols"`
}

// Scanner asks an rspamd instance what it makes of a message, over the
// /checkv2 endpoint of its normal worker, the one an MTA talks to, on 11333
// by default. The controller on 11334 answers the same endpoint but behind its
// password, so it is not what this points at.
//
// It exists for the messages this instance did not receive itself. A message
// delivered over SMTP is annotated by the milter on its way in, and those
// headers are what AnalyzeRspamd reads; a .eml the user uploaded carries no
// annotation of ours, so the only way to learn what a filter makes of its
// content is to ask one.
//
// The scan is deliberately envelope-less: no IP, HELO or MAIL FROM header is
// sent. An uploaded file has no SMTP connection behind it, and reconstructing
// one from the Received headers is exactly what this project refuses to do
// elsewhere; it is why the XCLIENT relay exists. Everything rspamd derives
// from a connection is therefore wrong in the reply, sometimes by a wide
// margin: a clean message with no connection collects some twenty points of
// artefacts (ONCE_RECEIVED_STRICT, VIOLATED_DIRECT_SPF,
// HFILTER_HOSTNAME_UNKNOWN, RDNS_NONE, AUTH_NA and their kin). Only the
// symbols the advice catalogue knows are read out of it, and it never touches
// the spam score.
type Scanner struct {
	url     string
	client  *http.Client
	symbols map[string]string

	// mu guards the throttling of the error log.
	mu         sync.Mutex
	lastErr    string
	lastLogged time.Time
	suppressed int
}

// NewScanner returns a scanner posting to the given rspamd worker, or
// nil when no URL was configured, which is the default, and what makes
// this a feature an operator turns on rather than one they discover.
//
// A nil scanner is usable: Scan returns nothing. The caller has no branch to
// write.
func NewScanner(url string, timeout time.Duration, symbols map[string]string) *Scanner {
	if strings.TrimSpace(url) == "" {
		return nil
	}
	if timeout <= 0 {
		timeout = rspamdScanTimeout
	}

	return &Scanner{
		url:     strings.TrimRight(strings.TrimSpace(url), "/") + "/checkv2",
		client:  &http.Client{Timeout: timeout},
		symbols: symbols,
	}
}

// Scan submits the message as it arrived and returns what rspamd made of it,
// or nil when nothing usable came back.
//
// Every failure is a nil result and a log line, never an error: a report is
// worth producing without the filter's opinion, and an operator whose rspamd
// is down should not have every analysis fail on them.
//
// The bytes must be the message as received. Re-serialising it from the parsed
// parts would change the transfer encodings and the MIME boundaries, and
// several of the symbols worth reading (MIME_BASE64_TEXT, the excess-encoding
// family, SUSPICIOUS_BOUNDARY) are about exactly those.
func (s *Scanner) Scan(raw []byte) *model.RspamdResult {
	if s == nil || len(raw) == 0 {
		return nil
	}

	// A Reader rather than a raw slice, so net/http sets Content-Length: some
	// versions of the controller handle a chunked body poorly.
	req, err := http.NewRequest(http.MethodPost, s.url, bytes.NewReader(raw))
	if err != nil {
		s.logFailure(fmt.Errorf("building the request: %w", err))
		return nil
	}
	req.Header.Set("Content-Type", "message/rfc822")
	req.ContentLength = int64(len(raw))

	resp, err := s.client.Do(req)
	if err != nil {
		s.logFailure(err)
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, rspamdScanReplyLimit))
	if err != nil {
		s.logFailure(fmt.Errorf("reading the reply: %w", err))
		return nil
	}

	if resp.StatusCode != http.StatusOK {
		// An instance with a controller password answers 403 with a line of
		// text. Quote a little of it rather than trying to parse it: the
		// operator needs to read what it said.
		s.logFailure(fmt.Errorf("answered %s: %s", resp.Status, firstLine(body, 200)))
		return nil
	}

	var reply checkReply
	if err := json.Unmarshal(body, &reply); err != nil {
		s.logFailure(fmt.Errorf("reply is not the JSON of a scan: %w", err))
		return nil
	}

	// Settings told rspamd to leave this message alone, so the empty result it
	// returned is not an opinion about the content.
	if reply.IsSkipped {
		return nil
	}

	return s.result(reply)
}

// result turns a reply into the result the rest of the analysis speaks.
//
// Every field of the protocol is carried across, not only the symbols the
// advice catalogue reads today: this is the protocol's translation, and what a
// caller makes of a score it cannot compare to anything is its own business.
func (s *Scanner) result(reply checkReply) *model.RspamdResult {
	result := &model.RspamdResult{
		Score:   reply.Score,
		Symbols: make(map[string]model.SpamTestDetail, len(reply.Symbols)),
	}

	// A threshold of zero or less is not one. The bundled image switches every
	// action off so that rspamd annotates without ever rejecting, and then
	// reports no usable required_score, the same reason the header path
	// ignores it.
	if reply.RequiredScore > 0 {
		result.Threshold = utils.PtrTo(reply.RequiredScore)
	}

	if action := strings.TrimSpace(reply.Action); action != "" {
		result.Action = utils.PtrTo(action)
		// The schema defines is_spam by the action, which is the one thing
		// here that does not depend on a threshold this instance may have
		// switched off.
		result.IsSpam = action == "reject" || action == "soft reject"
	}

	for name, symbol := range reply.Symbols {
		if name == "" {
			continue
		}

		detail := model.SpamTestDetail{Name: name, Score: symbol.Score}

		// rspamd sends the options as a list, while the header path parses
		// them out of "SYMBOL(score)[a,b]". Joining them the same way keeps
		// one shape for both, so nothing downstream has to know which path a
		// result came through.
		if options := nonEmpty(symbol.Options); len(options) > 0 {
			detail.Params = utils.PtrTo(strings.Join(options, ", "))
		}

		// The reply's own description is preferred: it comes from the instance
		// that raised the symbol, so it matches its configuration, where the
		// embedded catalogue only matches the version it was dumped from.
		switch {
		case strings.TrimSpace(symbol.Description) != "":
			detail.Description = utils.PtrTo(symbol.Description)
		case s.symbols != nil:
			if description, ok := s.symbols[name]; ok {
				detail.Description = utils.PtrTo(description)
			}
		}

		result.Symbols[name] = detail
	}

	return result
}

// logFailure reports a scan that did not happen, at most once per interval.
// What it suppressed in between is counted, so a log does not read as a single
// hiccup when rspamd has been down for an hour.
func (s *Scanner) logFailure(err error) {
	message := err.Error()

	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	if message == s.lastErr && now.Sub(s.lastLogged) < rspamdScanErrorInterval {
		s.suppressed++
		return
	}

	if s.suppressed > 0 {
		log.Printf("rspamd scan failed: %v (and %d more like the previous one)", err, s.suppressed)
	} else {
		log.Printf("rspamd scan failed: %v", err)
	}

	s.lastErr = message
	s.lastLogged = now
	s.suppressed = 0
}

// nonEmpty drops the blank entries rspamd sends for a symbol raised without
// options, so that a symbol with nothing to add carries no location.
func nonEmpty(values []string) []string {
	kept := make([]string, 0, len(values))
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			kept = append(kept, trimmed)
		}
	}

	return kept
}

// firstLine quotes the beginning of a reply that was not a scan, bounded, for
// a log line.
func firstLine(body []byte, limit int) string {
	text := strings.TrimSpace(string(body))
	if index := strings.IndexAny(text, "\r\n"); index >= 0 {
		text = text[:index]
	}
	if len(text) > limit {
		return text[:limit] + "…"
	}
	if text == "" {
		return "(empty reply)"
	}

	return text
}
