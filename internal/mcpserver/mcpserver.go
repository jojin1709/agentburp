// Package mcpserver implements a minimal JSON-RPC-over-stdio server exposing
// agentburp's core actions as callable "tools", so an MCP-aware agent (e.g.
// Claude) can drive the CLI programmatically instead of shelling out.
//
// This is a deliberately small hand-rolled implementation (request/response
// framed as newline-delimited JSON) rather than a full MCP SDK integration,
// so it has zero extra dependencies and is easy to audit. Swap in an
// official MCP SDK later if you want full protocol compliance.
package mcpserver

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/jojin1709/agentburp/internal/db"
	"github.com/jojin1709/agentburp/internal/diff"
	"github.com/jojin1709/agentburp/internal/export"
	"github.com/jojin1709/agentburp/internal/fuzzer"
	"github.com/jojin1709/agentburp/internal/model"
	"github.com/jojin1709/agentburp/internal/repeater"
	"github.com/jojin1709/agentburp/internal/oast"
	"github.com/jojin1709/agentburp/internal/report"
	"github.com/jojin1709/agentburp/internal/scanner"
	"github.com/jojin1709/agentburp/internal/scope"
	"github.com/jojin1709/agentburp/internal/sitemap"
)

type Request struct {
	ID     int             `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

type Response struct {
	ID     int         `json:"id"`
	Result interface{} `json:"result,omitempty"`
	Error  string      `json:"error,omitempty"`
}

type Server struct {
	DB    *db.DB
	Guard *scope.Guard
	Workspace string
}

// Serve reads newline-delimited JSON-RPC requests from stdin and writes
// responses to stdout. Each line is one request/response.
func (s *Server) Serve() error {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1024*1024), 10*1024*1024)
	out := json.NewEncoder(os.Stdout)

	for in.Scan() {
		var req Request
		if err := json.Unmarshal(in.Bytes(), &req); err != nil {
			out.Encode(Response{Error: fmt.Sprintf("bad request: %v", err)})
			continue
		}
		resp := s.handle(req)
		out.Encode(resp)
	}
	return in.Err()
}

func (s *Server) handle(req Request) Response {
	switch req.Method {
	case "tools/list":
		return Response{ID: req.ID, Result: []string{
			"history.search", "repeat", "fuzz", "diff", "scan", "sitemap", "export.curl", "export.har", "scope.test", "report", "oast.token", "oast.poll", "ws.list",
		}}

	case "history.search":
		var p struct {
			Host   string `json:"host"`
			Status int    `json:"status"`
			Limit  int    `json:"limit"`
		}
		json.Unmarshal(req.Params, &p)
		entries, err := s.DB.Search(db.SearchOpts{Workspace: s.Workspace, Host: p.Host, Status: p.Status, Limit: p.Limit})
		if err != nil {
			return Response{ID: req.ID, Error: err.Error()}
		}
		return Response{ID: req.ID, Result: entries}

	case "repeat":
		var p struct {
			ID         int64             `json:"id"`
			SetHeaders map[string]string `json:"set_headers"`
			Body       string            `json:"body"`
		}
		json.Unmarshal(req.Params, &p)
		e, err := repeater.Replay(s.DB, s.Guard, p.ID, repeater.Options{
			SetHeaders: p.SetHeaders, Body: p.Body, Workspace: s.Workspace,
		})
		if err != nil {
			return Response{ID: req.ID, Error: err.Error()}
		}
		return Response{ID: req.ID, Result: e}

	case "fuzz":
		var p struct {
			BaselineID    int64  `json:"baseline_id"`
			Param         string `json:"param"`
			WordlistPath  string `json:"wordlist_path"`
			RangeFrom     int    `json:"range_from"`
			RangeTo       int    `json:"range_to"`
			OnlyAnomalies bool   `json:"only_anomalies"`
		}
		json.Unmarshal(req.Params, &p)
		rows, err := fuzzer.Run(s.DB, s.Guard, p.BaselineID, fuzzer.Options{
			Param: p.Param, WordlistPath: p.WordlistPath,
			NumRangeFrom: p.RangeFrom, NumRangeTo: p.RangeTo,
			OnlyAnomalies: p.OnlyAnomalies, Workspace: s.Workspace,
		})
		if err != nil {
			return Response{ID: req.ID, Error: err.Error()}
		}
		return Response{ID: req.ID, Result: rows}

	case "diff":
		var p struct {
			A int64 `json:"a"`
			B int64 `json:"b"`
		}
		json.Unmarshal(req.Params, &p)
		ea, err := s.DB.GetEntry(p.A)
		if err != nil {
			return Response{ID: req.ID, Error: err.Error()}
		}
		eb, err := s.DB.GetEntry(p.B)
		if err != nil {
			return Response{ID: req.ID, Error: err.Error()}
		}
		return Response{ID: req.ID, Result: diff.Compare(ea, eb)}

	case "scan":
		var p struct {
			EntryID int64 `json:"entry_id"`
		}
		json.Unmarshal(req.Params, &p)
		e, err := s.DB.GetEntry(p.EntryID)
		if err != nil {
			return Response{ID: req.ID, Error: err.Error()}
		}
		findings := scanner.RunAll(e)
		for _, f := range findings {
			s.DB.InsertFinding(f)
		}
		return Response{ID: req.ID, Result: findings}

	case "sitemap":
		var p struct {
			Host  string `json:"host"`
			Limit int    `json:"limit"`
		}
		json.Unmarshal(req.Params, &p)
		if p.Limit == 0 {
			p.Limit = 1000
		}
		entries, err := s.DB.Search(db.SearchOpts{Workspace: s.Workspace, Host: p.Host, Limit: p.Limit})
		if err != nil {
			return Response{ID: req.ID, Error: err.Error()}
		}
		return Response{ID: req.ID, Result: sitemap.Build(entries)}

	case "export.curl":
		var p struct {
			ID int64 `json:"id"`
		}
		json.Unmarshal(req.Params, &p)
		e, err := s.DB.GetEntry(p.ID)
		if err != nil {
			return Response{ID: req.ID, Error: err.Error()}
		}
		return Response{ID: req.ID, Result: export.ToCurl(e)}

	case "export.har":
		var p struct {
			ID    int64 `json:"id"`
			Limit int   `json:"limit"`
		}
		json.Unmarshal(req.Params, &p)
		var entries []*model.Entry
		if p.ID != 0 {
			e, err := s.DB.GetEntry(p.ID)
			if err != nil {
				return Response{ID: req.ID, Error: err.Error()}
			}
			entries = []*model.Entry{e}
		} else {
			if p.Limit == 0 {
				p.Limit = 100
			}
			var err error
			entries, err = s.DB.Search(db.SearchOpts{Workspace: s.Workspace, Limit: p.Limit})
			if err != nil {
				return Response{ID: req.ID, Error: err.Error()}
			}
		}
		data, err := export.ToHAR(entries)
		if err != nil {
			return Response{ID: req.ID, Error: err.Error()}
		}
		return Response{ID: req.ID, Result: string(data)}

	case "scope.test":
		var p struct {
			Target string `json:"target"`
		}
		json.Unmarshal(req.Params, &p)
		host := p.Target
		if strings.Contains(p.Target, "://") {
			if u, err := url.Parse(p.Target); err == nil && u.Host != "" {
				host = u.Host
			}
		}
		allowed, reason := s.Guard.Allowed(host)
		return Response{ID: req.ID, Result: map[string]interface{}{
			"target":  p.Target,
			"host":    host,
			"allowed": allowed,
			"reason":  reason,
		}}

	case "report":
		var p struct {
			EntryID   int64  `json:"entry_id"`
			Format    string `json:"format"`
			FindingID int64  `json:"finding_id"`
		}
		json.Unmarshal(req.Params, &p)
		e, err := s.DB.GetEntry(p.EntryID)
		if err != nil {
			return Response{ID: req.ID, Error: err.Error()}
		}
		findings, err := s.DB.ListFindings(s.Workspace, "")
		if err != nil {
			return Response{ID: req.ID, Error: err.Error()}
		}
		var f *model.Finding
		for _, cand := range findings {
			if cand.EntryID == p.EntryID && (p.FindingID == 0 || cand.ID == p.FindingID) {
				f = cand
				break
			}
		}
		if f == nil {
			return Response{ID: req.ID, Error: fmt.Sprintf("no finding found for entry %d", p.EntryID)}
		}
		fmtChoice := report.Format(p.Format)
		if fmtChoice == "" {
			fmtChoice = report.Generic
		}
		return Response{ID: req.ID, Result: report.Generate(fmtChoice, f, e)}

	case "oast.token":
		var p struct {
			Server string `json:"server"`
		}
		json.Unmarshal(req.Params, &p)
		if p.Server == "" {
			p.Server = "http://127.0.0.1:9998"
		}
		tok, cbURL, err := oast.RequestToken(p.Server)
		if err != nil {
			tok = oast.GenerateToken()
			cbURL = fmt.Sprintf("%s/c/%s", strings.TrimRight(p.Server, "/"), tok)
		}
		return Response{ID: req.ID, Result: map[string]string{
			"token": tok,
			"url":   cbURL,
		}}

	case "oast.poll":
		var p struct {
			Token  string `json:"token"`
			Server string `json:"server"`
		}
		json.Unmarshal(req.Params, &p)
		if p.Server == "" {
			p.Server = "http://127.0.0.1:9998"
		}
		interactions, err := oast.Poll(p.Server, p.Token)
		if err != nil {
			return Response{ID: req.ID, Error: err.Error()}
		}
		return Response{ID: req.ID, Result: interactions}

	case "ws.list":
		var p struct {
			EntryID int64 `json:"entry_id"`
			Limit   int   `json:"limit"`
		}
		json.Unmarshal(req.Params, &p)
		if p.Limit <= 0 {
			p.Limit = 50
		}
		frames, err := s.DB.SearchWSFrames(s.Workspace, p.EntryID, p.Limit)
		if err != nil {
			return Response{ID: req.ID, Error: err.Error()}
		}
		return Response{ID: req.ID, Result: frames}

	default:
		return Response{ID: req.ID, Error: "unknown method: " + req.Method}
	}
}
