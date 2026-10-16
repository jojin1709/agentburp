package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jojin1709/agentburp/internal/db"
	"github.com/jojin1709/agentburp/internal/diff"
	"github.com/jojin1709/agentburp/internal/export"
	"github.com/jojin1709/agentburp/internal/fuzzer"
	"github.com/jojin1709/agentburp/internal/mcpserver"
	"github.com/jojin1709/agentburp/internal/model"
	"github.com/jojin1709/agentburp/internal/proxy"
	"github.com/jojin1709/agentburp/internal/repeater"
	"github.com/jojin1709/agentburp/internal/report"
	"github.com/jojin1709/agentburp/internal/scanner"
	"github.com/jojin1709/agentburp/internal/scope"
	"github.com/jojin1709/agentburp/internal/workspace"
)

func openDB() (*db.DB, error) {
	p, err := workspace.DBPath()
	if err != nil {
		return nil, err
	}
	return db.Open(p)
}

func loadScope(path string) (*scope.Config, error) {
	if path == "" || path == "scope.yml" {
		if _, err := os.Stat("scope.yml"); err == nil {
			return scope.Load("scope.yml")
		}
		if exe, err := os.Executable(); err == nil {
			cand := filepath.Join(filepath.Dir(exe), "scope.yml")
			if _, err := os.Stat(cand); err == nil {
				return scope.Load(cand)
			}
		}
		if home, err := os.UserHomeDir(); err == nil {
			cand := filepath.Join(home, ".agentburp", "scope.yml")
			if _, err := os.Stat(cand); err == nil {
				return scope.Load(cand)
			}
		}
		path = "scope.yml"
	}
	return scope.Load(path)
}

func currentWorkspace() string {
	s, err := workspace.Load()
	if err != nil {
		return "default"
	}
	return s.Active
}

func printJSON(v interface{}) {
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(b))
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}

const usage = `agentburp — a CLI, agent-native intercepting proxy & bug bounty toolkit

Only point this at hosts you are authorized to test (see scope.yml / examples/scope.yml).

Usage:
  agentburp proxy start [--addr 127.0.0.1:8888] [--scope scope.yml] [--upstream URL] [--inject-header "Name: Value"]...
  agentburp export [<id>] [--format curl|har] [--out FILE] [--limit N]
  agentburp hist list [--host H] [--method M] [--status N] [--body S] [--limit N]
  agentburp hist show <id>
  agentburp repeat <id> [--set "Header: value"]... [--body B]
  agentburp fuzz <baseline_id> --param NAME (--wordlist FILE | --range-from N --range-to N) [--anomalies] [--confirm]
  agentburp diff <id_a> <id_b>
  agentburp scan <entry_id>
  agentburp report <entry_id> [--format hackerone|bugcrowd|generic] [--finding-id N]
  agentburp workspace use <name>
  agentburp workspace current
  agentburp mcp-serve [--scope scope.yml]

Global:
  --scope PATH   path to scope.yml (default "scope.yml"), accepted by any subcommand
`

func main() {
	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(1)
	}
	args := os.Args[2:]
	switch os.Args[1] {
	case "proxy":
		cmdProxy(args)
	case "export":
		cmdExport(args)
	case "hist":
		cmdHist(args)
	case "repeat":
		cmdRepeat(args)
	case "fuzz":
		cmdFuzz(args)
	case "diff":
		cmdDiff(args)
	case "scan":
		cmdScan(args)
	case "report":
		cmdReport(args)
	case "workspace":
		cmdWorkspace(args)
	case "mcp-serve":
		cmdMCP(args)
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		fmt.Print(usage)
		os.Exit(1)
	}
}

// ---------- shared helpers ----------

type stringList []string

func (s *stringList) String() string { return fmt.Sprint(*s) }
func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func splitHeader(s string) (string, string) {
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			k := s[:i]
			v := s[i+1:]
			for len(v) > 0 && v[0] == ' ' {
				v = v[1:]
			}
			return k, v
		}
	}
	return s, ""
}

// ---------- proxy ----------

func cmdProxy(args []string) {
	if len(args) == 0 || args[0] != "start" {
		fmt.Fprintln(os.Stderr, "usage: agentburp proxy start [--addr 127.0.0.1:8888] [--scope scope.yml] [--upstream URL] [--inject-header \"Name: Value\"]")
		os.Exit(1)
	}
	fs := flag.NewFlagSet("proxy start", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:8888", "listen address")
	scopePath := fs.String("scope", "scope.yml", "path to scope.yml")
	upstream := fs.String("upstream", "", "upstream proxy URL (e.g. http://127.0.0.1:8080)")
	var injectHeaders stringList
	fs.Var(&injectHeaders, "inject-header", `header to inject into outgoing requests, e.g. --inject-header "X-Bug-Bounty: user@platform"`)
	fs.Parse(args[1:])

	cfg, err := loadScope(*scopePath)
	if err != nil {
		fatal(fmt.Errorf("load scope: %w (did you create scope.yml? see examples/scope.yml)", err))
	}
	d, err := openDB()
	if err != nil {
		fatal(err)
	}
	defer d.Close()
	g := scope.NewGuard(cfg)

	headers := map[string]string{}
	for _, h := range injectHeaders {
		k, v := splitHeader(h)
		headers[k] = v
	}

	opts := proxy.Options{
		UpstreamProxy: *upstream,
		InjectHeaders: headers,
	}
	srv := proxy.New(*addr, d, g, currentWorkspace(), opts)
	if err := srv.ListenAndServe(); err != nil {
		fatal(err)
	}
}

// ---------- history ----------

func cmdHist(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: agentburp hist list|show ...")
		os.Exit(1)
	}
	switch args[0] {
	case "list":
		fs := flag.NewFlagSet("hist list", flag.ExitOnError)
		host := fs.String("host", "", "filter by host substring")
		method := fs.String("method", "", "filter by HTTP method")
		status := fs.Int("status", 0, "filter by status code")
		body := fs.String("body", "", "filter by substring in req/resp body")
		limit := fs.Int("limit", 50, "max results")
		fs.Parse(args[1:])

		d, err := openDB()
		if err != nil {
			fatal(err)
		}
		defer d.Close()
		entries, err := d.Search(db.SearchOpts{
			Workspace: currentWorkspace(), Host: *host, Method: *method,
			Status: *status, BodyRegex: *body, Limit: *limit,
		})
		if err != nil {
			fatal(err)
		}
		printJSON(entries)

	case "show":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: agentburp hist show <id>")
			os.Exit(1)
		}
		id, err := strconv.ParseInt(args[1], 10, 64)
		if err != nil {
			fatal(err)
		}
		d, err := openDB()
		if err != nil {
			fatal(err)
		}
		defer d.Close()
		e, err := d.GetEntry(id)
		if err != nil {
			fatal(err)
		}
		printJSON(e)

	default:
		fmt.Fprintln(os.Stderr, "usage: agentburp hist list|show ...")
		os.Exit(1)
	}
}

// ---------- repeat ----------

func cmdRepeat(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, `usage: agentburp repeat <id> [--set "Header: value"]... [--body B]`)
		os.Exit(1)
	}
	id, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil {
		fatal(err)
	}
	fs := flag.NewFlagSet("repeat", flag.ExitOnError)
	var setHeaders stringList
	fs.Var(&setHeaders, "set", `header to set, e.g. --set "Authorization: Bearer xyz"`)
	body := fs.String("body", "", "override request body")
	scopePath := fs.String("scope", "scope.yml", "path to scope.yml")
	fs.Parse(args[1:])

	cfg, err := loadScope(*scopePath)
	if err != nil {
		fatal(err)
	}
	d, err := openDB()
	if err != nil {
		fatal(err)
	}
	defer d.Close()
	g := scope.NewGuard(cfg)

	headers := map[string]string{}
	for _, h := range setHeaders {
		k, v := splitHeader(h)
		headers[k] = v
	}
	e, err := repeater.Replay(d, g, id, repeater.Options{
		SetHeaders: headers, Body: *body, Workspace: currentWorkspace(),
	})
	if err != nil {
		fatal(err)
	}
	printJSON(e)
}

// ---------- fuzz ----------

func cmdFuzz(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: agentburp fuzz <baseline_id> --param NAME (--wordlist FILE | --range-from N --range-to N)")
		os.Exit(1)
	}
	id, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil {
		fatal(err)
	}
	fs := flag.NewFlagSet("fuzz", flag.ExitOnError)
	param := fs.String("param", "", "parameter name to fuzz (required)")
	wordlist := fs.String("wordlist", "", "path to wordlist file")
	from := fs.Int("range-from", 0, "numeric range start")
	to := fs.Int("range-to", 0, "numeric range end")
	onlyAnomalies := fs.Bool("anomalies", true, "only output responses that differ from baseline")
	confirm := fs.Bool("confirm", false, "confirm active operation when safe_mode is on")
	scopePath := fs.String("scope", "scope.yml", "path to scope.yml")
	fs.Parse(args[1:])

	if *param == "" {
		fatal(fmt.Errorf("--param is required"))
	}
	cfg, err := loadScope(*scopePath)
	if err != nil {
		fatal(err)
	}
	if cfg.SafeMode && !*confirm {
		fatal(fmt.Errorf("safe mode is on (scope.yml) — rerun with --confirm to run active fuzzing"))
	}
	d, err := openDB()
	if err != nil {
		fatal(err)
	}
	defer d.Close()
	g := scope.NewGuard(cfg)
	rows, err := fuzzer.Run(d, g, id, fuzzer.Options{
		Param: *param, WordlistPath: *wordlist, NumRangeFrom: *from, NumRangeTo: *to,
		OnlyAnomalies: *onlyAnomalies, Workspace: currentWorkspace(), MaxRequests: 5000,
	})
	if err != nil {
		fatal(err)
	}
	d.LogAudit(&model.AuditEvent{
		Timestamp: time.Now(), Action: "fuzz",
		Reason:    fmt.Sprintf("fuzzed param=%s on baseline=%d (%d results)", *param, id, len(rows)),
		EntryID:   id, Workspace: currentWorkspace(),
	})
	printJSON(rows)
}

// ---------- diff ----------

func cmdDiff(args []string) {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: agentburp diff <id_a> <id_b>")
		os.Exit(1)
	}
	a, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil {
		fatal(err)
	}
	b, err := strconv.ParseInt(args[1], 10, 64)
	if err != nil {
		fatal(err)
	}
	d, err := openDB()
	if err != nil {
		fatal(err)
	}
	defer d.Close()
	ea, err := d.GetEntry(a)
	if err != nil {
		fatal(err)
	}
	eb, err := d.GetEntry(b)
	if err != nil {
		fatal(err)
	}
	printJSON(diff.Compare(ea, eb))
}

// ---------- scan ----------

func cmdScan(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: agentburp scan <entry_id>")
		os.Exit(1)
	}
	id, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil {
		fatal(err)
	}
	d, err := openDB()
	if err != nil {
		fatal(err)
	}
	defer d.Close()
	e, err := d.GetEntry(id)
	if err != nil {
		fatal(err)
	}
	findings := scanner.RunAll(e)
	for _, f := range findings {
		d.InsertFinding(f)
	}
	if len(findings) == 0 {
		fmt.Println("[]")
		fmt.Fprintln(os.Stderr, "// no heuristic matches — this does not mean the endpoint is safe")
		return
	}
	printJSON(findings)
}

// ---------- report ----------

func cmdReport(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: agentburp report <entry_id> [--format hackerone|bugcrowd|generic] [--finding-id N]")
		os.Exit(1)
	}
	id, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil {
		fatal(err)
	}
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	format := fs.String("format", "generic", "hackerone | bugcrowd | generic")
	findingID := fs.Int64("finding-id", 0, "specific finding id (default: latest for entry)")
	fs.Parse(args[1:])

	d, err := openDB()
	if err != nil {
		fatal(err)
	}
	defer d.Close()
	e, err := d.GetEntry(id)
	if err != nil {
		fatal(err)
	}
	findings, err := d.ListFindings(currentWorkspace(), "")
	if err != nil {
		fatal(err)
	}
	var f *model.Finding
	for _, cand := range findings {
		if cand.EntryID == id && (*findingID == 0 || cand.ID == *findingID) {
			f = cand
			break
		}
	}
	if f == nil {
		fatal(fmt.Errorf("no finding found for entry %d — run `agentburp scan %d` first", id, id))
	}
	fmt.Println(report.Generate(report.Format(*format), f, e))
}

// ---------- workspace ----------

func cmdWorkspace(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: agentburp workspace use <name> | agentburp workspace current")
		os.Exit(1)
	}
	switch args[0] {
	case "use":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: agentburp workspace use <name>")
			os.Exit(1)
		}
		if err := workspace.Use(args[1]); err != nil {
			fatal(err)
		}
		fmt.Println("active workspace:", args[1])
	case "current":
		fmt.Println(currentWorkspace())
	default:
		fmt.Fprintln(os.Stderr, "usage: agentburp workspace use <name> | agentburp workspace current")
		os.Exit(1)
	}
}

// ---------- mcp ----------

func cmdMCP(args []string) {
	fs := flag.NewFlagSet("mcp-serve", flag.ExitOnError)
	scopePath := fs.String("scope", "scope.yml", "path to scope.yml")
	fs.Parse(args)

	cfg, err := loadScope(*scopePath)
	if err != nil {
		fatal(err)
	}
	d, err := openDB()
	if err != nil {
		fatal(err)
	}
	defer d.Close()
	g := scope.NewGuard(cfg)
	srv := &mcpserver.Server{DB: d, Guard: g, Workspace: currentWorkspace()}
	if err := srv.Serve(); err != nil {
		fatal(err)
	}
}

// ---------- export ----------

func cmdExport(args []string) {
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	format := fs.String("format", "curl", "export format: curl | har")
	outPath := fs.String("out", "", "write output to file instead of stdout")
	limit := fs.Int("limit", 100, "max entries for har export")
	scopePath := fs.String("scope", "scope.yml", "path to scope.yml")
	_ = scopePath

	var entryID int64
	var nonFlags []string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			if (arg == "-format" || arg == "--format" ||
				arg == "-out" || arg == "--out" ||
				arg == "-limit" || arg == "--limit" ||
				arg == "-scope" || arg == "--scope") && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				fs.Parse([]string{arg, args[i+1]})
				i++
			} else {
				fs.Parse([]string{arg})
			}
		} else {
			nonFlags = append(nonFlags, arg)
		}
	}

	if len(nonFlags) > 0 {
		if id, err := strconv.ParseInt(nonFlags[0], 10, 64); err == nil {
			entryID = id
		}
	}

	d, err := openDB()
	if err != nil {
		fatal(err)
	}
	defer d.Close()

	var outputText string

	switch strings.ToLower(*format) {
	case "curl":
		if entryID == 0 {
			fatal(fmt.Errorf("entry id required for curl export: agentburp export <id> [--format curl]"))
		}
		e, err := d.GetEntry(entryID)
		if err != nil {
			fatal(err)
		}
		outputText = export.ToCurl(e) + "\n"

	case "har":
		var entries []*model.Entry
		if entryID != 0 {
			e, err := d.GetEntry(entryID)
			if err != nil {
				fatal(err)
			}
			entries = []*model.Entry{e}
		} else {
			entries, err = d.Search(db.SearchOpts{
				Workspace: currentWorkspace(),
				Limit:     *limit,
			})
			if err != nil {
				fatal(err)
			}
		}
		data, err := export.ToHAR(entries)
		if err != nil {
			fatal(err)
		}
		outputText = string(data) + "\n"

	default:
		fatal(fmt.Errorf("unsupported format %q, use 'curl' or 'har'", *format))
	}

	if *outPath != "" {
		if err := os.WriteFile(*outPath, []byte(outputText), 0644); err != nil {
			fatal(err)
		}
		fmt.Fprintf(os.Stderr, "exported %s to %s\n", *format, *outPath)
	} else {
		fmt.Print(outputText)
	}
}

