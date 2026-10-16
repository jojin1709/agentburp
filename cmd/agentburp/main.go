package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jojin1709/agentburp/internal/cert"
	"github.com/jojin1709/agentburp/internal/dashboard"
	"github.com/jojin1709/agentburp/internal/db"
	"github.com/jojin1709/agentburp/internal/diff"
	"github.com/jojin1709/agentburp/internal/export"
	"github.com/jojin1709/agentburp/internal/fuzzer"
	"github.com/jojin1709/agentburp/internal/mcpserver"
	"github.com/jojin1709/agentburp/internal/model"
	"github.com/jojin1709/agentburp/internal/oast"
	"github.com/jojin1709/agentburp/internal/proxy"
	"github.com/jojin1709/agentburp/internal/raw"
	"github.com/jojin1709/agentburp/internal/repeater"
	"github.com/jojin1709/agentburp/internal/report"
	"github.com/jojin1709/agentburp/internal/scanner"
	"github.com/jojin1709/agentburp/internal/scope"
	"github.com/jojin1709/agentburp/internal/sitemap"
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
  agentburp proxy start [--addr 127.0.0.1:8888] [--scope scope.yml] [--upstream URL] [--inject-header "Name: Value"]... [--ui] [--quiet]
  agentburp proxy ca [--out-dir DIR]
  agentburp ui [--addr 127.0.0.1:8889] [--scope scope.yml]
  agentburp raw <request_file> [--ssl] [--target host:port]
  agentburp oast start [--addr 127.0.0.1:9998] [--domain DOMAIN]
  agentburp oast token [--server URL]
  agentburp oast poll <token> [--server URL]
  agentburp oast list [--server URL]
  agentburp ws list [--entry-id N] [--limit N]
  agentburp ws show <frame_id>
  agentburp export [<id>] [--format curl|har] [--out FILE] [--limit N]
  agentburp import <file.har> [--workspace W]
  agentburp map [--host H] [--json] [--limit N]
  agentburp scope test <host_or_url> [--scope scope.yml] [--json]
  agentburp hist list [--host H] [--method M] [--status N] [--body S] [--limit N]
  agentburp hist show <id>
  agentburp repeat <id> [--set "Header: value"]... [--body B]
  agentburp fuzz <baseline_id> --param NAME (--wordlist FILE | --range-from N --range-to N) [--anomalies] [--confirm]
  agentburp diff <id_a> <id_b>
  agentburp scan <entry_id>
  agentburp report <entry_id> [--format hackerone|bugcrowd|nuclei|generic] [--finding-id N]
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
		if len(args) > 0 && args[0] == "ca" {
			cmdProxyCA(args[1:])
		} else {
			cmdProxy(args)
		}
	case "ui":
		cmdUI(args)
	case "oast":
		cmdOAST(args)
	case "ws":
		cmdWS(args)
	case "raw":
		cmdRaw(args)
	case "export":
		cmdExport(args)
	case "import":
		cmdImport(args)
	case "map":
		cmdMap(args)
	case "scope":
		cmdScope(args)
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
		fmt.Fprintln(os.Stderr, "usage: agentburp proxy start [--addr 127.0.0.1:8888] [--scope scope.yml] [--upstream URL] [--inject-header \"Name: Value\"] [--ui] [--quiet]")
		os.Exit(1)
	}
	fs := flag.NewFlagSet("proxy start", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:8888", "listen address")
	scopePath := fs.String("scope", "scope.yml", "path to scope.yml")
	upstream := fs.String("upstream", "", "upstream proxy URL (e.g. http://127.0.0.1:8080)")
	withUI := fs.Bool("ui", false, "also launch embedded web dashboard on 127.0.0.1:8889")
	quiet := fs.Bool("quiet", false, "disable real-time traffic stream logs")
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
		Quiet:         *quiet,
	}

	if *withUI {
		dashSrv := dashboard.NewServer("127.0.0.1:8889", d, cfg, currentWorkspace(), nil)
		go func() {
			fmt.Printf("[+] agentburp web dashboard listening on http://127.0.0.1:8889\n")
			_ = dashSrv.Start()
		}()
	}

	srv := proxy.New(*addr, d, g, currentWorkspace(), opts)
	if err := srv.ListenAndServe(); err != nil {
		fatal(err)
	}
}

// ---------- web ui ----------

func cmdUI(args []string) {
	fs := flag.NewFlagSet("ui", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:8889", "dashboard listen address")
	scopePath := fs.String("scope", "scope.yml", "path to scope.yml")
	fs.Parse(args)

	cfg, _ := loadScope(*scopePath)
	d, err := openDB()
	if err != nil {
		fatal(err)
	}
	defer d.Close()

	oastSrv := oast.NewServer("127.0.0.1:9998", "http://127.0.0.1:9998")
	go func() {
		_ = oastSrv.Start()
	}()

	fmt.Printf("[+] agentburp web dashboard listening on http://%s (workspace=%s)\n", *addr, currentWorkspace())
	srv := dashboard.NewServer(*addr, d, cfg, currentWorkspace(), oastSrv)
	if err := srv.Start(); err != nil {
		fatal(err)
	}
}

// ---------- oast collaborator ----------

func cmdOAST(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: agentburp oast start|token|poll|list ...")
		os.Exit(1)
	}
	switch args[0] {
	case "start":
		fs := flag.NewFlagSet("oast start", flag.ExitOnError)
		addr := fs.String("addr", "127.0.0.1:9998", "listener address")
		domain := fs.String("domain", "", "public callback domain/URL")
		fs.Parse(args[1:])

		srv := oast.NewServer(*addr, *domain)
		fmt.Printf("[+] agentburp OAST collaborator listening on %s (domain=%s)\n", *addr, *domain)
		if err := srv.Start(); err != nil {
			fatal(err)
		}
	case "token":
		fs := flag.NewFlagSet("oast token", flag.ExitOnError)
		server := fs.String("server", "http://127.0.0.1:9998", "running OAST server URL")
		fs.Parse(args[1:])

		tok, cbURL, err := oast.RequestToken(*server)
		if err != nil {
			tok = oast.GenerateToken()
			cbURL = fmt.Sprintf("%s/c/%s", strings.TrimRight(*server, "/"), tok)
		}
		printJSON(map[string]string{
			"token": tok,
			"url":   cbURL,
		})
	case "poll":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: agentburp oast poll <token> [--server URL]")
			os.Exit(1)
		}
		token := args[1]
		fs := flag.NewFlagSet("oast poll", flag.ExitOnError)
		server := fs.String("server", "http://127.0.0.1:9998", "running OAST server URL")
		fs.Parse(args[2:])

		interactions, err := oast.Poll(*server, token)
		if err != nil {
			fatal(err)
		}
		printJSON(interactions)
	case "list":
		fs := flag.NewFlagSet("oast list", flag.ExitOnError)
		server := fs.String("server", "http://127.0.0.1:9998", "running OAST server URL")
		fs.Parse(args[1:])

		interactions, err := oast.Poll(*server, "")
		if err != nil {
			fatal(err)
		}
		printJSON(interactions)
	default:
		fmt.Fprintf(os.Stderr, "unknown oast subcommand %q\n", args[0])
		os.Exit(1)
	}
}

// ---------- websocket ----------

func cmdWS(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: agentburp ws list|show ...")
		os.Exit(1)
	}
	d, err := openDB()
	if err != nil {
		fatal(err)
	}
	defer d.Close()

	switch args[0] {
	case "list":
		fs := flag.NewFlagSet("ws list", flag.ExitOnError)
		entryID := fs.Int64("entry-id", 0, "filter by HTTP handshake entry ID")
		limit := fs.Int("limit", 50, "max frames to list")
		fs.Parse(args[1:])

		frames, err := d.SearchWSFrames(currentWorkspace(), *entryID, *limit)
		if err != nil {
			fatal(err)
		}
		printJSON(frames)
	case "show":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: agentburp ws show <frame_id>")
			os.Exit(1)
		}
		id, err := strconv.ParseInt(args[1], 10, 64)
		if err != nil {
			fatal(err)
		}
		f, err := d.GetWSFrame(id)
		if err != nil {
			fatal(err)
		}
		printJSON(f)
	default:
		fmt.Fprintf(os.Stderr, "unknown ws subcommand %q\n", args[0])
		os.Exit(1)
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

// ---------- proxy ca ----------

func cmdProxyCA(args []string) {
	fs := flag.NewFlagSet("proxy ca", flag.ExitOnError)
	outDir := fs.String("out-dir", "", "directory to store ca.crt and ca.key (default: ~/.agentburp)")
	fs.Parse(args)

	dir := *outDir
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			fatal(err)
		}
		dir = filepath.Join(home, ".agentburp")
	}

	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	if err := cert.GenerateCA(certPath, keyPath); err != nil {
		fatal(err)
	}

	fmt.Println("Generated agentburp Root CA:")
	fmt.Printf("  Certificate: %s\n", certPath)
	fmt.Printf("  Private Key: %s\n\n", keyPath)
	fmt.Println("Install 'ca.crt' into your browser or operating system's Trusted Root Certification Authorities to decrypt HTTPS traffic.")
}

// ---------- import ----------

func cmdImport(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: agentburp import <file.har> [--workspace W]")
		os.Exit(1)
	}
	filePath := args[0]
	fs := flag.NewFlagSet("import", flag.ExitOnError)
	ws := fs.String("workspace", "", "target workspace (default: active workspace)")
	fs.Parse(args[1:])

	data, err := os.ReadFile(filePath)
	if err != nil {
		fatal(err)
	}

	targetWS := currentWorkspace()
	if *ws != "" {
		targetWS = *ws
	}

	entries, err := export.FromHAR(data, targetWS)
	if err != nil {
		fatal(err)
	}

	d, err := openDB()
	if err != nil {
		fatal(err)
	}
	defer d.Close()

	count := 0
	for _, e := range entries {
		if _, err := d.InsertEntry(e); err == nil {
			count++
		}
	}
	fmt.Printf("Successfully imported %d HTTP entries into workspace %q from %s\n", count, targetWS, filePath)
}

// ---------- map ----------

func cmdMap(args []string) {
	fs := flag.NewFlagSet("map", flag.ExitOnError)
	hostFilter := fs.String("host", "", "filter sitemap by host")
	asJSON := fs.Bool("json", false, "output sitemap as JSON")
	limit := fs.Int("limit", 1000, "max history entries to analyze")
	fs.Parse(args)

	d, err := openDB()
	if err != nil {
		fatal(err)
	}
	defer d.Close()

	entries, err := d.Search(db.SearchOpts{
		Workspace: currentWorkspace(),
		Host:      *hostFilter,
		Limit:     *limit,
	})
	if err != nil {
		fatal(err)
	}

	maps := sitemap.Build(entries)
	if *asJSON {
		printJSON(maps)
		return
	}
	fmt.Print(sitemap.RenderTree(maps))
}

// ---------- scope ----------

func cmdScope(args []string) {
	if len(args) == 0 || args[0] != "test" {
		fmt.Fprintln(os.Stderr, "usage: agentburp scope test <host_or_url> [--scope scope.yml] [--json]")
		os.Exit(1)
	}
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: agentburp scope test <host_or_url> [--scope scope.yml] [--json]")
		os.Exit(1)
	}
	targetInput := args[1]
	fs := flag.NewFlagSet("scope test", flag.ExitOnError)
	scopePath := fs.String("scope", "scope.yml", "path to scope.yml")
	asJSON := fs.Bool("json", false, "output in JSON")
	fs.Parse(args[2:])

	cfg, err := loadScope(*scopePath)
	if err != nil {
		fatal(err)
	}
	g := scope.NewGuard(cfg)

	host := targetInput
	if strings.Contains(targetInput, "://") {
		if u, err := url.Parse(targetInput); err == nil && u.Host != "" {
			host = u.Host
		}
	}
	allowed, reason := g.Allowed(host)

	if *asJSON {
		res := map[string]interface{}{
			"target":  targetInput,
			"host":    host,
			"allowed": allowed,
			"reason":  reason,
		}
		printJSON(res)
		return
	}

	if allowed {
		fmt.Printf("[ALLOWED] Target %q (%s) is IN SCOPE\n", targetInput, host)
	} else {
		fmt.Printf("[DENIED]  Target %q (%s) is OUT OF SCOPE: %s\n", targetInput, host, reason)
	}
}

// ---------- raw ----------

func cmdRaw(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: agentburp raw <file.http | -> [--ssl] [--target host:port] [--scope scope.yml]")
		os.Exit(1)
	}
	filePath := args[0]
	fs := flag.NewFlagSet("raw", flag.ExitOnError)
	useTLS := fs.Bool("ssl", false, "use TLS (HTTPS) connection")
	target := fs.String("target", "", "override destination host:port")
	scopePath := fs.String("scope", "scope.yml", "path to scope.yml")
	fs.Parse(args[1:])

	var rawData []byte
	var err error
	if filePath == "-" {
		rawData, err = io.ReadAll(os.Stdin)
	} else {
		rawData, err = os.ReadFile(filePath)
	}
	if err != nil {
		fatal(err)
	}

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

	entry, err := raw.ReplayRaw(d, g, rawData, raw.Options{
		UseTLS:    *useTLS,
		Target:    *target,
		Workspace: currentWorkspace(),
	})
	if err != nil {
		fatal(err)
	}
	printJSON(entry)
}



