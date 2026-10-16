// Package scanner provides lightweight, heuristic checks that flag candidate
// issues for a human (or the calling agent) to verify. None of these modules
// auto-confirm a vulnerability — every finding carries a confidence level and
// must be manually validated before reporting, per responsible-disclosure
// norms and program rules.
package scanner

import (
	"fmt"
	"strings"
	"time"

	"github.com/jojin1709/agentburp/internal/model"
)

type Module func(e *model.Entry) []*model.Finding

var Modules = map[string]Module{
	"idor":          checkIDOR,
	"open_redirect": checkOpenRedirect,
	"cors":          checkCORS,
	"jwt":           checkJWT,
	"ssrf_hint":     checkSSRFHint,
}

func finding(module, title, detail, confidence string, e *model.Entry) *model.Finding {
	return &model.Finding{
		Timestamp:  time.Now(),
		Module:     module,
		EntryID:    e.ID,
		Title:      title,
		Detail:     detail,
		Confidence: confidence,
		Workspace:  e.Workspace,
	}
}

// checkIDOR flags numeric-ID-looking params in the URL as candidates worth
// testing with a different identity/session (pair with `fuzz` + `diff`).
func checkIDOR(e *model.Entry) []*model.Finding {
	var out []*model.Finding
	for _, key := range []string{"id=", "user_id=", "uid=", "account=", "order_id="} {
		if strings.Contains(e.URL, key) {
			out = append(out, finding("idor",
				"Possible IDOR candidate parameter",
				fmt.Sprintf("URL contains %q — replay as a different identity and diff the responses to confirm authorization is enforced.", strings.TrimSuffix(key, "=")),
				"low", e))
		}
	}
	return out
}

func checkOpenRedirect(e *model.Entry) []*model.Finding {
	var out []*model.Finding
	for _, key := range []string{"redirect=", "url=", "next=", "return_to=", "continue="} {
		if strings.Contains(e.URL, key) {
			out = append(out, finding("open_redirect",
				"Possible open redirect parameter",
				fmt.Sprintf("URL contains %q — try an external/attacker-controlled URL as the value and check for a Location header pointing off-domain.", strings.TrimSuffix(key, "=")),
				"low", e))
		}
	}
	if loc, ok := e.RespHeaders["Location"]; ok && loc != "" && !strings.Contains(loc, e.Host) && strings.HasPrefix(loc, "http") {
		out = append(out, finding("open_redirect",
			"Redirect to external host",
			fmt.Sprintf("Response redirects to %s, which is off-host — verify this isn't attacker-steerable.", loc),
			"medium", e))
	}
	return out
}

func checkCORS(e *model.Entry) []*model.Finding {
	var out []*model.Finding
	acao := e.RespHeaders["Access-Control-Allow-Origin"]
	acac := e.RespHeaders["Access-Control-Allow-Credentials"]
	if acao == "*" && strings.EqualFold(acac, "true") {
		out = append(out, finding("cors",
			"Permissive CORS with credentials",
			"Access-Control-Allow-Origin: * combined with Allow-Credentials: true is invalid per spec in most browsers but worth confirming the server actually reflects arbitrary Origin headers (which is the real vuln).",
			"medium", e))
	}
	return out
}

func checkJWT(e *model.Entry) []*model.Finding {
	var out []*model.Finding
	auth := e.ReqHeaders["Authorization"]
	if strings.HasPrefix(auth, "Bearer ey") {
		out = append(out, finding("jwt",
			"JWT observed in request",
			"Decode header/payload and check: alg=none acceptance, weak HMAC secret, missing exp/aud validation, and whether the server accepts a token re-signed with a different algorithm.",
			"low", e))
	}
	return out
}

func checkSSRFHint(e *model.Entry) []*model.Finding {
	var out []*model.Finding
	for _, key := range []string{"url=", "uri=", "target=", "callback=", "webhook="} {
		if strings.Contains(e.URL, key) || strings.Contains(e.ReqBody, strings.TrimSuffix(key, "=")) {
			out = append(out, finding("ssrf_hint",
				"Possible SSRF sink parameter",
				fmt.Sprintf("Parameter resembling %q may fetch a server-controlled URL — test with your OOB collaborator domain to confirm callback.", strings.TrimSuffix(key, "=")),
				"low", e))
		}
	}
	return out
}

// RunAll runs every registered module against an entry.
func RunAll(e *model.Entry) []*model.Finding {
	var out []*model.Finding
	for _, m := range Modules {
		out = append(out, m(e)...)
	}
	return out
}
