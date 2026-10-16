// Package scanner provides lightweight, heuristic checks that flag candidate
// issues for a human (or the calling agent) to verify. None of these modules
// auto-confirm a vulnerability — every finding carries a confidence level and
// must be manually validated before reporting, per responsible-disclosure
// norms and program rules.
package scanner

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jojin1709/agentburp/internal/model"
)

type Module func(e *model.Entry) []*model.Finding

var Modules = map[string]Module{
	"idor":              checkIDOR,
	"open_redirect":     checkOpenRedirect,
	"cors":              checkCORS,
	"jwt":               checkJWT,
	"ssrf_hint":         checkSSRFHint,
	"graphql":           checkGraphQL,
	"security_headers":  checkSecurityHeaders,
	"sensitive_exposure": checkSensitiveExposure,
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
	for _, key := range []string{"redirect=", "url=", "next=", "return_to=", "continue=", "dest=", "target="} {
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

func decodeB64URL(s string) ([]byte, error) {
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}

func checkJWT(e *model.Entry) []*model.Finding {
	var out []*model.Finding
	var tokens []string

	if auth := e.ReqHeaders["Authorization"]; strings.HasPrefix(auth, "Bearer ey") {
		tokens = append(tokens, strings.TrimPrefix(auth, "Bearer "))
	}
	if cookie := e.ReqHeaders["Cookie"]; cookie != "" {
		for _, part := range strings.Split(cookie, ";") {
			part = strings.TrimSpace(part)
			if strings.Contains(part, "=ey") {
				idx := strings.Index(part, "=ey")
				tokens = append(tokens, part[idx+1:])
			}
		}
	}

	for _, token := range tokens {
		parts := strings.Split(strings.TrimSpace(token), ".")
		if len(parts) < 2 {
			continue
		}

		hdrBytes, errHdr := decodeB64URL(parts[0])
		payloadBytes, errPay := decodeB64URL(parts[1])
		if errHdr != nil || errPay != nil {
			out = append(out, finding("jwt",
				"JWT observed in request",
				"Malformed or unparsed JWT token observed in headers.",
				"low", e))
			continue
		}

		var hdrMap map[string]any
		var payMap map[string]any
		_ = json.Unmarshal(hdrBytes, &hdrMap)
		_ = json.Unmarshal(payloadBytes, &payMap)

		alg, _ := hdrMap["alg"].(string)
		if strings.EqualFold(alg, "none") {
			out = append(out, finding("jwt",
				"JWT alg=none vulnerability candidate",
				fmt.Sprintf("JWT explicitly specifies algorithm %q: token signature verification may be completely bypassed by server.", alg),
				"high", e))
		} else {
			expStr := "none"
			if exp, ok := payMap["exp"].(float64); ok {
				expTime := time.Unix(int64(exp), 0)
				expStr = expTime.Format(time.RFC3339)
				if time.Now().After(expTime) {
					expStr += " (EXPIRED)"
				}
			}
			out = append(out, finding("jwt",
				fmt.Sprintf("JWT observed (%s)", alg),
				fmt.Sprintf("Header alg=%s, exp=%s. Claims: %s. Test alg=none, weak HMAC secret brute force, or algorithm confusion (RS256->HS256).", alg, expStr, string(payloadBytes)),
				"low", e))
		}
	}
	return out
}

func checkSSRFHint(e *model.Entry) []*model.Finding {
	var out []*model.Finding
	for _, key := range []string{"url=", "uri=", "target=", "callback=", "webhook=", "dest=", "proxy="} {
		if strings.Contains(e.URL, key) || strings.Contains(e.ReqBody, strings.TrimSuffix(key, "=")) {
			out = append(out, finding("ssrf_hint",
				"Possible SSRF sink parameter",
				fmt.Sprintf("Parameter resembling %q may fetch a server-controlled URL — test with agentburp OAST collaborator token to confirm callback.", strings.TrimSuffix(key, "=")),
				"low", e))
		}
	}
	return out
}

func checkGraphQL(e *model.Entry) []*model.Finding {
	var out []*model.Finding
	isGQLPath := strings.Contains(e.URL, "/graphql") || strings.Contains(e.URL, "/api/graphql")
	hasGQLBody := strings.Contains(e.ReqBody, "__schema") || strings.Contains(e.ReqBody, "__typename") || strings.Contains(e.ReqBody, "IntrospectionQuery")
	respHasSchema := strings.Contains(e.RespBody, "__schema") || strings.Contains(e.RespBody, "\"types\":")

	if respHasSchema {
		out = append(out, finding("graphql",
			"GraphQL Introspection Schema Enabled",
			"Response contains GraphQL introspection schema (__schema/types). Full query and mutation attack surface is exposed.",
			"high", e))
	} else if isGQLPath || hasGQLBody {
		out = append(out, finding("graphql",
			"GraphQL Endpoint Discovered",
			fmt.Sprintf("Target exposes GraphQL at %s. Test for introspection queries, query depth exhaustion, and field suggestion leaks.", e.URL),
			"medium", e))
	}
	return out
}

func checkSecurityHeaders(e *model.Entry) []*model.Finding {
	var out []*model.Finding
	if e.Status != 200 {
		return out
	}
	cType := e.RespHeaders["Content-Type"]
	if !strings.Contains(cType, "text/html") && !strings.Contains(cType, "application/xhtml+xml") {
		return out
	}

	if _, ok := e.RespHeaders["Content-Security-Policy"]; !ok {
		out = append(out, finding("security_headers",
			"Missing Content-Security-Policy",
			"HTML response does not specify a Content-Security-Policy header to mitigate Cross-Site Scripting (XSS) and data injection.",
			"low", e))
	}
	if _, ok := e.RespHeaders["X-Frame-Options"]; !ok {
		if csp := e.RespHeaders["Content-Security-Policy"]; !strings.Contains(csp, "frame-ancestors") {
			out = append(out, finding("security_headers",
				"Missing Clickjacking Protection (X-Frame-Options)",
				"Response lacks X-Frame-Options or frame-ancestors directive, potentially vulnerable to Clickjacking / UI Redress.",
				"low", e))
		}
	}
	if xcto := e.RespHeaders["X-Content-Type-Options"]; !strings.EqualFold(xcto, "nosniff") {
		out = append(out, finding("security_headers",
			"Missing X-Content-Type-Options: nosniff",
			"Response lacks 'X-Content-Type-Options: nosniff', allowing MIME-type sniffing by browsers.",
			"low", e))
	}
	return out
}

func checkSensitiveExposure(e *model.Entry) []*model.Finding {
	var out []*model.Finding
	urlLower := strings.ToLower(e.URL)
	sensitivePatterns := map[string]string{
		"/.env":             "Exposed .env configuration file containing potential environment secrets",
		"/.git/":            "Exposed .git repository directory leading to source code disclosure",
		"/actuator/":        "Spring Boot Actuator endpoint potentially leaking JVM heap or environment variables",
		"/swagger.json":     "Publicly accessible Swagger/OpenAPI documentation schema",
		"/openapi.json":     "Publicly accessible OpenAPI specification schema",
		"/wp-config.php":    "WordPress configuration file backup exposure",
		"/phpinfo.php":      "PHP configuration info disclosure (phpinfo)",
	}

	for pattern, desc := range sensitivePatterns {
		if strings.Contains(urlLower, pattern) {
			conf := "low"
			if e.Status == 200 {
				conf = "high"
			}
			out = append(out, finding("sensitive_exposure",
				fmt.Sprintf("Sensitive Resource Access: %s", pattern),
				fmt.Sprintf("%s (Status: %d).", desc, e.Status),
				conf, e))
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
