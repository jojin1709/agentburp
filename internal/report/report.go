package report

import (
	"fmt"
	"strings"

	"github.com/jojin1709/agentburp/internal/model"
)

// Format selects the output template.
type Format string

const (
	HackerOne Format = "hackerone"
	Bugcrowd  Format = "bugcrowd"
	Nuclei    Format = "nuclei"
	Generic   Format = "generic"
)

// Generate builds a Markdown PoC writeup or Nuclei YAML template. The agent/human must fill in
// impact and remediation details — this scaffolds structure, not the
// vulnerability claim itself.
func Generate(f Format, finding *model.Finding, entry *model.Entry) string {
	var b strings.Builder

	title := finding.Title
	if title == "" {
		title = "Security Finding"
	}

	switch f {
	case Nuclei:
		cleanTitle := strings.ReplaceAll(title, `"`, `'`)
		cleanModule := strings.ToLower(strings.ReplaceAll(finding.Module, " ", "-"))
		severity := "medium"
		if strings.EqualFold(finding.Confidence, "high") {
			severity = "high"
		} else if strings.EqualFold(finding.Confidence, "low") {
			severity = "low"
		}

		fmt.Fprintf(&b, "id: agentburp-%s-%d\n", cleanModule, entry.ID)
		b.WriteString("info:\n")
		fmt.Fprintf(&b, "  name: %q\n", cleanTitle)
		b.WriteString("  author: agentburp (JOJIN JOHN)\n")
		fmt.Fprintf(&b, "  severity: %s\n", severity)
		fmt.Fprintf(&b, "  description: %q\n", finding.Detail)
		fmt.Fprintf(&b, "  tags: agentburp,%s\n\n", cleanModule)
		b.WriteString("http:\n")
		b.WriteString("  - raw:\n")
		b.WriteString("      - |\n")
		fmt.Fprintf(&b, "        %s %s HTTP/1.1\n", entry.Method, entry.URL)
		fmt.Fprintf(&b, "        Host: %s\n", entry.Host)
		for k, v := range entry.ReqHeaders {
			if strings.EqualFold(k, "Host") {
				continue
			}
			fmt.Fprintf(&b, "        %s: %s\n", k, v)
		}
		if entry.ReqBody != "" {
			b.WriteString("\n        " + strings.ReplaceAll(entry.ReqBody, "\n", "\n        ") + "\n")
		}
		b.WriteString("\n    matchers-condition: and\n")
		b.WriteString("    matchers:\n")
		b.WriteString("      - type: status\n")
		b.WriteString("        status:\n")
		fmt.Fprintf(&b, "          - %d\n", entry.Status)

	case HackerOne:
		fmt.Fprintf(&b, "## Summary\n\n%s\n\n", title)
		fmt.Fprintf(&b, "## Description\n\n%s\n\n", finding.Detail)
		fmt.Fprintf(&b, "## Steps To Reproduce\n\n1. Send the following request:\n\n")
		fmt.Fprintf(&b, "```http\n%s %s\n", entry.Method, entry.URL)
		for k, v := range entry.ReqHeaders {
			fmt.Fprintf(&b, "%s: %s\n", k, v)
		}
		if entry.ReqBody != "" {
			fmt.Fprintf(&b, "\n%s\n", truncate(entry.ReqBody, 2000))
		}
		b.WriteString("```\n\n")
		fmt.Fprintf(&b, "2. Observe response status `%d`.\n\n", entry.Status)
		b.WriteString("## Supporting Material\n\nResponse snippet:\n\n```\n")
		b.WriteString(truncate(entry.RespBody, 2000))
		b.WriteString("\n```\n\n")
		fmt.Fprintf(&b, "## Impact\n\n_(Fill in business impact — confidence level from scanner: %s. Verify manually before submitting.)_\n\n", finding.Confidence)

	case Bugcrowd:
		fmt.Fprintf(&b, "# %s\n\n", title)
		fmt.Fprintf(&b, "**VRT / Category:** %s\n\n**Confidence:** %s\n\n", finding.Module, finding.Confidence)
		fmt.Fprintf(&b, "**Description:**\n%s\n\n", finding.Detail)
		fmt.Fprintf(&b, "**Request:**\n```\n%s %s\n```\n\n", entry.Method, entry.URL)
		fmt.Fprintf(&b, "**Response Status:** %d\n\n", entry.Status)
		b.WriteString("**Remediation Suggestion:**\n_(fill in)_\n")

	default:
		fmt.Fprintf(&b, "# %s\n\nModule: %s | Confidence: %s\n\n%s\n\nRequest: %s %s\nStatus: %d\n",
			title, finding.Module, finding.Confidence, finding.Detail, entry.Method, entry.URL, entry.Status)
	}

	return b.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "\n...(truncated)"
}
