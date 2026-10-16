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
	Generic   Format = "generic"
)

// Generate builds a Markdown PoC writeup. The agent/human must fill in
// impact and remediation details — this scaffolds structure, not the
// vulnerability claim itself.
func Generate(f Format, finding *model.Finding, entry *model.Entry) string {
	var b strings.Builder

	title := finding.Title
	if title == "" {
		title = "Security Finding"
	}

	switch f {
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
