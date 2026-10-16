package diff

import (
	"fmt"
	"strings"

	"github.com/jojin1709/agentburp/internal/model"
)

// Result summarizes differences between two entries.
type Result struct {
	StatusChanged   bool   `json:"status_changed"`
	StatusA         int    `json:"status_a"`
	StatusB         int    `json:"status_b"`
	LengthDeltaByte int    `json:"length_delta_bytes"`
	HeaderDiff      []string `json:"header_diff"`
	BodyDiffLines   []string `json:"body_diff_lines"`
	Identical       bool   `json:"identical"`
}

// Compare produces a readable diff between two responses — used for anomaly
// detection in fuzzing and for user-vs-user authorization checks.
func Compare(a, b *model.Entry) *Result {
	r := &Result{
		StatusChanged:   a.Status != b.Status,
		StatusA:         a.Status,
		StatusB:         b.Status,
		LengthDeltaByte: b.Length - a.Length,
	}

	// header diff (keys present/absent/changed)
	seen := map[string]bool{}
	for k, va := range a.RespHeaders {
		seen[k] = true
		if vb, ok := b.RespHeaders[k]; !ok {
			r.HeaderDiff = append(r.HeaderDiff, fmt.Sprintf("-%s: %s", k, va))
		} else if vb != va {
			r.HeaderDiff = append(r.HeaderDiff, fmt.Sprintf("~%s: %s -> %s", k, va, vb))
		}
	}
	for k, vb := range b.RespHeaders {
		if !seen[k] {
			r.HeaderDiff = append(r.HeaderDiff, fmt.Sprintf("+%s: %s", k, vb))
		}
	}

	r.BodyDiffLines = lineDiff(a.RespBody, b.RespBody, 20)
	r.Identical = !r.StatusChanged && r.LengthDeltaByte == 0 && len(r.HeaderDiff) == 0 && len(r.BodyDiffLines) == 0
	return r
}

// lineDiff is a simple LCS-free line diff good enough for quick anomaly spotting
// (not meant to replace a proper diff library for large bodies).
func lineDiff(a, b string, maxLines int) []string {
	linesA := strings.Split(a, "\n")
	linesB := strings.Split(b, "\n")
	var out []string
	max := len(linesA)
	if len(linesB) > max {
		max = len(linesB)
	}
	for i := 0; i < max && len(out) < maxLines; i++ {
		var la, lb string
		if i < len(linesA) {
			la = linesA[i]
		}
		if i < len(linesB) {
			lb = linesB[i]
		}
		if la != lb {
			if la != "" {
				out = append(out, "-"+truncate(la, 200))
			}
			if lb != "" {
				out = append(out, "+"+truncate(lb, 200))
			}
		}
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...(truncated)"
}
