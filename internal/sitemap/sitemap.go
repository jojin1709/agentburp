package sitemap

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/jojin1709/agentburp/internal/model"
)

// Endpoint represents a unique discovered URL endpoint.
type Endpoint struct {
	Path       string              `json:"path"`
	Methods    []string            `json:"methods"`
	Parameters []string            `json:"parameters,omitempty"`
	Statuses   []int               `json:"statuses,omitempty"`
}

// HostMap represents the sitemap for a specific host.
type HostMap struct {
	Host      string      `json:"host"`
	Endpoints []*Endpoint `json:"endpoints"`
}

// Build generates an aggregated site map from a list of captured entries.
func Build(entries []*model.Entry) []*HostMap {
	type epKey struct {
		host string
		path string
	}

	data := make(map[epKey]*struct {
		methods  map[string]bool
		params   map[string]bool
		statuses map[int]bool
	})

	for _, e := range entries {
		u, err := url.Parse(e.URL)
		if err != nil {
			continue
		}
		host := e.Host
		if host == "" {
			host = u.Host
		}
		if host == "" {
			continue
		}

		path := u.Path
		if path == "" {
			path = "/"
		}

		k := epKey{host: host, path: path}
		if data[k] == nil {
			data[k] = &struct {
				methods  map[string]bool
				params   map[string]bool
				statuses map[int]bool
			}{
				methods:  make(map[string]bool),
				params:   make(map[string]bool),
				statuses: make(map[int]bool),
			}
		}

		if e.Method != "" {
			data[k].methods[e.Method] = true
		}
		if e.Status > 0 {
			data[k].statuses[e.Status] = true
		}

		// Query params
		for qk := range u.Query() {
			data[k].params[qk] = true
		}

		// Body params (if form-urlencoded or JSON)
		if strings.Contains(e.ReqHeaders["Content-Type"], "application/x-www-form-urlencoded") {
			if vals, err := url.ParseQuery(e.ReqBody); err == nil {
				for bk := range vals {
					data[k].params[bk] = true
				}
			}
		} else if strings.Contains(e.ReqHeaders["Content-Type"], "application/json") && strings.HasPrefix(strings.TrimSpace(e.ReqBody), "{") {
			var jsonMap map[string]interface{}
			if err := json.Unmarshal([]byte(e.ReqBody), &jsonMap); err == nil {
				for jk := range jsonMap {
					data[k].params[jk] = true
				}
			}
		}
	}

	// Group by host
	byHost := make(map[string][]*Endpoint)
	for k, v := range data {
		var methods []string
		for m := range v.methods {
			methods = append(methods, m)
		}
		sort.Strings(methods)

		var params []string
		for p := range v.params {
			params = append(params, p)
		}
		sort.Strings(params)

		var statuses []int
		for s := range v.statuses {
			statuses = append(statuses, s)
		}
		sort.Ints(statuses)

		byHost[k.host] = append(byHost[k.host], &Endpoint{
			Path:       k.path,
			Methods:    methods,
			Parameters: params,
			Statuses:   statuses,
		})
	}

	var result []*HostMap
	for h, eps := range byHost {
		sort.Slice(eps, func(i, j int) bool {
			return eps[i].Path < eps[j].Path
		})
		result = append(result, &HostMap{
			Host:      h,
			Endpoints: eps,
		})
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Host < result[j].Host
	})

	return result
}

// RenderTree returns an ASCII tree view representation of the sitemap.
func RenderTree(maps []*HostMap) string {
	if len(maps) == 0 {
		return "No endpoints discovered yet.\n"
	}

	var sb strings.Builder
	for _, hm := range maps {
		sb.WriteString(fmt.Sprintf("%s\n", hm.Host))
		for i, ep := range hm.Endpoints {
			isLast := i == len(hm.Endpoints)-1
			prefix := "├──"
			if isLast {
				prefix = "└──"
			}

			methodsStr := strings.Join(ep.Methods, ",")
			paramStr := ""
			if len(ep.Parameters) > 0 {
				paramStr = fmt.Sprintf(" (params: %s)", strings.Join(ep.Parameters, ", "))
			}
			statusStr := ""
			if len(ep.Statuses) > 0 {
				var sList []string
				for _, s := range ep.Statuses {
					sList = append(sList, fmt.Sprintf("%d", s))
				}
				statusStr = fmt.Sprintf(" [%s]", strings.Join(sList, ","))
			}

			sb.WriteString(fmt.Sprintf(" %s [%s] %s%s%s\n", prefix, methodsStr, ep.Path, paramStr, statusStr))
		}
		sb.WriteString("\n")
	}
	return sb.String()
}
