package workspace

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// State tracks the currently active workspace name, persisted to disk so
// `use` sticks across CLI invocations.
type State struct {
	Active string `json:"active"`
}

func statePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".agentburp")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return filepath.Join(dir, "workspace.json"), nil
}

func Load() (*State, error) {
	p, err := statePath()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if os.IsNotExist(err) {
		return &State{Active: "default"}, nil
	}
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return &State{Active: "default"}, nil
	}
	if s.Active == "" {
		s.Active = "default"
	}
	return &s, nil
}

func Use(name string) error {
	p, err := statePath()
	if err != nil {
		return err
	}
	s := State{Active: name}
	b, _ := json.MarshalIndent(s, "", "  ")
	return os.WriteFile(p, b, 0o644)
}

func DBPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".agentburp")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return filepath.Join(dir, "history.db"), nil
}
