package cert

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateCA(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "ca.crt")
	keyPath := filepath.Join(tmpDir, "ca.key")

	if err := GenerateCA(certPath, keyPath); err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	// Verify cert file exists and is valid PEM
	certData, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("failed to read generated cert: %v", err)
	}
	block, _ := pem.Decode(certData)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("invalid cert PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}
	if !cert.IsCA {
		t.Errorf("expected IsCA to be true")
	}
	if cert.Subject.CommonName != "agentburp Root CA" {
		t.Errorf("unexpected CommonName: %s", cert.Subject.CommonName)
	}

	// Verify key file exists and is valid PEM
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("failed to read generated key: %v", err)
	}
	keyBlock, _ := pem.Decode(keyData)
	if keyBlock == nil || keyBlock.Type != "RSA PRIVATE KEY" {
		t.Fatalf("invalid key PEM block")
	}
}
