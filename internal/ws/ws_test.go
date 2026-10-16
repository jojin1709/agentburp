package ws

import (
	"bytes"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/jojin1709/agentburp/internal/db"
)

func TestReadAndBuildFrame(t *testing.T) {
	maskKey := [4]byte{0x12, 0x34, 0x56, 0x78}
	msg := "Hello agentburp WebSocket"

	wireBytes := BuildFrame(OpText, []byte(msg), true, maskKey)

	r := bytes.NewReader(wireBytes)
	var forwarded bytes.Buffer

	op, payload, err := ReadFrame(r, &forwarded)
	if err != nil {
		t.Fatalf("ReadFrame failed: %v", err)
	}

	if op != OpText {
		t.Errorf("expected OpText (%d), got %d", OpText, op)
	}
	if string(payload) != msg {
		t.Errorf("expected %q, got %q", msg, string(payload))
	}
	if !bytes.Equal(wireBytes, forwarded.Bytes()) {
		t.Errorf("forwarded wire bytes mismatch")
	}
}

func TestPipeAndLog(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	database, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open failed: %v", err)
	}
	defer database.Close()

	// Create pipe for client <-> proxy clientConn
	clientConn, proxyClientConn := net.Pipe()
	// Create pipe for proxy serverConn <-> target server
	proxyServerConn, targetServerConn := net.Pipe()

	done := make(chan struct{})
	go func() {
		PipeAndLog(proxyClientConn, proxyServerConn, 42, "test_ws", database)
		close(done)
	}()

	// 1. Client sends a masked text frame
	maskKey := [4]byte{0xaa, 0xbb, 0xcc, 0xdd}
	reqFrame := BuildFrame(OpText, []byte("ping from client"), true, maskKey)
	go func() {
		_, _ = clientConn.Write(reqFrame)
	}()

	// 2. Target server reads frame
	var srvRcv bytes.Buffer
	op, payload, err := ReadFrame(targetServerConn, &srvRcv)
	if err != nil {
		t.Fatalf("target server ReadFrame failed: %v", err)
	}
	if op != OpText || string(payload) != "ping from client" {
		t.Fatalf("unexpected frame received at target: op=%d, msg=%q", op, string(payload))
	}

	// 3. Target server sends unmasked pong back to client
	respFrame := BuildFrame(OpText, []byte("pong from server"), false, [4]byte{})
	go func() {
		_, _ = targetServerConn.Write(respFrame)
	}()

	// 4. Client reads response
	var cliRcv bytes.Buffer
	op, payload, err = ReadFrame(clientConn, &cliRcv)
	if err != nil {
		t.Fatalf("client ReadFrame failed: %v", err)
	}
	if op != OpText || string(payload) != "pong from server" {
		t.Fatalf("unexpected response at client: op=%d, msg=%q", op, string(payload))
	}

	// Send close frame to finish
	closeFrame := BuildFrame(OpClose, []byte{}, false, [4]byte{})
	_, _ = targetServerConn.Write(closeFrame)
	_, _, _ = ReadFrame(clientConn, nil)
	_ = clientConn.Close()
	_ = targetServerConn.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("PipeAndLog did not terminate in time")
	}

	// Verify frames logged into SQLite database
	frames, err := database.SearchWSFrames("test_ws", 42, 10)
	if err != nil {
		t.Fatalf("SearchWSFrames failed: %v", err)
	}
	if len(frames) < 2 {
		t.Fatalf("expected at least 2 frames logged, got %d", len(frames))
	}
	if frames[0].Payload != "ping from client" {
		t.Errorf("expected first frame 'ping from client', got %q", frames[0].Payload)
	}
	if frames[1].Payload != "pong from server" {
		t.Errorf("expected second frame 'pong from server', got %q", frames[1].Payload)
	}
}
