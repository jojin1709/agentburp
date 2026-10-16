// Package ws provides RFC 6455 WebSocket frame interception, parsing,
// logging to SQLite, and bidirectional socket proxying.
package ws

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/jojin1709/agentburp/internal/db"
	"github.com/jojin1709/agentburp/internal/model"
)

// Opcode constants
const (
	OpContinuation = 0
	OpText         = 1
	OpBinary       = 2
	OpClose        = 8
	OpPing         = 9
	OpPong         = 10
)

// OpcodeName returns human-readable name for an opcode.
func OpcodeName(op int) string {
	switch op {
	case OpContinuation:
		return "continuation"
	case OpText:
		return "text"
	case OpBinary:
		return "binary"
	case OpClose:
		return "close"
	case OpPing:
		return "ping"
	case OpPong:
		return "pong"
	default:
		return fmt.Sprintf("unknown(%d)", op)
	}
}

// ReadFrame reads a single RFC 6455 frame from r, forwards all raw wire bytes to w,
// and returns the opcode and decoded payload.
func ReadFrame(r io.Reader, w io.Writer) (opcode int, payload []byte, err error) {
	var header [2]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, nil, err
	}
	if w != nil {
		if _, err := w.Write(header[:]); err != nil {
			return 0, nil, err
		}
	}

	opcode = int(header[0] & 0x0F)
	masked := (header[1] & 0x80) != 0
	length := int(header[1] & 0x7F)

	if length == 126 {
		var ext [2]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return 0, nil, err
		}
		if w != nil {
			if _, err := w.Write(ext[:]); err != nil {
				return 0, nil, err
			}
		}
		length = int(binary.BigEndian.Uint16(ext[:]))
	} else if length == 127 {
		var ext [8]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return 0, nil, err
		}
		if w != nil {
			if _, err := w.Write(ext[:]); err != nil {
				return 0, nil, err
			}
		}
		length = int(binary.BigEndian.Uint64(ext[:]))
	}

	var maskKey [4]byte
	if masked {
		if _, err := io.ReadFull(r, maskKey[:]); err != nil {
			return 0, nil, err
		}
		if w != nil {
			if _, err := w.Write(maskKey[:]); err != nil {
				return 0, nil, err
			}
		}
	}

	rawPayload := make([]byte, length)
	if _, err := io.ReadFull(r, rawPayload); err != nil {
		return 0, nil, err
	}
	if w != nil {
		if _, err := w.Write(rawPayload); err != nil {
			return 0, nil, err
		}
	}

	unmasked := make([]byte, length)
	copy(unmasked, rawPayload)
	if masked {
		for i := 0; i < length; i++ {
			unmasked[i] ^= maskKey[i%4]
		}
	}

	return opcode, unmasked, nil
}

// BuildFrame serializes an RFC 6455 frame with the specified opcode and payload.
func BuildFrame(opcode int, payload []byte, masked bool, maskKey [4]byte) []byte {
	var buf []byte
	b0 := byte(0x80 | (opcode & 0x0F)) // FIN = 1
	var b1 byte
	if masked {
		b1 = 0x80
	}

	length := len(payload)
	if length < 126 {
		b1 |= byte(length)
		buf = append(buf, b0, b1)
	} else if length <= 65535 {
		b1 |= 126
		buf = append(buf, b0, b1)
		var ext [2]byte
		binary.BigEndian.PutUint16(ext[:], uint16(length))
		buf = append(buf, ext[:]...)
	} else {
		b1 |= 127
		buf = append(buf, b0, b1)
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(length))
		buf = append(buf, ext[:]...)
	}

	if masked {
		buf = append(buf, maskKey[:]...)
		maskedPayload := make([]byte, length)
		for i := 0; i < length; i++ {
			maskedPayload[i] = payload[i] ^ maskKey[i%4]
		}
		buf = append(buf, maskedPayload...)
	} else {
		buf = append(buf, payload...)
	}

	return buf
}

// PipeAndLog intercepts frames in both directions between clientConn and serverConn,
// forwarding each frame while storing it in the SQLite database.
func PipeAndLog(clientConn, serverConn net.Conn, entryID int64, workspace string, database *db.DB) {
	var wg sync.WaitGroup
	wg.Add(2)

	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			_ = clientConn.Close()
			_ = serverConn.Close()
		})
	}
	defer closeBoth()

	logAndPipe := func(src, dst net.Conn, direction string) {
		defer wg.Done()
		defer closeBoth()

		for {
			op, payload, err := ReadFrame(src, dst)
			if err != nil {
				return
			}

			payloadStr := ""
			if op == OpText && utf8.Valid(payload) {
				payloadStr = string(payload)
			} else {
				payloadStr = hex.EncodeToString(payload)
			}

			if database != nil {
				frame := &model.WSFrame{
					Timestamp:  time.Now(),
					EntryID:    entryID,
					Direction:  direction,
					Opcode:     op,
					OpcodeName: OpcodeName(op),
					Length:     len(payload),
					Payload:    payloadStr,
					Workspace:  workspace,
				}
				_, _ = database.InsertWSFrame(frame)
			}

			if op == OpClose {
				return
			}
		}
	}

	go logAndPipe(clientConn, serverConn, "client->server")
	go logAndPipe(serverConn, clientConn, "server->client")

	wg.Wait()
}
