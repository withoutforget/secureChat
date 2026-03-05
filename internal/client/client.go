package client

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // WebSocket RFC 6455 requires SHA-1
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
)

// Envelope is a framed message: sender ID + payload.
type Envelope struct {
	From string
	Data []byte
}

// frame packs senderID + data into wire format:
//
//	[1 byte: len(from)] [from] [payload]
func frame(from string, data []byte) []byte {
	buf := make([]byte, 1+len(from)+len(data))
	buf[0] = byte(len(from))
	copy(buf[1:], from)
	copy(buf[1+len(from):], data)
	return buf
}

// unframe parses a framed message back into an Envelope.
func unframe(raw []byte) (Envelope, error) {
	if len(raw) < 1 {
		return Envelope{}, fmt.Errorf("empty frame")
	}
	n := int(raw[0])
	if len(raw) < 1+n {
		return Envelope{}, fmt.Errorf("frame too short for sender id (need %d, have %d)", 1+n, len(raw))
	}
	return Envelope{
		From: string(raw[1 : 1+n]),
		Data: raw[1+n:],
	}, nil
}

// HTTPClient implements Client via plain HTTP + a minimal WebSocket.
type HTTPClient struct {
	url string
}

func NewClient(url string) *HTTPClient {
	return &HTTPClient{url: url}
}

// doPost is a shared helper that eliminates repeated HTTP boilerplate.
func (c *HTTPClient) doPost(path string, body []byte) error {
	var bodyReader io.Reader
	contentType := ""
	if body != nil {
		bodyReader = bytes.NewReader(body)
		contentType = "application/octet-stream"
	}

	resp, err := http.Post(c.url+path, contentType, bodyReader) //nolint:noctx // CLI client
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%d: %s", resp.StatusCode, raw)
	}
	return nil
}

func (c *HTTPClient) Take(id string) error {
	return c.doPost("/api/take/"+id, nil)
}

func (c *HTTPClient) Keep(id string) error {
	return c.doPost("/api/keep/"+id, nil)
}

// Send wraps data with senderID and sends to targetID's slot.
func (c *HTTPClient) Send(targetID string, senderID string, data []byte) error {
	return c.doPost("/api/send/"+targetID, frame(senderID, data))
}

// Recv opens a single WebSocket to /api/listen/{id} and returns
// a channel of Envelope (sender + payload already split).
// The channel is closed when the connection drops.
func (c *HTTPClient) Recv(id string) (<-chan Envelope, error) {
	conn, r, err := wsDial(c.url, "/api/listen/"+id)
	if err != nil {
		return nil, err
	}

	ch := make(chan Envelope, 64)
	go func() {
		defer close(ch)
		defer conn.Close()
		for {
			raw, err := wsRead(r)
			if err != nil {
				return
			}
			env, err := unframe(raw)
			if err != nil {
				continue // skip malformed frames
			}
			ch <- env
		}
	}()

	return ch, nil
}

// ── minimal websocket client ──────────────────────────────────────────────────

func wsDial(baseURL, path string) (net.Conn, *bufio.Reader, error) {
	wsURL := "ws" + strings.TrimPrefix(baseURL, "http")

	nonce := make([]byte, 16)
	rand.Read(nonce) //nolint:errcheck  // crypto/rand.Read never returns error in Go 1.20+
	key := base64.StdEncoding.EncodeToString(nonce)

	host := strings.TrimPrefix(wsURL, "ws://")
	host = strings.TrimPrefix(host, "wss://")
	host = strings.SplitN(host, "/", 2)[0]

	conn, err := net.Dial("tcp", host)
	if err != nil {
		return nil, nil, err
	}

	req := fmt.Sprintf(
		"GET %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Key: %s\r\n"+
			"Sec-WebSocket-Version: 13\r\n\r\n",
		path, host, key)

	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, nil, err
	}

	r := bufio.NewReader(conn)

	h := sha1.New()
	h.Write([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	expectedAccept := base64.StdEncoding.EncodeToString(h.Sum(nil))

	gotAccept := ""
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			conn.Close()
			return nil, nil, err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}
		if strings.HasPrefix(line, "Sec-WebSocket-Accept:") {
			gotAccept = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
		}
	}

	if gotAccept != expectedAccept {
		conn.Close()
		return nil, nil, fmt.Errorf("bad ws accept: %s", gotAccept)
	}

	return conn, r, nil
}

func wsRead(r io.Reader) ([]byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}

	length := int(header[1] & 0x7f)
	switch length {
	case 126:
		buf := make([]byte, 2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		length = int(binary.BigEndian.Uint16(buf))
	case 127:
		buf := make([]byte, 8)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		length = int(binary.BigEndian.Uint64(buf)) //nolint:gosec // can't be too big for chat
	}

	payload := make([]byte, length)
	_, err := io.ReadFull(r, payload)
	return payload, err
}
