package client

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
)

type Client struct {
	url string
}

func NewClient(url string) *Client {
	return &Client{url: url}
}

func (c *Client) Take(id string) error {
	resp, err := http.Post(c.url+"/api/take/"+id, "", nil)
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

func (c *Client) Keep(id string) error {
	resp, err := http.Post(c.url+"/api/keep/"+id, "", nil)
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

func (c *Client) Send(id string, data []byte) error {
	resp, err := http.Post(c.url+"/api/send/"+id, "application/octet-stream", bytes.NewReader(data))
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

// Recv подключается к /api/listen/{id} по WebSocket и возвращает канал.
// Канал закрывается когда соединение разрывается (сервер убил ID или сеть упала).
func (c *Client) Recv(id string) (<-chan []byte, error) {
	conn, r, err := wsDial(c.url, "/api/listen/"+id)
	if err != nil {
		return nil, err
	}

	ch := make(chan []byte, 64)
	go func() {
		defer close(ch)
		defer conn.Close()
		for {
			frame, err := wsRead(r)
			if err != nil {
				return
			}
			ch <- frame
		}
	}()

	return ch, nil
}

// ── minimal websocket client ──────────────────────────────────────────────────

func wsDial(baseURL, path string) (net.Conn, *bufio.Reader, error) {
	wsURL := "ws" + strings.TrimPrefix(baseURL, "http")

	// случайный nonce
	nonce := make([]byte, 16)
	rand.Read(nonce)
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

	// проверяем accept
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
		length = int(binary.BigEndian.Uint64(buf))
	}

	payload := make([]byte, length)
	_, err := io.ReadFull(r, payload)
	return payload, err
}
