package main

import (
	"bufio"
	"crypto/sha1" //nolint:gosec // WebSocket RFC 6455 requires SHA-1
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const ttl = time.Minute

// ── Logger ────────────────────────────────────────────────────────────────────

var logger = log.New(log.Writer(), "", 0)

func logf(r *http.Request, format string, args ...any) {
	ip := r.RemoteAddr
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		ip = strings.SplitN(fwd, ",", 2)[0]
	}
	ts := time.Now().Format("2006-01-02 15:04:05.000")
	msg := fmt.Sprintf(format, args...)
	logger.Printf("[%s] %s — %s", ts, ip, msg)
}

// ── WebSocket ─────────────────────────────────────────────────────────────────

func wsHandshake(w http.ResponseWriter, r *http.Request) (net.Conn, *bufio.ReadWriter, error) {
	key := r.Header.Get("Sec-Websocket-Key")
	if key == "" {
		http.Error(w, "not a websocket", http.StatusBadRequest)
		return nil, nil, fmt.Errorf("no ws key")
	}

	h := sha1.New()
	h.Write([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	accept := base64.StdEncoding.EncodeToString(h.Sum(nil))

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return nil, nil, fmt.Errorf("no hijacker")
	}

	conn, rw, err := hj.Hijack()
	if err != nil {
		return nil, nil, err
	}

	fmt.Fprintf(rw,
		"HTTP/1.1 101 Switching Protocols\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Accept: %s\r\n\r\n", accept)
	rw.Flush()

	return conn, rw, nil
}

//nolint:unused //use later
func wsReadFrame(r io.Reader) ([]byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}

	length := int(header[1] & 0x7f)
	masked := header[1]&0x80 != 0

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
		l := binary.BigEndian.Uint64(buf)
		if l > math.MaxInt32 {
			return nil, fmt.Errorf("frame too large: %d", l)
		}
		length = int(l)
	}

	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(r, mask[:]); err != nil {
			return nil, err
		}
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}

	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}

	return payload, nil
}

func wsWriteFrame(w io.Writer, data []byte) error {
	length := len(data)

	var header []byte
	switch {
	case length <= 125:
		header = []byte{0x82, byte(length)}
	case length <= 0xffff:
		header = []byte{0x82, 126, byte(length >> 8), byte(length & 0xff)}
	default:
		header = make([]byte, 10)
		header[0] = 0x82
		header[1] = 127
		binary.BigEndian.PutUint64(header[2:], uint64(length))
	}

	if _, err := w.Write(header); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

// ── Relay ─────────────────────────────────────────────────────────────────────

type slot struct {
	expiresAt time.Time
	send      chan []byte
	done      chan struct{}
}

type Relay struct {
	mu    sync.Mutex
	slots map[string]*slot
}

func NewRelay() *Relay {
	r := &Relay{slots: make(map[string]*slot)}
	go r.reaper()
	return r
}

func (r *Relay) reaper() {
	for range time.NewTicker(5 * time.Second).C {
		now := time.Now()
		r.mu.Lock()
		for id, s := range r.slots {
			if now.After(s.expiresAt) {
				log.Printf("[%s] reaper — slot %q expired, closing",
					time.Now().Format("2006-01-02 15:04:05.000"), id)
				close(s.done)
				delete(r.slots, id)
			}
		}
		r.mu.Unlock()
	}
}

func (r *Relay) handleTake(w http.ResponseWriter, req *http.Request) {
	id := req.PathValue("id")
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.slots[id]; exists {
		logf(req, "TAKE %q — conflict, already taken", id)
		http.Error(w, "id already taken", http.StatusConflict)
		return
	}
	r.slots[id] = &slot{
		expiresAt: time.Now().Add(ttl),
		send:      make(chan []byte, 64),
		done:      make(chan struct{}),
	}
	logf(req, "TAKE %q — registered, ttl=%s", id, ttl)
	w.WriteHeader(http.StatusOK)
}

func (r *Relay) handleKeep(w http.ResponseWriter, req *http.Request) {
	id := req.PathValue("id")
	r.mu.Lock()
	defer r.mu.Unlock()

	s, exists := r.slots[id]
	if !exists {
		logf(req, "KEEP %q — not found", id)
		http.Error(w, "id not found", http.StatusNotFound)
		return
	}
	s.expiresAt = time.Now().Add(ttl)
	logf(req, "KEEP %q — ttl extended", id)
	w.WriteHeader(http.StatusOK)
}

func (r *Relay) handleSend(w http.ResponseWriter, req *http.Request) {
	http.MaxBytesReader(w, req.Body, 1<<20)
	id := req.PathValue("id")
	r.mu.Lock()
	s, exists := r.slots[id]
	r.mu.Unlock()

	if !exists {
		logf(req, "SEND %q — not found", id)
		http.Error(w, "id not found", http.StatusNotFound)
		return
	}

	data, err := io.ReadAll(req.Body)
	if err != nil {
		logf(req, "SEND %q — read error: %v", id, err)
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}

	select {
	case s.send <- data:
		logf(req, "SEND %q — %d bytes queued: %q", id, len(data), truncate(data, 120))
		w.WriteHeader(http.StatusOK)
	default:
		logf(req, "SEND %q — buffer full, dropped %d bytes", id, len(data))
		http.Error(w, "buffer full", http.StatusServiceUnavailable)
	}
}

func (r *Relay) handleListen(w http.ResponseWriter, req *http.Request) {
	id := req.PathValue("id")
	r.mu.Lock()
	s, exists := r.slots[id]
	r.mu.Unlock()

	if !exists {
		logf(req, "LISTEN %q — not found", id)
		http.Error(w, "id not found", http.StatusNotFound)
		return
	}

	if !strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
		logf(req, "LISTEN %q — missing websocket upgrade", id)
		http.Error(w, "websocket required", http.StatusBadRequest)
		return
	}

	conn, rw, err := wsHandshake(w, req)
	if err != nil {
		logf(req, "LISTEN %q — handshake error: %v", id, err)
		return
	}
	defer conn.Close()

	logf(req, "LISTEN %q — websocket connected", id)
	sent := 0

	for {
		select {
		case <-s.done:
			logf(req, "LISTEN %q — slot expired, closing (sent %d messages)", id, sent)
			rw.Flush()
			return
		case msg := <-s.send:
			if err := wsWriteFrame(rw, msg); err != nil {
				logf(req, "LISTEN %q — write error after %d messages: %v", id, sent, err)
				return
			}
			rw.Flush()
			sent++
			logf(req, "LISTEN %q — delivered msg #%d (%d bytes)", id, sent, len(msg))
		}
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

// truncate returns a printable snippet of data, safe for logs.
func truncate(data []byte, max int) string {
	s := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '.'
		}
		return r
	}, string(data))
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}

// ── main ──────────────────────────────────────────────────────────────────────

func main() {
	relay := NewRelay()

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/take/{id}", relay.handleTake)
	mux.HandleFunc("POST /api/keep/{id}", relay.handleKeep)
	mux.HandleFunc("POST /api/send/{id}", relay.handleSend)
	mux.HandleFunc("GET /api/listen/{id}", relay.handleListen)

	fmt.Println("listening on :8080")
	if err := http.ListenAndServe(":8080", mux); err != nil { //nolint:gosec // just ignore
		log.Fatal(err)
	}
}
