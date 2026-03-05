package chat

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/withoutforget/secureChat/internal/client"
	"github.com/withoutforget/secureChat/internal/identity"
	"github.com/withoutforget/secureChat/internal/message"
)

const (
	// HandshakeTimeout is how long ContactWith waits for the peer to respond.
	HandshakeTimeout = 30 * time.Second

	handshakeRetryInterval = 3 * time.Second
	// How many extra sends after handshake completes, to make sure the peer gets our hs.
	handshakeFinalResends = 3
	handshakeFinalDelay   = 500 * time.Millisecond

	keepAliveInterval = 40 * time.Second
	inboxBuffer       = 64
)

var (
	errRegister     = errors.New("cannot register")
	errHandshake    = errors.New("handshake failed")
	errPeerNotFound = errors.New("peer not found")
)

// ChatInfo holds per-peer session state.
type ChatInfo struct {
	Secret  *message.SecretMessage
	Trusted bool
	inbox   chan []byte
}

// Chat manages registration, handshake, and encrypted IO with peers.
type Chat struct {
	ctx    context.Context
	client client.Client
	myID   string
	creds  *identity.Credential

	mu    sync.Mutex
	peers map[string]*ChatInfo
}

func NewChat(
	ctx context.Context,
	c client.Client,
	creds *identity.Credential,
	id string,
) *Chat {
	return &Chat{
		ctx:    ctx,
		client: c,
		myID:   id,
		creds:  creds,
		peers:  make(map[string]*ChatInfo),
	}
}

func (c *Chat) ID() string        { return c.myID }
func (c *Chat) PubKeyHex() string { return c.creds.String() }

// Register claims the ID on the server, opens a single Recv stream,
// and starts the keep-alive + router goroutines.
func (c *Chat) Register() error {
	if err := c.client.Take(c.myID); err != nil {
		return fmt.Errorf("%w: %w", errRegister, err)
	}

	stream, err := c.client.Recv(c.myID)
	if err != nil {
		return fmt.Errorf("recv stream: %w", err)
	}

	go c.router(stream)
	go c.keepAlive()
	return nil
}

func (c *Chat) router(stream <-chan client.Envelope) {
	for {
		select {
		case <-c.ctx.Done():
			return
		case env, ok := <-stream:
			if !ok {
				return
			}
			c.mu.Lock()
			info, exists := c.peers[env.From]
			c.mu.Unlock()

			if !exists {
				slog.Debug("message from unknown peer, dropping",
					slog.String("from", env.From))
				continue
			}

			select {
			case info.inbox <- env.Data:
			default:
				slog.Warn("inbox full, dropping message",
					slog.String("from", env.From))
			}
		}
	}
}

// ContactWith performs a handshake with peerID.
// trustedKey may be nil — in that case the connection is unauthenticated.
func (c *Chat) ContactWith(peerID string, trustedKey []byte) error {
	info := &ChatInfo{inbox: make(chan []byte, inboxBuffer)}

	c.mu.Lock()
	c.peers[peerID] = info
	c.mu.Unlock()

	ctx, cancel := context.WithTimeout(c.ctx, HandshakeTimeout)
	defer cancel()

	if err := c.handshake(ctx, info, peerID, trustedKey); err != nil {
		c.mu.Lock()
		delete(c.peers, peerID)
		c.mu.Unlock()
		return fmt.Errorf("handshake with %s: %w", peerID, err)
	}

	return nil
}

func (c *Chat) Trusted(peerID string) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	info, ok := c.peers[peerID]
	if !ok {
		return false, fmt.Errorf("%w: %s", errPeerNotFound, peerID)
	}
	return info.Trusted, nil
}

// IO returns a read channel and a write channel for the given peer.
func (c *Chat) IO(peerID string) (<-chan []byte, chan<- []byte, error) {
	c.mu.Lock()
	info, ok := c.peers[peerID]
	c.mu.Unlock()

	if !ok {
		return nil, nil, fmt.Errorf("%w: %s", errPeerNotFound, peerID)
	}

	read := make(chan []byte)
	write := make(chan []byte)

	go c.readLoop(info, read)
	go c.writeLoop(info, peerID, write)

	return read, write, nil
}

func (c *Chat) readLoop(info *ChatInfo, out chan<- []byte) {
	defer close(out)
	for {
		select {
		case <-c.ctx.Done():
			return
		case raw, ok := <-info.inbox:
			if !ok {
				return
			}
			plain, err := info.Secret.ReadMessage(raw)
			if err != nil {
				// Expected after handshake: stale retry messages from
				// the peer land here and can't be decrypted. Skip them.
				slog.Debug("decrypt failed (likely stale handshake), skipping",
					slog.String("err", err.Error()))
				continue
			}
			select {
			case <-c.ctx.Done():
				return
			case out <- plain:
			}
		}
	}
}

func (c *Chat) writeLoop(info *ChatInfo, peerID string, in <-chan []byte) {
	for {
		select {
		case <-c.ctx.Done():
			return
		case plain, ok := <-in:
			if !ok {
				return
			}
			cipher, err := info.Secret.GenerateMessage(plain)
			if err != nil {
				slog.Warn("encrypt failed", slog.String("err", err.Error()))
				continue
			}
			if err := c.client.Send(peerID, c.myID, cipher); err != nil {
				slog.Warn("send failed", slog.String("err", err.Error()))
			}
		}
	}
}

func (c *Chat) keepAlive() {
	ticker := time.NewTicker(keepAliveInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := c.client.Keep(c.myID); err != nil {
				slog.Warn("keep-alive failed", slog.String("err", err.Error()))
			}
		case <-c.ctx.Done():
			return
		}
	}
}

// handshake exchanges DH keys and (optionally) verifies the peer's ed25519 signature.
//
// Both peers run the same logic:
//  1. send our pub+salt+sig
//  2. retry every 3 s (peer's router may not know us yet)
//  3. wait for peer's pub+salt+sig
//  4. after receiving — send our message a few more times so the peer
//     is guaranteed to get it (fixes the race where we complete and
//     stop retrying before the peer has registered us)
func (c *Chat) handshake(
	ctx context.Context,
	info *ChatInfo,
	peerID string,
	trustedKey []byte,
) error {
	secret, err := message.NewSecretMessage()
	if err != nil {
		return err
	}

	pub, salt := secret.GetPublicKey(), secret.GetSalt()
	payload := slices.Concat(salt, pub)
	sig := c.creds.Sign(payload)
	hsMsg := slices.Concat(payload, sig)

	// ── phase 1: send + retry ────────────────────────────────────────────

	if err := c.client.Send(peerID, c.myID, hsMsg); err != nil {
		return fmt.Errorf("send handshake: %w", err)
	}

	retryDone := make(chan struct{})
	go func() {
		ticker := time.NewTicker(handshakeRetryInterval)
		defer ticker.Stop()
		for {
			select {
			case <-retryDone:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = c.client.Send(peerID, c.myID, hsMsg)
			}
		}
	}()

	// ── phase 2: wait for peer's handshake ───────────────────────────────

	var resp []byte
	select {
	case tmp, ok := <-info.inbox:
		if !ok {
			close(retryDone)
			return fmt.Errorf("%w: inbox closed before response", errHandshake)
		}
		resp = tmp
	case <-ctx.Done():
		close(retryDone)
		return ctx.Err()
	}
	close(retryDone)

	// ── phase 3: final resends ───────────────────────────────────────────
	// The peer may have just registered us in their peers map.
	// Their earlier retries were dropped by our router (we weren't in their map),
	// and they received OUR message and completed — stopping THEIR retries.
	// So we must send a few more times to make sure they get ours.
	go func() {
		for range handshakeFinalResends {
			time.Sleep(handshakeFinalDelay)
			_ = c.client.Send(peerID, c.myID, hsMsg)
		}
	}()

	// ── phase 4: verify + derive keys ────────────────────────────────────

	minLen := len(salt) + len(pub) + 64
	if len(resp) < minLen {
		return fmt.Errorf("%w: response too short (%d < %d)", errHandshake, len(resp), minLen)
	}

	peerSalt := resp[:len(salt)]
	peerPub := resp[len(salt) : len(salt)+len(pub)]
	peerSig := resp[len(salt)+len(pub) : len(salt)+len(pub)+64]

	trusted := false
	if trustedKey != nil {
		if err := identity.Verify(resp[:len(salt)+len(pub)], peerSig, trustedKey); err != nil {
			slog.Warn("ed25519 verification failed", slog.String("peer", peerID))
		} else {
			trusted = true
		}
	}

	if err := secret.SetUpSharedKey(peerPub, peerSalt); err != nil {
		return fmt.Errorf("shared key: %w", err)
	}

	info.Secret = secret
	info.Trusted = trusted
	return nil
}
