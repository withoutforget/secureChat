package chat

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/withoutforget/secureChat/internal/client"
	"github.com/withoutforget/secureChat/internal/identity"
	"github.com/withoutforget/secureChat/internal/message"
)

var (
	errRegister  = errors.New("cannot register")
	errHandshake = errors.New("handshake failed")
)

// ChatInfo holds per-peer session state.
type ChatInfo struct {
	Secret  *message.SecretMessage
	Trusted bool
	Stream  <-chan []byte
}

// Chat manages registration, handshake, and encrypted IO with peers.
// It does NOT touch stdin/stdout — all user interaction goes through channels.
type Chat struct {
	ctx    context.Context
	client client.Client
	myID   string
	creds  *identity.Credential

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

// ID returns the local identifier so the caller can display it.
func (c *Chat) ID() string { return c.myID }

// PubKeyHex returns the ed25519 public key as hex for display.
func (c *Chat) PubKeyHex() string { return c.creds.String() }

// Register claims the ID on the server and starts the keep-alive loop.
func (c *Chat) Register() error {
	if err := c.client.Take(c.myID); err != nil {
		return fmt.Errorf("%w: %w", errRegister, err)
	}
	go c.keepAlive()
	return nil
}

// ContactWith performs a handshake with peerID.
// trustedKey may be nil — in that case the connection is unauthenticated.
func (c *Chat) ContactWith(peerID string, trustedKey []byte) error {
	stream, err := c.client.Recv(c.myID)
	if err != nil {
		return fmt.Errorf("recv stream: %w", err)
	}

	info, err := c.handshake(stream, peerID, trustedKey)
	if err != nil {
		return fmt.Errorf("handshake with %s: %w", peerID, err)
	}

	c.peers[peerID] = info
	return nil
}

// Trusted reports whether the peer's key was verified.
func (c *Chat) Trusted(peerID string) (bool, error) {
	info, ok := c.peers[peerID]
	if !ok {
		return false, fmt.Errorf("peer %s: not found", peerID)
	}
	return info.Trusted, nil
}

// IO returns a read channel and a write channel for the given peer.
// The caller owns both channels; close write when done sending.
func (c *Chat) IO(peerID string) (<-chan []byte, chan<- []byte, error) {
	info, ok := c.peers[peerID]
	if !ok {
		return nil, nil, fmt.Errorf("peer %s: not found", peerID)
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
		case raw, ok := <-info.Stream:
			if !ok {
				return
			}
			plain, err := info.Secret.ReadMessage(raw)
			if err != nil {
				slog.Warn("decrypt failed", slog.String("err", err.Error()))
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
			if err := c.client.Send(peerID, cipher); err != nil {
				slog.Warn("send failed", slog.String("err", err.Error()))
			}
		}
	}
}

// keepAlive periodically pings the server so the ID stays reserved.
func (c *Chat) keepAlive() {
	ticker := time.NewTicker(40 * time.Second)
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
func (c *Chat) handshake(
	stream <-chan []byte,
	peerID string,
	trustedKey []byte,
) (*ChatInfo, error) {
	secret, err := message.NewSecretMessage()
	if err != nil {
		return nil, err
	}

	pub, salt := secret.GetPublicKey(), secret.GetSalt()
	payload := slices.Concat(salt, pub)
	sig := c.creds.Sign(payload)

	if err := c.client.Send(peerID, slices.Concat(payload, sig)); err != nil {
		return nil, fmt.Errorf("send handshake: %w", err)
	}
	var resp []byte

	select {
	case tmp, ok := <-stream:
		if !ok {
			return nil, fmt.Errorf("%w: stream closed before response", errHandshake)
		}
		resp = tmp
	case <-c.ctx.Done():
		return nil, c.ctx.Err()
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
		return nil, fmt.Errorf("shared key: %w", err)
	}

	return &ChatInfo{
		Secret:  secret,
		Trusted: trusted,
		Stream:  stream,
	}, nil
}
