package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/withoutforget/secureChat/internal/chat"
	"github.com/withoutforget/secureChat/internal/client"
	"github.com/withoutforget/secureChat/internal/identity"
)

const serverURL = "http://localhost:8080"

func runTUI(ctx context.Context, chat *chat.Chat) {
	scanner := bufio.NewScanner(os.Stdin)

	fmt.Print("peer id: ")
	if !scanner.Scan() {
		return
	}
	peerID := strings.TrimSpace(scanner.Text())

	fmt.Print("trusted key (hex, enter to skip): ")
	if !scanner.Scan() {
		return
	}
	var trustedKey []byte
	if raw := strings.TrimSpace(scanner.Text()); raw != "" {
		var err error
		trustedKey, err = base64.StdEncoding.DecodeString(raw)
		if err != nil {
			trustedKey, err = hex.DecodeString(raw)
		}
		if err != nil {
			slog.Error("bad key (expected base64 or hex)", slog.String("err", err.Error()))
			return
		}
	}

	if err := chat.ContactWith(peerID, trustedKey); err != nil {
		slog.Error("contact", slog.String("err", err.Error()))
		return
	}

	trusted, _ := chat.Trusted(peerID)
	if !trusted {
		fmt.Println("[WARN] connection is NOT authenticated — MITM possible")
	}

	read, write, err := chat.IO(peerID)
	if err != nil {
		slog.Error("io", slog.String("err", err.Error()))
		return
	}

	// incoming messages
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case msg, ok := <-read:
				if !ok {
					return
				}
				fmt.Printf("\r[%s]: %s\n> ", peerID, msg)
			}
		}
	}()

	// outgoing messages
	for {
		fmt.Print("> ")
		select {
		case <-ctx.Done():
			return
		default:
			if !scanner.Scan() {
				return
			}
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			select {
			case write <- []byte(line):
			case <-ctx.Done():
				return
			}
		}
	}
}

func generateID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand unavailable")
	}
	return hex.EncodeToString(b)
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT)
	defer cancel()

	c := client.NewClient(serverURL)
	creds, err := identity.GenerateCredential()
	if err != nil {
		slog.Error("generate credentials", slog.String("err", err.Error()))
		return
	}

	id := generateID()
	chat := chat.NewChat(ctx, c, creds, id)

	fmt.Printf("ed25519: %s\n", chat.PubKeyHex())
	fmt.Printf("id:      %s\n", chat.ID())

	if err := chat.Register(); err != nil {
		slog.Error("register", slog.String("err", err.Error()))
		return
	}

	runTUI(ctx, chat)
}
