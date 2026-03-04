package main

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/withoutforget/secureChat/internal/client"
	"github.com/withoutforget/secureChat/internal/identity"
	"github.com/withoutforget/secureChat/internal/message"
)

const SERVER_URL = "http://localhost:8080"

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT)
	defer cancel()

	reader := bufio.NewReader(os.Stdin)

	creds, err := identity.GenerateCredential()
	if err != nil {
		panic("cannot create credentials: " + err.Error())
	}
	fmt.Printf("ed25519:\"%v\"\n", creds.String())

	c := client.NewClient(SERVER_URL)

	myID, peerID, trustedKey := readSetup(reader, c)

	go keepAlive(ctx, c, myID)

	stream, err := c.Recv(myID)
	if err != nil {
		panic("cannot get stream: " + err.Error())
	}

	secret := doHandshake(c, creds, stream, peerID, trustedKey)

	go recvLoop(ctx, cancel, stream, secret)
	go sendLoop(ctx, reader, c, peerID, secret)

	<-ctx.Done()
}

func readSetup(reader *bufio.Reader,
	c *client.Client) (
	myID,
	peerID string,
	trustedKey []byte,
) {
	fmt.Printf("Input your id:")
	myID, _ = reader.ReadString('\n')
	myID = strings.TrimSpace(myID)
	if err := c.Take(myID); err != nil {
		panic(err)
	}

	fmt.Printf("Input peer id:")
	peerID, _ = reader.ReadString('\n')
	peerID = strings.TrimSpace(peerID)

	fmt.Printf("Input peer ed25519 (or -):")
	peerKey, _ := reader.ReadString('\n')
	peerKey = strings.TrimSpace(peerKey)

	if peerKey != "-" {
		var err error
		trustedKey, err = identity.ParseCredential(peerKey)
		if err != nil {
			panic("invalid key: " + err.Error())
		}
	}

	return myID, peerID, trustedKey
}

func keepAlive(ctx context.Context,
	c *client.Client,
	myID string,
) {
	ticker := time.NewTicker(40 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := c.Keep(myID); err != nil {
				slog.Warn("Cannot keep id", slog.String("err", err.Error()))
			}
		case <-ctx.Done():
			return
		}
	}
}

func doHandshake(c *client.Client,
	creds *identity.Credential,
	stream <-chan []byte,
	peerID string,
	trustedKey []byte,
) *message.SecretMessage {
	secret, err := message.NewSecretMessage()
	if err != nil {
		panic("cannot create secret message: " + err.Error())
	}

	pb, salt := secret.GetPublicKey(), secret.GetSalt()
	keys := slices.Concat(salt, pb)
	sig := creds.Sign(keys)

	if err := c.Send(peerID, slices.Concat(keys, sig)); err != nil {
		panic("cannot send message: " + err.Error())
	}

	authResponse, ok := <-stream
	if !ok {
		panic("websocket closed")
	}

	salt = authResponse[:len(salt)]
	pb = authResponse[len(salt) : len(salt)+len(pb)]
	sig = authResponse[len(salt)+len(pb) : len(salt)+len(pb)+64]

	if trustedKey != nil {
		if err := identity.Verify(authResponse[:len(salt)+len(pb)], sig, trustedKey); err != nil {
			fmt.Printf("\n[WARN] ed25519 not verified\n\n")
		}
	} else {
		fmt.Printf("\n[WARN] not using ed25519 allows MITM\n\n")
	}

	if err := secret.SetUpSharedKey(pb, salt); err != nil {
		panic("cannot create shared key: " + err.Error())
	}

	return secret
}

func recvLoop(ctx context.Context,
	cancel context.CancelFunc,
	stream <-chan []byte,
	secret *message.SecretMessage,
) {
	for {
		select {
		case <-ctx.Done():
			return
		case data, ok := <-stream:
			if !ok {
				cancel()
				fmt.Println("websocket closed")
				return
			}
			text, err := secret.ReadMessage(data)
			if err != nil {
				fmt.Printf("Cannot decode message:%v\n", err.Error())
				continue
			}
			fmt.Printf("[PEER]:%v\n", string(text))
		}
	}
}

func sendLoop(ctx context.Context,
	reader *bufio.Reader,
	c *client.Client,
	peerID string,
	secret *message.SecretMessage,
) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			input, _ := reader.ReadString('\n')
			input = strings.TrimSpace(input)
			if input == "" {
				continue
			}
			encrypted, err := secret.GenerateMessage([]byte(input))
			if err != nil {
				fmt.Printf("Cannot encode message:%v\n", err.Error())
			}
			if err := c.Send(peerID, encrypted); err != nil {
				panic("cannot send message: " + err.Error())
			}
		}
	}
}
