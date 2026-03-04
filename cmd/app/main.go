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

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT)
	defer cancel()

	reader := bufio.NewReader(os.Stdin)
	creds, err := identity.GenerateCredential()

	if err != nil {
		panic("cannot create credentials: " + err.Error())
	}

	fmt.Printf("ed25519:\"%v\"\n", creds.String())

	client := client.NewClient("http://localhost:8080")

	var MyID string
	var PeerID string
	var PeerKey string
	fmt.Printf("Input your id:")
	MyID, _ = reader.ReadString('\n')
	MyID = strings.TrimSpace(MyID)
	if err := client.Take(MyID); err != nil {
		panic(err)
	}

	go func() {
		ticker := time.NewTicker(40 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := client.Keep(MyID); err != nil {
					slog.Warn("Cannot keep id", slog.String("err", err.Error()))
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	fmt.Printf("Input peer id:")
	PeerID, _ = reader.ReadString('\n')
	PeerID = strings.TrimSpace(PeerID)

	fmt.Printf("Input peer ed25519 (or -):")
	PeerKey, _ = reader.ReadString('\n')
	PeerKey = strings.TrimSpace(PeerKey)

	var trustedKey []byte
	if PeerKey != "-" {
		trustedKey, err = identity.ParseCredential(PeerKey)
		if err != nil {
			panic("invalid key: " + err.Error())
		}
	}

	stream, err := client.Recv(MyID)
	if err != nil {
		panic("cannot get stream: " + err.Error())
	}

	secret, err := message.NewSecretMessage()
	if err != nil {
		panic("cannot create secret message: " + err.Error())
	}

	pb, salt := secret.GetPublicKey(), secret.GetSalt()
	keys := slices.Concat(salt, pb)
	sig := creds.Sign(keys)

	err = client.Send(PeerID, slices.Concat(keys, sig))
	if err != nil {
		panic("cannot send message : " + err.Error())
	}

	auth_response, ok := <-stream
	if !ok {
		panic("websocket closed")
	}
	salt = auth_response[:len(salt)]
	pb = auth_response[len(salt) : len(salt)+len(pb)]
	sig = auth_response[len(salt)+len(pb) : len(salt)+len(pb)+64]
	if trustedKey != nil {
		err = identity.Verify(auth_response[:len(salt)+len(pb)], sig, trustedKey)
		if err != nil {
			fmt.Printf("[WARN] ed25519 not verified\n")
		}
	} else {
		fmt.Printf("[WARN] not using ed25519 allows MITM\n")
	}

	err = secret.SetUpSharedKey(pb, salt)
	if err != nil {
		panic("cannot create shared key: " + err.Error())
	}

	go func() {
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
	}()
	go func() {
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
				err = client.Send(PeerID, encrypted)
				if err != nil {
					panic("cannot send message : " + err.Error())
				}
			}
		}
	}()
	<-ctx.Done()
}
