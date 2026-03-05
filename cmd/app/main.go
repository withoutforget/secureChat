/*
----------------------------------------
Сейчас тут всё навайбкожено, но работает.
потом буду править.
----------------------------------------
*/

package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"context"
	"crypto/rand"
	"log/slog"
	"os/signal"
	"syscall"

	"github.com/withoutforget/secureChat/internal/chat"
	"github.com/withoutforget/secureChat/internal/client"
	"github.com/withoutforget/secureChat/internal/identity"
)

const serverURL = "http://localhost:8080"

var (
	a       fyne.App
	w       fyne.Window
	content *fyne.Container // сюда подставляем экраны
)

// Шапка — всегда видна
func makeHeader(c *chat.Chat) fyne.CanvasObject {
	pubEntry := widget.NewEntry()
	pubEntry.SetText(c.PubKeyHex())
	pubEntry.Disable()

	idEntry := widget.NewEntry()
	idEntry.SetText(c.ID())
	idEntry.Disable()

	return container.NewVBox(
		container.NewGridWithColumns(2,
			widget.NewLabel("ID:"), idEntry,
			widget.NewLabel("PubKey:"), pubEntry,
		),
		widget.NewSeparator(),
	)
}

// Экран подключения
func showConnect(c *chat.Chat) {
	peerIDEntry := widget.NewEntry()
	peerIDEntry.SetPlaceHolder("Peer ID")

	peerKeyEntry := widget.NewEntry()
	peerKeyEntry.SetPlaceHolder("Trusted key (hex/base64, необязательно)")

	statusLabel := widget.NewLabel("")

	content.Objects[1] = container.NewVBox(
		widget.NewLabel("Подключиться к пиру:"),
		peerIDEntry,
		peerKeyEntry,
		statusLabel,
		widget.NewButton("Подключиться", func() {
			peerID := strings.TrimSpace(peerIDEntry.Text)
			if peerID == "" {
				statusLabel.SetText("Введите Peer ID")
				return
			}

			var trustedKey []byte
			if raw := strings.TrimSpace(peerKeyEntry.Text); raw != "" {
				var err error
				trustedKey, err = base64.StdEncoding.DecodeString(raw)
				if err != nil {
					trustedKey, err = hex.DecodeString(raw)
				}
				if err != nil {
					statusLabel.SetText("Неверный формат ключа")
					return
				}
			}

			if err := c.ContactWith(peerID, trustedKey); err != nil {
				statusLabel.SetText("Ошибка: " + err.Error())
				return
			}

			trusted, _ := c.Trusted(peerID)
			showChat(c, peerID, trusted)
		}),
	)
	content.Refresh()
}

// Экран чата
func showChat(c *chat.Chat, peerID string, trusted bool) {
	msgText := ""
	msgLabel := widget.NewLabel("")
	msgLabel.Wrapping = fyne.TextWrapWord

	scroll := container.NewScroll(msgLabel)
	scroll.SetMinSize(fyne.NewSize(460, 280))

	addMessage := func(who, text string) {
		msgText += fmt.Sprintf("[%s]: %s\n", who, text)
		msgLabel.SetText(msgText)
		scroll.ScrollToBottom()
	}

	input := widget.NewEntry()
	input.SetPlaceHolder("Сообщение...")

	read, write, err := c.IO(peerID)
	if err != nil {
		showConnect(c)
		return
	}

	go func() {
		for msg := range read {
			msg := msg
			fyne.Do(func() { addMessage(peerID, string(msg)) })
		}
	}()

	sendBtn := widget.NewButton("→", func() {
		text := strings.TrimSpace(input.Text)
		if text == "" {
			return
		}
		write <- []byte(text)
		addMessage("Вы", text)
		input.SetText("")
	})

	input.OnSubmitted = func(_ string) { sendBtn.OnTapped() }

	warn := widget.NewLabel("")
	if !trusted {
		warn.SetText("⚠️  Соединение НЕ аутентифицировано — возможен MITM")
	}

	backBtn := widget.NewButton("← Назад", func() { showConnect(c) })

	content.Objects[1] = container.NewBorder(
		container.NewVBox(
			container.NewHBox(backBtn, widget.NewLabel("Чат с: "+peerID)),
			warn,
		),
		container.NewBorder(nil, nil, nil, sendBtn, input),
		nil, nil,
		scroll,
	)
	content.Refresh()
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
	chatInstance := chat.NewChat(ctx, c, creds, id)

	if err := chatInstance.Register(); err != nil {
		slog.Error("register", slog.String("err", err.Error()))
		return
	}

	a = app.New()
	w = a.NewWindow("secureChat")
	w.Resize(fyne.NewSize(520, 480))

	// content[0] = шапка (всегда), content[1] = текущий экран
	content = container.NewVBox(
		makeHeader(chatInstance),
		widget.NewLabel(""), // placeholder, заменяется
	)

	w.SetContent(content)
	showConnect(chatInstance)
	w.ShowAndRun()
}
