package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"

	"github.com/withoutforget/secureChat/internal/chat"
	"github.com/withoutforget/secureChat/internal/client"
	"github.com/withoutforget/secureChat/internal/identity"
)

const (
	defaultServer = "http://localhost:8080"
	windowWidth   = 850
	windowHeight  = 550
)

// ── data ──────────────────────────────────────────────────────────────────────

type chatMsg struct {
	sender string
	text   string
}

type contactEntry struct {
	peerID  string
	trusted bool
	msgs    []chatMsg
	writeCh chan<- []byte
}

type appState struct {
	mu          sync.Mutex
	chatInst    *chat.Chat
	contacts    []*contactEntry
	selectedIdx int // -1 = none selected

	// fyne refs
	win         fyne.Window
	contactList *widget.List
	rightPanel  *fyne.Container

	// currently displayed chat widgets (nil when placeholder is shown)
	activePeerID string
	activeMsgLbl *widget.Label
	activeScroll *container.Scroll
}

var state *appState

// ── helpers ───────────────────────────────────────────────────────────────────

func generateID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand unavailable")
	}
	return hex.EncodeToString(b)
}

// ── login screen ──────────────────────────────────────────────────────────────

func showLogin(_ fyne.App, w fyne.Window) {
	title := widget.NewLabelWithStyle(
		"secureChat",
		fyne.TextAlignCenter,
		fyne.TextStyle{Bold: true},
	)

	// ── ID row ──
	idEntry := widget.NewEntry()
	idEntry.SetPlaceHolder("e.g. alice123")

	genIDBtn := widget.NewButton("Random", func() {
		idEntry.SetText(generateID())
	})

	// ── Key section ──
	var creds *identity.Credential

	keyPathEntry := widget.NewEntry()
	keyPathEntry.SetPlaceHolder("Path to ed25519 PEM (optional)")

	keyStatus := widget.NewLabel("No key — will be generated on Enter")

	loadKeyBtn := widget.NewButton("Load", func() {
		path := strings.TrimSpace(keyPathEntry.Text)
		if path == "" {
			keyStatus.SetText("Enter a file path first")
			return
		}
		c, err := identity.LoadCredential(path)
		if err != nil {
			keyStatus.SetText("Error: " + err.Error())
			return
		}
		creds = c
		keyStatus.SetText("Loaded  " + truncate(c.String(), 24))
	})

	genKeyBtn := widget.NewButton("Generate Key", func() {
		c, err := identity.GenerateCredential()
		if err != nil {
			keyStatus.SetText("Error: " + err.Error())
			return
		}
		creds = c
		keyStatus.SetText("Generated  " + truncate(c.String(), 24))
	})

	// ── Server row ──
	serverEntry := widget.NewEntry()
	serverEntry.SetText(defaultServer)

	// ── Enter ──
	errorLbl := widget.NewLabel("")

	enterBtn := widget.NewButton("Enter", func() {
		id := strings.TrimSpace(idEntry.Text)
		if id == "" {
			errorLbl.SetText("ID is required")
			return
		}
		serverURL := strings.TrimSpace(serverEntry.Text)
		if serverURL == "" {
			errorLbl.SetText("Server URL is required")
			return
		}

		// auto-generate key if not loaded
		if creds == nil {
			c, err := identity.GenerateCredential()
			if err != nil {
				errorLbl.SetText("keygen: " + err.Error())
				return
			}
			creds = c
		}

		ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT)
		_ = cancel

		cl := client.NewClient(serverURL)
		chatInst := chat.NewChat(ctx, cl, creds, id)

		if err := chatInst.Register(); err != nil {
			errorLbl.SetText("Register: " + err.Error())
			return
		}

		state = &appState{
			chatInst:    chatInst,
			selectedIdx: -1,
			win:         w,
		}

		showMain(w)
	})

	// ── layout ──
	form := container.NewVBox(
		title,
		widget.NewSeparator(),

		widget.NewLabel("Your ID"),
		container.NewBorder(nil, nil, nil, genIDBtn, idEntry),

		widget.NewSeparator(),
		widget.NewLabel("Ed25519 Key"),
		container.NewBorder(nil, nil, nil, loadKeyBtn, keyPathEntry),
		genKeyBtn,
		keyStatus,

		widget.NewSeparator(),
		widget.NewLabel("Server"),
		serverEntry,

		widget.NewSeparator(),
		errorLbl,
		enterBtn,
	)

	// centre the form with some breathing room
	padded := container.NewVBox(
		layout.NewSpacer(),
		container.NewHBox(layout.NewSpacer(), form, layout.NewSpacer()),
		layout.NewSpacer(),
	)
	w.SetContent(padded)
}

// ── main screen (contacts + chat) ─────────────────────────────────────────────

func showMain(w fyne.Window) {
	// ── top bar ──
	copyBtn := widget.NewButton("Copy My Info", func() {
		info := state.chatInst.ID() + "|" + state.chatInst.PubKeyHex()
		w.Clipboard().SetContent(info)
		dialog.ShowInformation("Copied",
			"Share this string with your peer.\nThey paste it in «Add Contact».", w)
	})

	connectStatus := widget.NewLabel("")
	addBtn := widget.NewButton("+ Add Contact", nil) // handler set below
	addBtn.OnTapped = func() { showAddContact(w, addBtn, connectStatus) }

	topBar := container.NewHBox(copyBtn, layout.NewSpacer(), connectStatus, addBtn)

	// ── contact list ──
	contactList := widget.NewList(
		func() int {
			state.mu.Lock()
			defer state.mu.Unlock()
			return len(state.contacts)
		},
		func() fyne.CanvasObject {
			return container.NewHBox(
				widget.NewLabel("placeholder-id"),
				layout.NewSpacer(),
				widget.NewLabel(""),
			)
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			state.mu.Lock()
			if id >= len(state.contacts) {
				state.mu.Unlock()
				return
			}
			c := state.contacts[id]
			state.mu.Unlock()

			box := obj.(*fyne.Container)
			box.Objects[0].(*widget.Label).SetText(c.peerID)
			mark := "⚠"
			if c.trusted {
				mark = "✓"
			}
			box.Objects[2].(*widget.Label).SetText(mark)
		},
	)

	contactList.OnSelected = func(id widget.ListItemID) {
		state.mu.Lock()
		if id >= len(state.contacts) {
			state.mu.Unlock()
			return
		}
		state.selectedIdx = id
		state.mu.Unlock()
		showChatForSelected()
	}
	state.contactList = contactList

	// ── right panel (placeholder) ──
	placeholder := container.NewCenter(
		widget.NewLabel("Select a contact to start chatting"),
	)
	rightPanel := container.NewMax(placeholder)
	state.rightPanel = rightPanel

	// ── split ──
	split := container.NewHSplit(contactList, rightPanel)
	split.SetOffset(0.28)

	whole := container.NewBorder(
		container.NewVBox(topBar, widget.NewSeparator()),
		nil, nil, nil,
		split,
	)
	w.SetContent(whole)
}

// ── add contact dialog ────────────────────────────────────────────────────────

func showAddContact(w fyne.Window, addBtn *widget.Button, statusLbl *widget.Label) {
	peerEntry := widget.NewEntry()
	peerEntry.SetPlaceHolder("id|base64pubkey   or just id")

	items := []*widget.FormItem{
		widget.NewFormItem("Peer info", peerEntry),
	}

	dialog.ShowForm("Add Contact", "Connect", "Cancel", items, func(ok bool) {
		if !ok {
			return
		}

		raw := strings.TrimSpace(peerEntry.Text)
		if raw == "" {
			return
		}

		var peerID string
		var trustedKey []byte

		if parts := strings.SplitN(raw, "|", 2); len(parts) == 2 {
			peerID = parts[0]
			decoded, err := base64.StdEncoding.DecodeString(parts[1])
			if err != nil {
				dialog.ShowError(fmt.Errorf("bad pubkey: %w", err), w)
				return
			}
			trustedKey = decoded
		} else {
			peerID = raw
		}

		addBtn.Disable()
		statusLbl.SetText("connecting to " + peerID + "…")

		go func() {
			err := state.chatInst.ContactWith(peerID, trustedKey)

			fyne.Do(func() {
				addBtn.Enable()
				statusLbl.SetText("")

				if err != nil {
					dialog.ShowError(fmt.Errorf("handshake: %w", err), w)
					return
				}

				trusted, _ := state.chatInst.Trusted(peerID)
				readCh, writeCh, ioErr := state.chatInst.IO(peerID)
				if ioErr != nil {
					dialog.ShowError(ioErr, w)
					return
				}

				entry := &contactEntry{
					peerID:  peerID,
					trusted: trusted,
					writeCh: writeCh,
				}

				state.mu.Lock()
				state.contacts = append(state.contacts, entry)
				idx := len(state.contacts) - 1
				state.mu.Unlock()

				state.contactList.Refresh()
				state.contactList.Select(idx)

				go readerLoop(entry, readCh, idx)
			})
		}()
	}, w)
}

// ── reader goroutine (one per contact) ────────────────────────────────────────

func readerLoop(entry *contactEntry, readCh <-chan []byte, contactIdx int) {
	for msg := range readCh {
		text := string(msg)

		state.mu.Lock()
		entry.msgs = append(entry.msgs, chatMsg{sender: entry.peerID, text: text})
		isActive := state.selectedIdx == contactIdx && state.activePeerID == entry.peerID
		state.mu.Unlock()

		if isActive {
			fyne.Do(func() {
				appendMsgToUI(entry.peerID, text)
			})
		}
	}
}

// ── chat view ─────────────────────────────────────────────────────────────────

func showChatForSelected() {
	state.mu.Lock()
	if state.selectedIdx < 0 || state.selectedIdx >= len(state.contacts) {
		state.mu.Unlock()
		return
	}
	contact := state.contacts[state.selectedIdx]
	state.mu.Unlock()

	// ── header ──
	trustText := "⚠ Connection is NOT authenticated — MITM possible"
	if contact.trusted {
		trustText = "✓ Authenticated"
	}
	header := container.NewVBox(
		widget.NewLabelWithStyle(
			"Chat with: "+contact.peerID,
			fyne.TextAlignLeading,
			fyne.TextStyle{Bold: true},
		),
		widget.NewLabel(trustText),
		widget.NewSeparator(),
	)

	// ── message area ──
	msgLabel := widget.NewLabel("")
	msgLabel.Wrapping = fyne.TextWrapWord

	state.mu.Lock()
	var sb strings.Builder
	for _, m := range contact.msgs {
		sb.WriteString(fmt.Sprintf("[%s]: %s\n", m.sender, m.text))
	}
	state.mu.Unlock()
	msgLabel.SetText(sb.String())

	scroll := container.NewScroll(msgLabel)
	scroll.SetMinSize(fyne.NewSize(400, 250))

	state.activeMsgLbl = msgLabel
	state.activeScroll = scroll
	state.activePeerID = contact.peerID

	// ── input row ──
	input := widget.NewEntry()
	input.SetPlaceHolder("Message…")

	sendFn := func() {
		text := strings.TrimSpace(input.Text)
		if text == "" {
			return
		}
		input.SetText("")

		// non-blocking send
		go func() {
			contact.writeCh <- []byte(text)
		}()

		state.mu.Lock()
		contact.msgs = append(contact.msgs, chatMsg{sender: "You", text: text})
		state.mu.Unlock()

		appendMsgToUI("You", text)
	}

	sendBtn := widget.NewButton("Send", sendFn)
	input.OnSubmitted = func(_ string) { sendFn() }

	inputRow := container.NewBorder(nil, nil, nil, sendBtn, input)

	// ── assemble ──
	chatView := container.NewBorder(header, inputRow, nil, nil, scroll)

	state.rightPanel.Objects = []fyne.CanvasObject{chatView}
	state.rightPanel.Refresh()
}

func appendMsgToUI(sender, text string) {
	if state.activeMsgLbl == nil {
		return
	}
	cur := state.activeMsgLbl.Text
	cur += fmt.Sprintf("[%s]: %s\n", sender, text)
	state.activeMsgLbl.SetText(cur)
	state.activeScroll.ScrollToBottom()
}

// ── util ──────────────────────────────────────────────────────────────────────

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// ── entrypoint ────────────────────────────────────────────────────────────────

func main() {
	slog.SetLogLoggerLevel(slog.LevelDebug)

	a := app.New()
	w := a.NewWindow("secureChat")
	w.Resize(fyne.NewSize(windowWidth, windowHeight))

	showLogin(a, w)
	w.ShowAndRun()
}
