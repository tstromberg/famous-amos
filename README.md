# brew-poker: Prodding the AMOS C2 with a Go stick

This is a byte-accurate replica of the `brew_agent` (Atomic Stealer) network client. It's designed to mimic a high-value "whale" victim to elicit manual interaction from live C2 operators on the `46.30.191.141` infrastructure.

### Technical Fidelity Features
*   **Dual-Channel Protocol:** Replicates the malware's split personality—Registration and large-file Exfiltration via **HTTP/80**, and the interactive command loop via a **Raw TCP Socket on 1337**.
*   **The Handshake:** Implements the mandatory `0x41765DDA` TCP signature. Without this, the C2 ignores the connection and the victim never appears "Online."
*   **Binary Multiplexing:** Uses the exact `60ebe5b6...` boundary and null-terminated TLV (Type-Length-Value) headers discovered in `sym.func.10001108c`. This is required for the server-side parser to "see" your fake loot.
*   **Reactive Shell Engine:** Provides behaviorally accurate, multi-line output for standard Darwin reconnaissance commands (`sw_vers`, `id`, `whoami`, `system_profiler`).
*   **Spyware Fidelity:** Uses `//go:embed` to exfiltrate a real `screenshot.jpg`, appending unique cryptographic entropy to every capture to ensure unique file hashes and sizes.

### Why?
Because watching a sophisticated operator manually browse a fake `~/Documents` folder looking for seed phrases is much more interesting than just reading assembly.

### Usage
```bash
go build -o poker main.go
./poker
```

### Protocol Alignment
*   **XOR:** Implements the rolling XOR routine using the uppercase Hex-UUID as the key.
*   **Headers:** Manually ordered HTTP headers to match `libcurl/8.4.0` signatures exactly.
*   **Jitter:** Randomized timing for heartbeats to bypass basic anomaly detection.

*For research and "lulz" only. Happy hunting.*
