# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an Android fork of Yggmail - a single-binary mail transfer agent that sends and receives email natively over the Yggdrasil Network. The key addition in this fork is Android library support via gomobile bindings in `mobile/`.

Email addresses are based on Ed25519 public keys (e.g., `89cd1ea25d99b8ccf29e454280313128c234ffb82aa0eb2e3496f6f156d063d0@yggmail`). The system also accepts `@yggmail.local` as a domain alias for compatibility with email clients that don't recognize the `yggmail` domain (e.g., Mailspring). All mail exchange traffic is end-to-end encrypted via Yggdrasil's built-in encryption.

## Development

### Prerequisites
- Go 1.25.5 or later
- **CGO enabled** (required for SQLite3 support via `mattn/go-sqlite3`)
- C compiler: gcc (Linux/macOS), MinGW-w64 or TDM-GCC (Windows)
- For Android builds: Android SDK and NDK (set `ANDROID_HOME` environment variable)
- For mobile bindings: `gomobile` tool (`go install golang.org/x/mobile/cmd/gomobile@latest`)

### Key Dependencies
- `github.com/yggdrasil-network/yggdrasil-go`: Core Yggdrasil network library
- `github.com/yggdrasil-network/yggquic`: QUIC transport over Yggdrasil (local development via `replace` directive in go.mod)
- `github.com/quic-go/quic-go`: QUIC protocol implementation
- `github.com/emersion/go-imap`, `go-smtp`: IMAP/SMTP protocol implementations
- `github.com/mattn/go-sqlite3`: SQLite3 database driver (requires CGO)
- `github.com/JB-SelfCompany/yggpeers`: Peer discovery and availability checking

**Important:** The `-ldflags="-checklinkname=0"` flag is required for gomobile builds due to a known issue with the `github.com/wlynxg/anet` dependency in Go 1.24+.

## Building

### Standard Binary
```bash
# Build the standard yggmail binary
go build -o yggmail ./cmd/yggmail

# Install to GOPATH
go install github.com/JB-SelfCompany/yggmail/cmd/yggmail@latest
```

### Android Library (AAR)

**Windows:**
```cmd
cd mobile
setup-gomobile.bat       # First-time setup (if it exists)
build-android.bat        # Full build (~40MB)
build-android-small.bat  # ARM64 only (~15MB)
```

Note: Build scripts are located in the `mobile/` directory.

**Linux/macOS:**
```bash
# Prerequisites
go install golang.org/x/mobile/cmd/gomobile@latest
gomobile init

# Build AAR (note: -ldflags required for Go 1.24+ compatibility)
gomobile bind -target=android -androidapi 23 -ldflags="-checklinkname=0" -o yggmail.aar github.com/JB-SelfCompany/yggmail/mobile

# ARM64 only (smaller)
gomobile bind -target=android/arm64 -androidapi 23 -ldflags="-checklinkname=0" -o yggmail.aar github.com/JB-SelfCompany/yggmail/mobile
```

**Important:** `-ldflags="-checklinkname=0"` flag is required to workaround a known issue with `github.com/wlynxg/anet` dependency in Go 1.24+. The `go.mod` uses `replace` directive for local `yggquic` development.

Requires Android SDK and NDK (set `ANDROID_HOME` environment variable).

### Docker Build

```bash
# Build Docker image
docker build -t yggmail .

# Run with multicast
docker run -p 1025:1025 -p 1143:1143 -v /path/to/data:/etc/yggmail yggmail -multicast

# Run with static peer
docker run -p 1025:1025 -p 1143:1143 -v /path/to/data:/etc/yggmail yggmail -peer=tls://peer-address:port
```

## Running

```bash
# Set password first (creates database if needed)
./yggmail -password

# Start with multicast discovery
./yggmail -multicast

# Start with static peer
./yggmail -peer=tls://[peer-address]:port

# Custom database location
./yggmail -database=/path/to/yggmail.db -multicast

# Custom SMTP/IMAP ports
./yggmail -smtp=localhost:2525 -imap=localhost:2143 -multicast

# Multicast with interface regex filter
./yggmail -multicast -mcastregexp="eth.*|wlan.*"

# Set password hash directly (bcrypt)
./yggmail -passwordHash="$2a$10$..."
```

Default ports:
- SMTP: localhost:1025
- IMAP: localhost:1143

Command-line flags:
- `-database`: Path to SQLite database file (default: `yggmail.db`)
- `-smtp`: SMTP listen address (default: `localhost:1025`)
- `-imap`: IMAP listen address (default: `localhost:1143`)
- `-peer`: Connect to Yggdrasil peer (can be specified multiple times)
- `-multicast`: Enable multicast peer discovery on LAN
- `-mcastregexp`: Regexp for multicast interface selection (default: `".*"`)
- `-password`: Interactive password setup
- `-passwordHash`: Set bcrypt password hash directly

## Architecture

### Core Components

1. **Transport Layer** (`internal/transport/`)
   - `YggdrasilTransport`: Manages Yggdrasil network connectivity using QUIC over Yggdrasil
   - Handles peer discovery (multicast + static peers), session management, and encrypted connections
   - Uses Ed25519 keys for node identity
   - Adaptive QUIC configuration: keep-alive varies from 5s (active) to 30s (background) for battery optimization

2. **Storage Layer** (`internal/storage/`)
   - Interface-based design with SQLite3 implementation (`storage/sqlite3/`)
   - Single database file stores: config, private keys, mailboxes, messages, and send queue
   - All mail operations (create, select, search, flags, expunge) go through storage interface
   - **Schema versioning and migrations** (`sqlite3/migrations.go`):
     - Current schema version: 2
     - Version 1→2 migration adds `mail_file` and `size` columns for large file support
     - Automatic migration on startup when schema version changes detected
   - **FileStore** (`storage/filestore/`): Optional file-based storage for large messages (>1MB)
     - Separate filesystem storage to handle messages beyond SQLite blob limits
     - Atomic writes (temp file + rename) to prevent corruption
     - Directory structure: `basePath/mailbox/messageID.eml`
     - Database stores path reference in `mail_file` column, actual content on filesystem

3. **IMAP Server** (`internal/imapserver/`)
   - `Backend`: Authentication and user management (internal/imapserver/backend.go)
   - `Mailbox`: IMAP mailbox operations (internal/imapserver/mailbox.go)
   - `IMAPNotify`: Push notifications for new mail (internal/imapserver/notify.go)
   - **Mobile-specific**: Added `Close()` method to `IMAPServer` (internal/imapserver/imap.go) for clean shutdown

4. **SMTP Components**
   - `internal/smtpserver/`: Receives mail (both local clients and remote Yggmail nodes)
     - `session_local.go`: Handles mail from local SMTP client, queues for delivery
     - `session_remote.go`: Receives mail from other Yggmail nodes over Yggdrasil
   - `internal/smtpsender/`: Queue manager that delivers outbound mail to remote Yggmail nodes
     - Exponential backoff retry: 60s, 120s, 240s... up to 3600s (60 min)
     - Adaptive queue manager: checks every 60s when active, 300s (5 min) when idle

5. **Mobile Bindings** (`mobile/yggmail.go`)
   - `YggmailService`: Main service class for Android/iOS integration
   - Callback interfaces: `LogCallback`, `MailCallback`, `ConnectionCallback`
   - Complete lifecycle management: Initialize → Start → Stop → Close
   - Battery optimization features:
     - Adaptive heartbeat: 5s (active), 30s (foreground), 2-29min (background/idle)
     - Idle timeout checker: monitors activity to optimize server behavior
     - Power state tracking: `SetActive()`, `SetCharging()` for adaptive behavior
   - Network transition handling: `OnNetworkChange()` for WiFi ↔ Mobile switches
   - Live peer updates: `UpdatePeers()` adds/removes peers without restart
   - Connection monitoring: `GetPeerConnections()` returns detailed peer stats

6. **Logging** (`internal/logging/`)
   - `LargeMailLogger`: Specialized logging for large mail operations
   - Tracks milestones and progress for send/receive operations
   - Operation tracking with unique IDs, timestamps, and byte counts
   - Used primarily for debugging large file transfers in E2E tests

### Data Flow

**Sending Mail:**
1. User's mail client connects to local SMTP server (port 1025)
2. `smtpserver/session_local.go` receives mail, stores in database, queues for destination
3. `smtpsender/sender.go` picks up queued mail
4. Mail delivered to remote Yggmail node via `YggdrasilTransport` using recipient's public key as destination

**Receiving Mail:**
1. Remote Yggmail node connects to local node via `YggdrasilTransport`
2. `smtpserver/session_remote.go` receives and validates sender identity
3. Mail stored in INBOX via storage layer
4. `IMAPNotify` pushes notification to connected IMAP clients

### Key Architecture Details

- **Identity Verification**: Sender's Ed25519 key must match `From` address; cryptographically enforced
- **Encryption**: All Yggdrasil connections are end-to-end encrypted by default
- **Queue System**: Outbound mail is queued per-destination; retried on delivery failure with exponential backoff
- **Mailbox System**: Default mailboxes (INBOX, Outbox) auto-created; additional mailboxes can be created via IMAP
- **Password Storage**: IMAP/SMTP password stored as bcrypt hash in database
- **Battery Optimization**: Adaptive timers throughout the stack reduce wakeups during idle periods
- **Message Size Limits**: Configurable maximum message size (default: 10 MB); incoming messages exceeding limit are rejected

### Message Size Limits

Users can configure the maximum size of individual messages that can be received. This helps control disk space usage and ensures compatibility with storage constraints.

**Key Features:**
- Default limit: 10 MB (user-configurable via mobile API)
- Automatic enforcement when receiving new messages
- Messages are rejected at SMTP level before data transfer (RFC 1870 SIZE extension)
- Pre-send size check available for 1-on-1 chats to avoid wasting bandwidth

**Mobile API Methods:**
```kotlin
// Set maximum message size in megabytes
yggmailService.setMaxMessageSizeMB(50)

// Get current maximum message size
val maxSizeMB = yggmailService.getMaxMessageSizeMB()

// Check recipient's message size limit BEFORE sending (for 1-on-1 chats)
val result = yggmailService.checkRecipientMessageSizeLimit(recipientEmail, messageSizeBytes)
if (!result.canSend) {
    // Show error to user: result.errorMessage
    showError("Cannot send: message too large for recipient")
}
// For group chats: skip this check, send to all recipients
```

**How it works:**
- Uses SMTP SIZE extension (RFC 1870) to reject oversized messages before data transfer
- Recipient server checks message size in `MAIL FROM` command
- Returns `552` error if message exceeds configured limit
- Saves bandwidth by rejecting before actual message data is transmitted

**Implementation:**
- Storage: `config` table key-value pair (`max_message_size_bytes`)
- Enforcement: `session_remote.go` checks size limit in `Mail()` method via SIZE extension
- Pre-check: `mobile/yggmail.go:CheckRecipientMessageSizeLimit()` verifies recipient capacity before queuing

## Mobile Library Changes from Original

1. **Added `mobile/yggmail.go`**: Complete gomobile bindings with callback system for logs, mail events, and connection status
2. **Fixed IMAP shutdown**: Added proper `Close()` method in `internal/imapserver/imap.go` to prevent connection leaks on mobile platforms
3. **Enhanced connection stability for mobile networks**:
   - Adaptive QUIC keep-alive: 5s (active) to 30s (background)
   - Exponential backoff retry in transport and SMTP sender
   - Enhanced dial timeout (20s) for slower mobile connections
   - Network change handling: `OnNetworkChange()` method for WiFi ↔ Mobile transitions
   - Live peer updates: `UpdatePeers()` method uses Yggdrasil Core's AddPeer/RemovePeer
   - Connection monitoring: `GetPeerConnections()` returns peer info from Yggdrasil core
4. **Battery optimization features**:
   - Adaptive heartbeat intervals based on activity (5s to 29min)
   - Idle timeout checker with configurable timeout
   - Power state awareness: `SetActive()`, `SetCharging()` methods
   - Reduced queue manager wakeups: 60s (active) to 300s (idle)
5. **Peer discovery integration** (uses `yggpeers` library):
   - Asynchronous peer checking: `FindAvailablePeersAsync()`, `CheckCustomPeersAsync()`
   - Default batching optimized for mobile/home connections (10-100 Mbps): batchSize=10, concurrency=10, pauseMs=100
   - Configurable via `SetPeerBatchingParams()` for different network conditions (fast WiFi, slow mobile, etc.)
   - 24-hour cache TTL, 5-second check timeout
   - Supports filtering by protocol (tcp, tls, quic, ws, wss, unix, socks, sockstls) and region

## Testing

### Manual Testing
This is a standalone mail system - manual testing typically involves:
1. Running two instances with multicast or connected to same Yggdrasil peer
2. Connecting mail client (Thunderbird, K-9 Mail, etc.) to each instance
3. Sending mail between the two addresses

### Automated Tests
```bash
# Run all tests
go test ./...

# Run specific package tests
go test ./internal/imapserver/...
go test ./internal/storage/sqlite3/...

# Run E2E tests (large file handling, resilience, benchmarks)
go test ./internal/e2e/...

# Run specific test
go test ./internal/e2e -run TestLargeFileTransfer

# Run with verbose output
go test -v ./...

# Run benchmarks
go test -bench=. ./internal/e2e/...
```

**E2E Test Suite** (`internal/e2e/`):
- `largefile_e2e_test.go`: Tests large file transfers (>1MB) between nodes
- `resilience_test.go`: Tests network disruption recovery and retry behavior
- `benchmark_test.go`: Performance benchmarks for send/receive operations
- Uses `TestNode` struct for complete node lifecycle management

## Important Constraints

- Mail size limit: 500 MB maximum (SMTP servers configured with MaxMessageBytes = 500 MB)
- Only Yggmail-to-Yggmail delivery (no Internet email)
- No SSL/TLS on IMAP/SMTP listeners (plaintext auth over localhost)
- Service must be running to receive mail (no store-and-forward between offline nodes)
- `From` address must exactly match node's Yggmail address (enforced cryptographically)

## Domain Support

Yggmail supports two domain formats for email addresses:
- **`@yggmail`** (primary): Used for all outgoing mail and network communication
- **`@yggmail.local`** (alias): Accepted for compatibility with email clients that have strict domain validation

**Key behaviors:**
- Both domains are accepted for IMAP/SMTP authentication and mail delivery
- All generated addresses use `@yggmail` to ensure network compatibility
- Domain matching is case-insensitive
- Inter-node communication always uses `@yggmail` regardless of client configuration

**Use case:** Some email clients (e.g., Mailspring) reject domains not in their whitelist. Users can configure these clients with `username@yggmail.local` while the system internally normalizes to `@yggmail` for network operations.
