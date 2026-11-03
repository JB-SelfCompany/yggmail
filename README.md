> **Moved / Переехал:** development continues at https://git.shd.company/bubblegum/yggmail-go. This GitHub copy is archived.

<div align="center">

# 📧 Yggmail

End-to-end encrypted email over Yggdrasil Network with Android support

[![License](https://img.shields.io/github/license/JB-SelfCompany/yggmail)](LICENSE)
![Go](https://img.shields.io/badge/go-1.25+-00ADD8.svg)
[![Visitors](https://visitor-badge.laobi.icu/badge?page_id=JB-SelfCompany.yggmail)](https://github.com/JB-SelfCompany/yggmail)

**[English](#) | [Русский](README.ru.md)**

</div>

---

> **Note**: This is a fork of the [original Yggmail project](https://github.com/neilalexander/yggmail) with added support for Android library compilation via gomobile.

## ✨ Features

- 📬 Your inbox stored on your own machine
- 🔐 All mail traffic end-to-end encrypted via Yggdrasil
- 📱 IMAP/SMTP protocols for standard email clients
- 🌐 Automatic peer discovery via multicast
- 📲 Android library support via gomobile

---

## 📦 Installation

### Prerequisites

- Go 1.25.5 or later
- CGO enabled (required for SQLite)
- C compiler (gcc on Linux/macOS, MinGW on Windows)

### Install

```bash
go install github.com/JB-SelfCompany/yggmail/cmd/yggmail@latest
```

### Build from source

```bash
git clone https://github.com/JB-SelfCompany/yggmail.git
cd yggmail
go build -o yggmail ./cmd/yggmail
```

### Docker

```bash
docker build -t yggmail .
docker run -p 1025:1025 -p 1143:1143 -v /path/to/data:/etc/yggmail yggmail -multicast
```

---

## 🚀 Quick Start

```bash
# Set password (creates database)
yggmail -password

# Start with multicast discovery
yggmail -multicast

# Or with static peer
yggmail -peer=tls://[peer-address]:port
```

Connect your email client:
- **SMTP**: localhost:1025 (no SSL)
- **IMAP**: localhost:1143 (no SSL)

---

## ⚙️ Parameters

| Flag | Description |
|------|-------------|
| `-peer=tls://...` | Connect to Yggdrasil peer |
| `-multicast` | Enable LAN peer discovery |
| `-database=/path/to/yggmail.db` | Database file path |
| `-smtp=addr:port` | SMTP listen address |
| `-imap=addr:port` | IMAP listen address |
| `-password` | Set IMAP/SMTP password |

---

## 📱 Android Library

### Building AAR

```bash
# Install gomobile
go install golang.org/x/mobile/cmd/gomobile@latest
gomobile init

# Build (with workaround for Go 1.24+)
cd mobile
gomobile bind -target=android -androidapi 23 -ldflags="-checklinkname=0" -o yggmail.aar github.com/JB-SelfCompany/yggmail/mobile
```

### Usage in Android

```kotlin
import mobile.Mobile
import mobile.YggmailService

val service = Mobile.newYggmailService(dbPath, "localhost:1025", "localhost:1143")
service.initialize()
service.start("tls://peer:port", true, ".*")

val address = service.mailAddress
```

---

## 🔧 Fork Additions

- **Mobile bindings** (`mobile/yggmail.go`): Complete API for Android/iOS
- **Large file support**: Messages >1MB stored on filesystem (up to 500MB)
- **Message size limits**: Configurable max message size
- **Battery optimization**: Adaptive timers for mobile
- **Network transitions**: WiFi ↔ Mobile handling

---

## 📝 Notes

- Yggmail must be running to receive emails
- `From` address must match your Yggmail address
- Only Yggmail-to-Yggmail delivery (no Internet email)
- Both `@yggmail` and `@yggmail.local` domains supported

---

## 📄 License

GNU General Public License v3.0 - see [LICENSE](LICENSE)

---

<div align="center">

Made with ❤️ by <a href="https://github.com/JB-SelfCompany">JB-SelfCompany</a>

</div>
