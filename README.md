# Yggmail (Fork)

It's email, but not as you know it.

> **Note**: This is a fork of the [original Yggmail project](https://github.com/neilalexander/yggmail) with added support for Android library compilation via gomobile.

## Introduction

Yggmail is a single-binary all-in-one mail transfer agent which sends and receives email natively over the [Yggdrasil Network](https://yggdrasil-network.github.io/).

* Yggmail runs just about anywhere you like — your inbox is stored right on your own machine;
* Implements IMAP and SMTP protocols for sending and receiving mail, so you can use your favourite client (hopefully);
* Mails are exchanged between Yggmail users using built-in Yggdrasil connectivity;
* All mail exchange traffic between any two Yggmail nodes is always end-to-end encrypted without exception;
* Yggdrasil and Yggmail nodes on the same network are discovered automatically using multicast or you can configure a static Yggdrasil peer.

Email addresses are based on your public key, like `89cd1ea25d99b8ccf29e454280313128c234ffb82aa0eb2e3496f6f156d063d0@yggmail`.

## Why?

There are all sorts of messaging services in the world but there is still a lot of value in asynchronous communication. Email is something that a lot of people understand reasonably well and there is still a huge volume of software in the world which supports email. Yggmail is designed to comply with the standards that people know and expect.

Yggdrasil is well-suited for ad-hoc mail delivery and allows Yggmail to work even in closed networks, where Internet or other connectivity is restricted or simply not available. It guarantees end-to-end encryption and handles networks with changing topologies reasonably well.

## Quickstart

Use a recent version of Go to install Yggmail:

```
go install github.com/neilalexander/yggmail/cmd/yggmail@latest
```

It will then be installed into your `GOPATH`, so add that to your environment:

```
export PATH=$PATH:`go env GOPATH`/bin
```

Create a mailbox and set your password. Your Yggmail database will automatically be created in your working directory if it doesn't already exist:

```
yggmail -password
```

Start Yggmail, using the database in your working directory, with either multicast enabled, an [Yggdrasil static peer](https://publicpeers.neilalexander.dev/) specified or both:

```
yggmail -multicast
yggmail -peer=tls://...
yggmail -multicast -peer=tls://...
```

Your mail address will be printed in the log at startup. You will also use this as your username when you log into SMTP/IMAP.

Connect your mail client to Yggmail. In the above example:

* SMTP is listening on `localhost` port 1025, username is your mail address, plain password authentication, no SSL/TLS
* IMAP is listening on `localhost` port 1143, username is your mail address, plain password authentication, no SSL/TLS

Then try sending a mail to another Yggmail user!

## Parameters

The following command line switches are supported by the `yggmail` binary:

* `-peer=tls://...` or `-peer=tcp://...` — connect to a specific Yggdrasil node, like one of the [Public Peers](https://publicpeers.neilalexander.dev/);
* `-multicast` - enable multicast peer discovery for Yggdrasil nodes on your LAN
* `-mcastregexp=".*"` - regexp used in muticast peer discovery for interface name selection.
* `-database=/path/to/yggmail.db` — use a specific database file;
* `-smtp=listenaddr:port` — listen for SMTP on a specific address/port
* `-imap=listenaddr:port` — listen for IMAP on a specific address/port;
* `-password` — set your IMAP/SMTP password (doesn't matter if Yggmail is running or not, just make sure that Yggmail is pointing at the right database file or that you are in the right working directory).
* `-passwordHash` — Like `-password` however this sets what must be directly in the database. This assumes you passed a bcrypt hash

## Notes

There are a few important notes:

* Yggmail needs to be running in order to receive inbound emails — it's therefore important to run Yggmail somewhere that will have good uptime;
* Yggmail tries to guarantee that senders are who they say they are. Your `From` address must be your Yggmail address;
* You can only email other Yggmail users, not regular email addresses on the public Internet;
* You may need to configure your client to allow "insecure" or "plaintext" authentication to IMAP/SMTP — this is because we don't support SSL/TLS on the IMAP/SMTP listeners yet;
* Yggmail won't transport mails larger than 1MB right now.

## Android Library Build

This fork includes the `mobile/` directory with Go bindings for building an Android library using [gomobile](https://pkg.go.dev/golang.org/x/mobile/cmd/gomobile).

### Changes from Original

* **Added `mobile/yggmail.go`**: Go bindings for Android/iOS with complete API for mail operations, callbacks, and service management
* **Fixed IMAP server shutdown**: Added proper `Close()` method in `internal/imapserver/imap.go` to cleanly close IMAP connections, which is essential for library lifecycle management on mobile platforms

### Prerequisites

1. Install Go (1.24.0 or later)
2. Install gomobile:
   ```bash
   go install golang.org/x/mobile/cmd/gomobile@latest
   gomobile init
   ```

3. Set up Android SDK and NDK:
   - Install Android Studio or Android SDK command-line tools
   - Set `ANDROID_HOME` environment variable pointing to your Android SDK
   - Install NDK (recommended version 25.x or later)

### Building the Android Library

#### Windows (Recommended)

1. **First-time setup:**
   ```cmd
   setup-gomobile.bat
   ```
   This will install gomobile and configure Android SDK paths.

2. **Build the library:**
   ```cmd
   REM Full build (all architectures - ~40MB)
   build-android.bat

   REM Or ARM64 only (smaller size - ~15MB)
   build-android-small.bat
   ```

   **Note:** Build scripts automatically include `-ldflags="-checklinkname=0"` to workaround a known issue with `github.com/wlynxg/anet` dependency.

#### Linux/macOS

```bash
# First-time setup
go install golang.org/x/mobile/cmd/gomobile@latest
gomobile init

# Build AAR file for Android (with workaround for wlynxg/anet issue)
gomobile bind -target=android -androidapi 23 -ldflags="-checklinkname=0" -o yggmail.aar github.com/neilalexander/yggmail/mobile
```

This will generate:
- `yggmail.aar` - Android library archive
- `yggmail-sources.jar` - Source code for IDE integration

#### Build Options

You can customize the build with additional flags:

```bash
# Build for specific architectures (reduces size)
gomobile bind -target=android/arm64,android/amd64 -androidapi 23 -ldflags="-checklinkname=0" -o yggmail.aar github.com/neilalexander/yggmail/mobile

# ARM64 only (smallest, for modern devices)
gomobile bind -target=android/arm64 -androidapi 23 -ldflags="-checklinkname=0" -o yggmail.aar github.com/neilalexander/yggmail/mobile

# Different Android API levels
gomobile bind -target=android -androidapi 21 -ldflags="-checklinkname=0" -o yggmail.aar github.com/neilalexander/yggmail/mobile
```

**Important:** Always include `-ldflags="-checklinkname=0"` due to a known compatibility issue with Go 1.24+ and the `wlynxg/anet` dependency.

### Using the Library in Android

1. Copy `yggmail.aar` to your Android project's `app/libs/` directory
2. Add to `app/build.gradle`:
   ```gradle
   dependencies {
       implementation files('libs/yggmail.aar')
   }
   ```

3. Use the library in your code:
   ```java
   import mobile.YggmailService;

   // Initialize service
   YggmailService service = Mobile.newYggmailService(
       "/path/to/database.db",
       "localhost:1025",  // SMTP
       "localhost:1143"   // IMAP
   );

   // Initialize and start
   service.initialize();
   service.start("tls://peer1.example.com:12345", true, ".*");

   // Get email address
   String address = service.getMailAddress();
   ```

For detailed API documentation, see the source code in `mobile/yggmail.go`.

### Mobile Network Stability

This fork includes significant improvements for mobile network stability:
- Extended connection timeouts for slower mobile networks
- Automatic retry with exponential backoff
- Keepalive mechanism (30s intervals)
- Network change handling for WiFi ↔ Mobile transitions

## Bugs

There are probably all sorts of bugs, but the ones that we know of are:

* IMAP behaviour might not be entirely spec-compliant in all cases, so your mileage with mail clients might vary;
* IMAP search isn't implemented yet and will instead return all mails.

The code's also a bit of a mess, so sorry about that.
