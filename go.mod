module github.com/JB-SelfCompany/yggmail

go 1.25.5

require (
	github.com/JB-SelfCompany/yggpeers v0.0.0-20251216174745-cdf3f5f8f68d
	github.com/emersion/go-imap v1.2.1
	github.com/emersion/go-imap-idle v0.0.0-20210907174914-db2568431445
	github.com/emersion/go-imap-move v0.0.0-20210907172020-fe4558f9c872
	github.com/emersion/go-message v0.17.0
	github.com/emersion/go-sasl v0.0.0-20220912192320-0145f2c60ead
	github.com/emersion/go-smtp v0.15.0
	github.com/fatih/color v1.18.0
	github.com/gologme/log v1.3.0
	github.com/mattn/go-sqlite3 v1.14.32
	github.com/quic-go/quic-go v0.59.0
	github.com/yggdrasil-network/yggdrasil-go v0.5.13
	github.com/yggdrasil-network/yggquic v0.0.0-20260224233053-fa99f958d248
	go.uber.org/atomic v1.11.0
	golang.org/x/crypto v0.49.0
	golang.org/x/term v0.41.0
)

require (
	github.com/Arceliar/ironwood v0.0.0-20260117132459-7017dbc41d8e // indirect
	github.com/Arceliar/phony v0.0.0-20220903101357-530938a4b13d // indirect
	github.com/bits-and-blooms/bitset v1.24.4 // indirect
	github.com/bits-and-blooms/bloom/v3 v3.7.1 // indirect
	github.com/coder/websocket v1.8.14 // indirect
	github.com/emersion/go-textwrapper v0.0.0-20200911093747-65d896831594 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/hjson/hjson-go/v4 v4.6.0 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/neilalexander/generique v0.0.0-20251127000013-def6a5bd842a // indirect
	golang.org/x/mobile v0.0.0-20260312152759-81488f6aeb60 // indirect
	golang.org/x/mod v0.34.0 // indirect
	golang.org/x/net v0.52.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
	golang.org/x/text v0.35.0 // indirect
	golang.org/x/tools v0.43.0 // indirect
)

tool golang.org/x/mobile/cmd/gomobile

replace github.com/yggdrasil-network/yggquic => ../yggquic
