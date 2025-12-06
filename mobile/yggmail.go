/*
 *  Copyright (c) 2021 Neil Alexander
 *
 *  This Source Code Form is subject to the terms of the Mozilla Public
 *  License, v. 2.0. If a copy of the MPL was not distributed with this
 *  file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

// Package mobile provides Android/iOS bindings for Yggmail
package mobile

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/mail"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	"github.com/neilalexander/yggmail/internal/config"
	"github.com/neilalexander/yggmail/internal/imapserver"
	"github.com/neilalexander/yggmail/internal/smtpsender"
	"github.com/neilalexander/yggmail/internal/smtpserver"
	"github.com/neilalexander/yggmail/internal/storage/sqlite3"
	"github.com/neilalexander/yggmail/internal/transport"
	"github.com/neilalexander/yggmail/internal/utils"
	"golang.org/x/crypto/bcrypt"
)

// LogCallback interface for Android logging
type LogCallback interface {
	OnLog(level, tag, message string)
}

// MailCallback interface for receiving mail notifications
type MailCallback interface {
	OnNewMail(mailbox, from, subject string, mailID int)
	OnMailSent(to, subject string)
	OnMailError(to, subject, errorMsg string)
}

// ConnectionCallback interface for network status
type ConnectionCallback interface {
	OnConnected(peer string)
	OnDisconnected(peer string)
	OnConnectionError(peer, errorMsg string)
}


// YggmailService is the main service class for Android/iOS
type YggmailService struct {
	config            *config.Config
	storage           *sqlite3.SQLite3Storage
	transport         *transport.YggdrasilTransport
	queues            *smtpsender.Queues
	imapBackend       *imapserver.Backend
	imapServer        *imapserver.IMAPServer
	imapNotify        *imapserver.IMAPNotify
	localSMTP         *smtp.Server
	overlaySMTP       *smtp.Server
	logger            *log.Logger
	logCallback       LogCallback
	mailCallback      MailCallback
	connCallback      ConnectionCallback
	running           bool
	stopChan          chan struct{}
	smtpDone          chan struct{}
	overlayDone       chan struct{}
	mu                sync.RWMutex
	databasePath      string
	smtpAddr          string
	imapAddr          string
	lastPeers         string
	// Idle timeout for battery optimization
	lastActivity      time.Time
	idleTimeout       time.Duration
	serversPaused     bool
	idleCheckTicker   *time.Ticker
	idleCheckDone     chan struct{}
	// Heartbeat mechanism for keeping IMAP IDLE connections active
	heartbeatTicker   *time.Ticker
	heartbeatDone     chan struct{}
	heartbeatInterval time.Duration
	isActive          bool // Track if user is actively using the app
	lastMailActivity  time.Time
}

// NewYggmailService creates a new instance of Yggmail service
// databasePath: absolute path to SQLite database file
// smtpAddr: SMTP server listen address (e.g., "localhost:1025")
// imapAddr: IMAP server listen address (e.g., "localhost:1143")
func NewYggmailService(databasePath, smtpAddr, imapAddr string) (*YggmailService, error) {
	if databasePath == "" {
		return nil, fmt.Errorf("database path cannot be empty")
	}
	if smtpAddr == "" {
		smtpAddr = "localhost:1025"
	}
	if imapAddr == "" {
		imapAddr = "localhost:1143"
	}

	service := &YggmailService{
		databasePath:      databasePath,
		smtpAddr:          smtpAddr,
		imapAddr:          imapAddr,
		stopChan:          make(chan struct{}),
		smtpDone:          make(chan struct{}),
		overlayDone:       make(chan struct{}),
		idleCheckDone:     make(chan struct{}),
		heartbeatDone:     make(chan struct{}),
		idleTimeout:       10 * time.Minute, // 10 minutes idle timeout for battery optimization
		lastActivity:      time.Now(),
		lastMailActivity:  time.Now(),
		serversPaused:     false,
		heartbeatInterval: 30 * time.Second, // Start with conservative 30 seconds
		isActive:          true,
	}

	// Initialize custom logger
	service.logger = log.New(&logWriter{service: service}, "[Yggmail] ", log.LstdFlags|log.Lmsgprefix)

	return service, nil
}

// SetLogCallback sets the callback for log messages
func (s *YggmailService) SetLogCallback(callback LogCallback) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.logCallback = callback
}

// SetMailCallback sets the callback for mail events
func (s *YggmailService) SetMailCallback(callback MailCallback) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mailCallback = callback
}

// SetConnectionCallback sets the callback for connection events
func (s *YggmailService) SetConnectionCallback(callback ConnectionCallback) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.connCallback = callback
}

// Initialize initializes the service and creates/loads keys
// Must be called before Start()
func (s *YggmailService) Initialize() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.storage != nil {
		return fmt.Errorf("service already initialized")
	}

	// Open database
	storage, err := sqlite3.NewSQLite3StorageStorage(s.databasePath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	s.storage = storage
	s.logger.Printf("Using database file %q\n", s.databasePath)

	// Load or generate keys
	skStr, err := s.storage.ConfigGet("private_key")
	if err != nil {
		return fmt.Errorf("failed to get private key: %w", err)
	}

	sk := make(ed25519.PrivateKey, ed25519.PrivateKeySize)
	if skStr == "" {
		if _, sk, err = ed25519.GenerateKey(nil); err != nil {
			return fmt.Errorf("failed to generate key: %w", err)
		}
		if err := s.storage.ConfigSet("private_key", hex.EncodeToString(sk)); err != nil {
			return fmt.Errorf("failed to save private key: %w", err)
		}
		s.logger.Printf("Generated new server identity")
	} else {
		skBytes, err := hex.DecodeString(skStr)
		if err != nil {
			return fmt.Errorf("failed to decode private key: %w", err)
		}
		copy(sk, skBytes)
	}

	pk := sk.Public().(ed25519.PublicKey)
	s.config = &config.Config{
		PublicKey:  pk,
		PrivateKey: sk,
	}
	s.logger.Printf("Mail address: %s@%s\n", hex.EncodeToString(pk), utils.Domain)

	// Create default mailboxes
	for _, name := range []string{"INBOX", "Outbox"} {
		if err := s.storage.MailboxCreate(name); err != nil {
			return fmt.Errorf("failed to create mailbox %s: %w", name, err)
		}
	}

	return nil
}

// Start starts the Yggmail service with Yggdrasil network connectivity
// peers: comma-separated list of static peers (e.g., "tls://1.2.3.4:12345,tls://5.6.7.8:12345")
func (s *YggmailService) Start(peers string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return fmt.Errorf("service already running")
	}

	if s.storage == nil {
		return fmt.Errorf("service not initialized, call Initialize() first")
	}

	// Parse peers
	var peerList []string
	if peers != "" {
		peerList = strings.Split(peers, ",")
		for i, p := range peerList {
			peerList[i] = strings.TrimSpace(p)
		}
	}

	if len(peerList) == 0 {
		return fmt.Errorf("must specify at least one static peer")
	}

	// Initialize Yggdrasil transport
	rawLogger := log.New(s.logger.Writer(), "", 0)
	transport, err := transport.NewYggdrasilTransport(
		rawLogger,
		s.config.PrivateKey,
		s.config.PublicKey,
		peerList,
	)
	if err != nil {
		return fmt.Errorf("failed to create transport: %w", err)
	}
	s.transport = transport

	// Initialize SMTP queues
	s.queues = smtpsender.NewQueues(s.config, s.logger, s.transport, s.storage)

	// Initialize IMAP server
	s.imapBackend = &imapserver.Backend{
		Log:     s.logger,
		Config:  s.config,
		Storage: s.storage,
	}

	imapServer, notify, err := imapserver.NewIMAPServer(s.imapBackend, s.imapAddr, true)
	if err != nil {
		return fmt.Errorf("failed to start IMAP server: %w", err)
	}
	s.imapServer = imapServer
	s.imapNotify = notify
	s.logger.Println("Listening for IMAP on:", s.imapAddr)

	// Reinitialize channels for restart capability
	s.stopChan = make(chan struct{})
	s.smtpDone = make(chan struct{})
	s.overlayDone = make(chan struct{})

	// Start local SMTP server (for mail clients)
	go s.startLocalSMTP()

	// Start overlay SMTP server (for Yggdrasil network)
	go s.startOverlaySMTP()

	s.logger.Println("Mail notification callbacks configured")

	// Store connection parameters for potential reconnection
	s.lastPeers = peers

	// Start idle timeout checker for battery optimization
	s.lastActivity = time.Now()
	s.serversPaused = false
	s.idleCheckDone = make(chan struct{})
	go s.idleTimeoutChecker()

	// Start heartbeat to keep IMAP IDLE connections alive
	s.heartbeatDone = make(chan struct{})
	go s.heartbeatSender()

	s.running = true
	s.logger.Println("Yggmail service started successfully")

	return nil
}

// startLocalSMTP starts the local SMTP server for mail clients
func (s *YggmailService) startLocalSMTP() {
	defer close(s.smtpDone)

	localBackend := &smtpserver.Backend{
		Log:     s.logger,
		Mode:    smtpserver.BackendModeInternal,
		Config:  s.config,
		Storage: s.storage,
		Queues:  s.queues,
		Notify:  s.imapNotify,
	}

	s.localSMTP = smtp.NewServer(localBackend)
	s.localSMTP.Addr = s.smtpAddr
	s.localSMTP.Domain = hex.EncodeToString(s.config.PublicKey)
	s.localSMTP.MaxMessageBytes = 1024 * 1024 * 32
	s.localSMTP.MaxRecipients = 50
	s.localSMTP.AllowInsecureAuth = true
	s.localSMTP.EnableAuth(sasl.Login, func(conn *smtp.Conn) sasl.Server {
		return sasl.NewLoginServer(func(username, password string) error {
			_, err := localBackend.Login(nil, username, password)
			return err
		})
	})

	s.logger.Println("Listening for SMTP on:", s.localSMTP.Addr)
	if err := s.localSMTP.ListenAndServe(); err != nil {
		s.logger.Printf("Local SMTP server stopped: %v\n", err)
	}
	s.logger.Println("Local SMTP server stopped")
}

// mailCallbackAdapter adapts the mobile MailCallback to the internal callback interface
type mailCallbackAdapter struct {
	service *YggmailService
}

func (a *mailCallbackAdapter) OnNewMail(from string, mailID int) {
	// Record mail activity for aggressive heartbeat mode
	a.service.RecordMailActivity()

	if a.service.mailCallback != nil {
		// Extract mailbox name and get mail details
		a.service.mailCallback.OnNewMail("INBOX", from, "", int(mailID))
	}
}

// startOverlaySMTP starts the overlay SMTP server for Yggdrasil network
func (s *YggmailService) startOverlaySMTP() {
	defer close(s.overlayDone)

	overlayBackend := &smtpserver.Backend{
		Log:          s.logger,
		Mode:         smtpserver.BackendModeExternal,
		Config:       s.config,
		Storage:      s.storage,
		Queues:       s.queues,
		Notify:       s.imapNotify,
		MailCallback: &mailCallbackAdapter{service: s},
	}

	s.overlaySMTP = smtp.NewServer(overlayBackend)
	s.overlaySMTP.Domain = hex.EncodeToString(s.config.PublicKey)
	s.overlaySMTP.MaxMessageBytes = 1024 * 1024 * 32
	s.overlaySMTP.MaxRecipients = 50
	s.overlaySMTP.AuthDisabled = true

	if err := s.overlaySMTP.Serve(s.transport.Listener()); err != nil {
		s.logger.Printf("Overlay SMTP server stopped: %v\n", err)
	}
	s.logger.Println("Overlay SMTP server stopped")
}

// Stop stops the Yggmail service
func (s *YggmailService) Stop() error {
	s.mu.Lock()

	if !s.running {
		s.mu.Unlock()
		return fmt.Errorf("service not running")
	}

	s.logger.Println("Stopping Yggmail service...")

	// Mark as not running to prevent new requests
	s.running = false

	// Stop idle timeout checker
	close(s.idleCheckDone)
	if s.idleCheckTicker != nil {
		s.idleCheckTicker.Stop()
	}

	// Stop heartbeat sender
	close(s.heartbeatDone)
	if s.heartbeatTicker != nil {
		s.heartbeatTicker.Stop()
	}

	// Close IMAP server first
	if s.imapServer != nil {
		if err := s.imapServer.Close(); err != nil {
			s.logger.Printf("Error closing IMAP server: %v\n", err)
		}
	}

	// Close local SMTP server
	if s.localSMTP != nil {
		if err := s.localSMTP.Close(); err != nil {
			s.logger.Printf("Error closing local SMTP: %v\n", err)
		}
	}

	// Close overlay SMTP server
	if s.overlaySMTP != nil {
		if err := s.overlaySMTP.Close(); err != nil {
			s.logger.Printf("Error closing overlay SMTP: %v\n", err)
		}
	}

	// Close transport (this will unblock overlay SMTP)
	if s.transport != nil {
		if err := s.transport.Listener().Close(); err != nil {
			s.logger.Printf("Error closing transport: %v\n", err)
		}
	}

	// Signal stop
	close(s.stopChan)

	// Unlock before waiting to allow servers to finish
	s.mu.Unlock()

	// Wait for servers to fully stop with timeout
	timeout := time.NewTimer(5 * time.Second)
	defer timeout.Stop()

	smtpStopped := false
	overlayStopped := false

	for !smtpStopped || !overlayStopped {
		select {
		case _, ok := <-s.smtpDone:
			if ok || !smtpStopped {
				smtpStopped = true
				s.logger.Println("Local SMTP server fully stopped")
			}
		case _, ok := <-s.overlayDone:
			if ok || !overlayStopped {
				overlayStopped = true
				s.logger.Println("Overlay SMTP server fully stopped")
			}
		case <-timeout.C:
			s.logger.Println("Warning: Timeout waiting for servers to stop")
			return nil
		}
	}

	s.logger.Println("Yggmail service stopped successfully")
	return nil
}

// Close closes the service and releases all resources
func (s *YggmailService) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return fmt.Errorf("service still running, call Stop() first")
	}

	if s.storage != nil {
		if err := s.storage.Close(); err != nil {
			return fmt.Errorf("failed to close storage: %w", err)
		}
		s.storage = nil
	}

	return nil
}

// IsRunning returns whether the service is currently running
func (s *YggmailService) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}

// GetMailAddress returns the email address for this node
func (s *YggmailService) GetMailAddress() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.config == nil {
		return ""
	}
	return hex.EncodeToString(s.config.PublicKey) + "@" + utils.Domain
}

// GetPublicKey returns the hex-encoded public key
func (s *YggmailService) GetPublicKey() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.config == nil {
		return ""
	}
	return hex.EncodeToString(s.config.PublicKey)
}

// SetPassword sets a new password for IMAP/SMTP authentication
func (s *YggmailService) SetPassword(password string) error {
	s.mu.RLock()
	storage := s.storage
	s.mu.RUnlock()

	if storage == nil {
		return fmt.Errorf("service not initialized")
	}

	// Hash the password with bcrypt
	trimmedPassword := strings.TrimSpace(password)
	hash, err := bcrypt.GenerateFromPassword([]byte(trimmedPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Store the hashed password
	if err := storage.ConfigSetPassword(string(hash)); err != nil {
		return fmt.Errorf("failed to set password: %w", err)
	}

	s.logger.Println("Password updated successfully")
	return nil
}

// VerifyPassword verifies the provided password
func (s *YggmailService) VerifyPassword(password string) (bool, error) {
	s.mu.RLock()
	storage := s.storage
	s.mu.RUnlock()

	if storage == nil {
		return false, fmt.Errorf("service not initialized")
	}

	return storage.ConfigTryPassword(password)
}

// SendMail sends an email message
// from: sender address (e.g., "pubkey@yggmail")
// to: comma-separated recipient addresses
// subject: email subject
// body: email body (plain text)
func (s *YggmailService) SendMail(from, to, subject, body string) error {
	s.mu.RLock()
	storage := s.storage
	queues := s.queues
	s.mu.RUnlock()

	if storage == nil || queues == nil {
		return fmt.Errorf("service not initialized or not started")
	}

	// Parse recipients
	recipients := strings.Split(to, ",")
	for i, r := range recipients {
		recipients[i] = strings.TrimSpace(r)
	}

	// Build email message
	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf("From: %s\r\n", from))
	buf.WriteString(fmt.Sprintf("To: %s\r\n", to))
	buf.WriteString(fmt.Sprintf("Subject: %s\r\n", subject))
	buf.WriteString(fmt.Sprintf("Date: %s\r\n", time.Now().Format(time.RFC1123Z)))
	buf.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	buf.WriteString("\r\n")
	buf.WriteString(body)

	// Queue for sending
	if err := queues.QueueFor(from, recipients, buf.Bytes()); err != nil {
		if s.mailCallback != nil {
			s.mailCallback.OnMailError(to, subject, err.Error())
		}
		return fmt.Errorf("failed to queue mail: %w", err)
	}

	s.logger.Printf("Mail queued for sending to %s\n", to)

	// Record mail activity for aggressive delivery mode
	s.RecordMailActivity()

	if s.mailCallback != nil {
		s.mailCallback.OnMailSent(to, subject)
	}

	return nil
}

// GetMailboxList returns list of all mailboxes
func (s *YggmailService) GetMailboxList(onlySubscribed bool) ([]string, error) {
	s.mu.RLock()
	storage := s.storage
	s.mu.RUnlock()

	if storage == nil {
		return nil, fmt.Errorf("service not initialized")
	}

	return storage.MailboxList(onlySubscribed)
}

// CreateMailbox creates a new mailbox
func (s *YggmailService) CreateMailbox(name string) error {
	s.mu.RLock()
	storage := s.storage
	s.mu.RUnlock()

	if storage == nil {
		return fmt.Errorf("service not initialized")
	}

	return storage.MailboxCreate(name)
}

// DeleteMailbox deletes a mailbox
func (s *YggmailService) DeleteMailbox(name string) error {
	s.mu.RLock()
	storage := s.storage
	s.mu.RUnlock()

	if storage == nil {
		return fmt.Errorf("service not initialized")
	}

	return storage.MailboxDelete(name)
}

// RenameMailbox renames a mailbox
func (s *YggmailService) RenameMailbox(oldName, newName string) error {
	s.mu.RLock()
	storage := s.storage
	s.mu.RUnlock()

	if storage == nil {
		return fmt.Errorf("service not initialized")
	}

	return storage.MailboxRename(oldName, newName)
}

// GetMailCount returns the number of mails in a mailbox
func (s *YggmailService) GetMailCount(mailbox string) (int, error) {
	s.mu.RLock()
	storage := s.storage
	s.mu.RUnlock()

	if storage == nil {
		return 0, fmt.Errorf("service not initialized")
	}

	return storage.MailCount(mailbox)
}

// GetUnseenCount returns the number of unseen mails in a mailbox
func (s *YggmailService) GetUnseenCount(mailbox string) (int, error) {
	s.mu.RLock()
	storage := s.storage
	s.mu.RUnlock()

	if storage == nil {
		return 0, fmt.Errorf("service not initialized")
	}

	return storage.MailUnseen(mailbox)
}

// MailInfo represents basic mail information
type MailInfo struct {
	ID       int
	From     string
	Subject  string
	Date     string
	Seen     bool
	Flagged  bool
	Answered bool
}

// PeerConnectionInfo represents information about a connected peer
// This is a gomobile-compatible version of core.PeerInfo
type PeerConnectionInfo struct {
	URI           string  // Peer URI (e.g., "tls://example.com:12345")
	Up            bool    // Whether the connection is up
	Inbound       bool    // Whether this is an inbound connection
	LastError     string  // Last error message (empty if no error)
	Key           string  // Peer's public key (hex encoded)
	Uptime        int64   // Connection uptime in seconds
	LatencyMs     int64   // Round-trip latency in milliseconds
	RXBytes       int64   // Total bytes received
	TXBytes       int64   // Total bytes transmitted
	RXRate        int64   // Current receive rate (bytes/sec)
	TXRate        int64   // Current transmit rate (bytes/sec)
}

// GetMailList returns list of mails in a mailbox
func (s *YggmailService) GetMailList(mailbox string) ([]*MailInfo, error) {
	s.mu.RLock()
	storage := s.storage
	s.mu.RUnlock()

	if storage == nil {
		return nil, fmt.Errorf("service not initialized")
	}

	// Get mail IDs
	ids, err := storage.MailSearch(mailbox)
	if err != nil {
		return nil, fmt.Errorf("failed to search mails: %w", err)
	}

	var mails []*MailInfo
	for _, id := range ids {
		_, mailData, err := storage.MailSelect(mailbox, int(id))
		if err != nil {
			s.logger.Printf("Failed to load mail %d: %v\n", id, err)
			continue
		}

		// Parse email headers
		msg, err := mail.ReadMessage(bytes.NewReader(mailData.Mail))
		if err != nil {
			s.logger.Printf("Failed to parse mail %d: %v\n", id, err)
			continue
		}

		info := &MailInfo{
			ID:       mailData.ID,
			From:     msg.Header.Get("From"),
			Subject:  msg.Header.Get("Subject"),
			Date:     msg.Header.Get("Date"),
			Seen:     mailData.Seen,
			Flagged:  mailData.Flagged,
			Answered: mailData.Answered,
		}
		mails = append(mails, info)
	}

	return mails, nil
}

// GetMailContent returns the full content of a mail
func (s *YggmailService) GetMailContent(mailbox string, mailID int) (string, error) {
	s.mu.RLock()
	storage := s.storage
	s.mu.RUnlock()

	if storage == nil {
		return "", fmt.Errorf("service not initialized")
	}

	_, mailData, err := storage.MailSelect(mailbox, mailID)
	if err != nil {
		return "", fmt.Errorf("failed to get mail: %w", err)
	}

	return string(mailData.Mail), nil
}

// GetMailBody returns just the body of a mail (without headers)
func (s *YggmailService) GetMailBody(mailbox string, mailID int) (string, error) {
	s.mu.RLock()
	storage := s.storage
	s.mu.RUnlock()

	if storage == nil {
		return "", fmt.Errorf("service not initialized")
	}

	_, mailData, err := storage.MailSelect(mailbox, mailID)
	if err != nil {
		return "", fmt.Errorf("failed to get mail: %w", err)
	}

	// Parse email to extract body
	msg, err := mail.ReadMessage(bytes.NewReader(mailData.Mail))
	if err != nil {
		return "", fmt.Errorf("failed to parse mail: %w", err)
	}

	body, err := io.ReadAll(msg.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read body: %w", err)
	}

	return string(body), nil
}

// MarkMailSeen marks a mail as seen/unseen
func (s *YggmailService) MarkMailSeen(mailbox string, mailID int, seen bool) error {
	s.mu.RLock()
	storage := s.storage
	s.mu.RUnlock()

	if storage == nil {
		return fmt.Errorf("service not initialized")
	}

	_, mailData, err := storage.MailSelect(mailbox, mailID)
	if err != nil {
		return fmt.Errorf("failed to get mail: %w", err)
	}

	return storage.MailUpdateFlags(mailbox, mailID, seen, mailData.Answered, mailData.Flagged, mailData.Deleted)
}

// MarkMailFlagged marks a mail as flagged/unflagged
func (s *YggmailService) MarkMailFlagged(mailbox string, mailID int, flagged bool) error {
	s.mu.RLock()
	storage := s.storage
	s.mu.RUnlock()

	if storage == nil {
		return fmt.Errorf("service not initialized")
	}

	_, mailData, err := storage.MailSelect(mailbox, mailID)
	if err != nil {
		return fmt.Errorf("failed to get mail: %w", err)
	}

	return storage.MailUpdateFlags(mailbox, mailID, mailData.Seen, mailData.Answered, flagged, mailData.Deleted)
}

// DeleteMail deletes a mail
func (s *YggmailService) DeleteMail(mailbox string, mailID int) error {
	s.mu.RLock()
	storage := s.storage
	s.mu.RUnlock()

	if storage == nil {
		return fmt.Errorf("service not initialized")
	}

	return storage.MailDelete(mailbox, mailID)
}

// ExpungeMailbox permanently removes deleted mails from a mailbox
func (s *YggmailService) ExpungeMailbox(mailbox string) error {
	s.mu.RLock()
	storage := s.storage
	s.mu.RUnlock()

	if storage == nil {
		return fmt.Errorf("service not initialized")
	}

	return storage.MailExpunge(mailbox)
}

// GetSMTPAddress returns the local SMTP server address
func (s *YggmailService) GetSMTPAddress() string {
	return s.smtpAddr
}

// GetIMAPAddress returns the local IMAP server address
func (s *YggmailService) GetIMAPAddress() string {
	return s.imapAddr
}

// OnNetworkChange should be called when network connectivity changes (WiFi <-> Mobile)
// This helps maintain stable connections on mobile devices
func (s *YggmailService) OnNetworkChange() error {
	s.mu.RLock()
	running := s.running
	peers := s.lastPeers
	s.mu.RUnlock()

	if !running {
		s.logger.Println("Network changed but service not running")
		return nil
	}

	s.logger.Println("Network change detected, refreshing connections...")

	// Close existing transport to force reconnection
	if s.transport != nil {
		// Close the listener which will trigger reconnection
		if err := s.transport.Listener().Close(); err != nil {
			s.logger.Printf("Error closing transport on network change: %v\n", err)
		}
	}

	// Restart transport with same parameters
	s.mu.Lock()
	rawLogger := log.New(s.logger.Writer(), "", 0)
	newTransport, err := transport.NewYggdrasilTransport(
		rawLogger,
		s.config.PrivateKey,
		s.config.PublicKey,
		strings.Split(peers, ","),
	)
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("failed to recreate transport: %w", err)
	}
	s.transport = newTransport

	// Update queues with new transport
	if s.queues != nil {
		s.queues.Transport = newTransport
	}
	s.mu.Unlock()

	s.logger.Println("Network connections refreshed successfully")
	if s.connCallback != nil {
		s.connCallback.OnConnected("network_refreshed")
	}

	return nil
}

// GetConnectionStats returns basic connection statistics
func (s *YggmailService) GetConnectionStats() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.running {
		return "Service not running"
	}

	stats := fmt.Sprintf("Running: %v, Peers: %s",
		s.running, s.lastPeers)
	return stats
}

// RecordActivity records user activity to prevent idle timeout
// Call this method when mail is sent/received or user interacts with the app
func (s *YggmailService) RecordActivity() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.lastActivity = time.Now()
	// Note: We don't log here to reduce log spam from periodic polling

	// Resume servers if they were paused
	if s.serversPaused && s.running {
		s.logger.Println("Resuming servers due to activity")
		// Servers will be resumed by the idle checker on next tick
		s.serversPaused = false
	}
}

// RecordMailActivity records mail-related activity (send/receive)
// This triggers more aggressive heartbeat for immediate delivery
func (s *YggmailService) RecordMailActivity() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.lastActivity = time.Now()
	s.lastMailActivity = time.Now()
	s.logger.Println("Mail activity recorded, switching to aggressive mode")
}

// SetActive sets whether the app is in active/foreground mode
// Active mode uses more frequent heartbeats for better responsiveness
func (s *YggmailService) SetActive(active bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.isActive != active {
		s.isActive = active
		if active {
			s.logger.Println("App became active, increasing heartbeat frequency")
		} else {
			s.logger.Println("App became inactive, will reduce heartbeat frequency")
		}
	}
}

// SetIdleTimeout sets the idle timeout duration for battery optimization
// Default is 10 minutes. Set to 0 to disable idle timeout.
func (s *YggmailService) SetIdleTimeout(minutes int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if minutes <= 0 {
		s.idleTimeout = 0
		s.logger.Println("Idle timeout disabled")
	} else {
		s.idleTimeout = time.Duration(minutes) * time.Minute
		s.logger.Printf("Idle timeout set to %d minutes\n", minutes)
	}
}

// idleTimeoutChecker periodically checks for idle state and pauses servers
func (s *YggmailService) idleTimeoutChecker() {
	s.idleCheckTicker = time.NewTicker(1 * time.Minute) // Check every minute
	defer s.idleCheckTicker.Stop()

	s.logger.Println("Idle timeout checker started")

	for {
		select {
		case <-s.idleCheckTicker.C:
			s.checkIdleState()
		case <-s.idleCheckDone:
			s.logger.Println("Idle timeout checker stopped")
			return
		}
	}
}

// checkIdleState checks if service has been idle and pauses/resumes servers accordingly
func (s *YggmailService) checkIdleState() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return
	}

	// Skip if idle timeout is disabled
	if s.idleTimeout == 0 {
		return
	}

	idleTime := time.Since(s.lastActivity)

	// Check if we should pause servers
	if !s.serversPaused && idleTime >= s.idleTimeout {
		s.logger.Printf("Service idle for %v, considering pause (threshold: %v)\n",
			idleTime.Round(time.Second), s.idleTimeout)
		// Note: For mobile P2P email, we can't fully pause servers without losing incoming mail
		// Instead, we log the idle state for monitoring. Full server pause would require
		// store-and-forward infrastructure which yggmail doesn't support.
		// The WakeLock optimization in Android layer is more appropriate for battery saving.
	}

	// In future: could implement graceful degradation like:
	// - Reduce QUIC keepalive frequency
	// - Pause queue manager checks
}

// heartbeatSender periodically sends IMAP IDLE notifications to keep connections alive
// Uses adaptive intervals based on activity level for battery optimization
func (s *YggmailService) heartbeatSender() {
	s.mu.Lock()
	interval := s.heartbeatInterval
	s.mu.Unlock()

	s.heartbeatTicker = time.NewTicker(interval)
	defer s.heartbeatTicker.Stop()

	s.logger.Printf("IMAP heartbeat sender started (adaptive mode, initial: %v)", interval)

	lastCheck := time.Now()

	for {
		select {
		case <-s.heartbeatTicker.C:
			s.sendHeartbeat()

			// Adaptively adjust heartbeat interval based on activity
			// Check every minute if we should adjust
			if time.Since(lastCheck) >= time.Minute {
				lastCheck = time.Now()
				newInterval := s.calculateAdaptiveInterval()

				s.mu.Lock()
				if newInterval != s.heartbeatInterval {
					s.heartbeatInterval = newInterval
					s.heartbeatTicker.Reset(newInterval)
					s.logger.Printf("Heartbeat interval adjusted to %v", newInterval)
				}
				s.mu.Unlock()
			}

		case <-s.heartbeatDone:
			s.logger.Println("IMAP heartbeat sender stopped")
			return
		}
	}
}

// calculateAdaptiveInterval determines optimal heartbeat interval based on activity
func (s *YggmailService) calculateAdaptiveInterval() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()

	timeSinceMailActivity := time.Since(s.lastMailActivity)
	timeSinceActivity := time.Since(s.lastActivity)

	// Aggressive mode: Recent mail activity (< 2 minutes)
	if timeSinceMailActivity < 2*time.Minute {
		return 5 * time.Second
	}

	// Active mode: Recent app activity (< 5 minutes)
	if timeSinceActivity < 5*time.Minute || s.isActive {
		return 15 * time.Second
	}

	// Idle mode: Some activity (< 15 minutes)
	if timeSinceActivity < 15*time.Minute {
		return 30 * time.Second
	}

	// Deep idle mode: No activity for long time
	// Still need heartbeat but can be very infrequent
	return 60 * time.Second
}

// sendHeartbeat sends a lightweight notification to IMAP IDLE clients
func (s *YggmailService) sendHeartbeat() {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.running || s.imapNotify == nil {
		return
	}

	// Get current mail count for INBOX
	count, err := s.storage.MailCount("INBOX")
	if err != nil {
		// Silently ignore errors to avoid log spam
		return
	}

	// Send lightweight status update to IMAP IDLE clients
	// This keeps the connection active and ensures notifications are delivered
	// Note: We use count of -1 as a special "heartbeat" signal to avoid creating
	// false "new mail" notifications in the logs
	_ = s.imapNotify.NotifyNew(-1, count)
}

// GetPeerConnections returns information about all connected peers
// Returns nil if service is not running or transport is not initialized
func (s *YggmailService) GetPeerConnections() []*PeerConnectionInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.running || s.transport == nil {
		return nil
	}

	// Get peer information from yggdrasil core
	corePeers := s.transport.GetPeers()
	if corePeers == nil {
		return nil
	}

	// Convert to gomobile-compatible format
	peers := make([]*PeerConnectionInfo, 0, len(corePeers))
	for _, peer := range corePeers {
		info := &PeerConnectionInfo{
			URI:       peer.URI,
			Up:        peer.Up,
			Inbound:   peer.Inbound,
			Key:       hex.EncodeToString(peer.Key),
			Uptime:    int64(peer.Uptime.Seconds()),
			LatencyMs: int64(peer.Latency.Milliseconds()),
			RXBytes:   int64(peer.RXBytes),
			TXBytes:   int64(peer.TXBytes),
			RXRate:    int64(peer.RXRate),
			TXRate:    int64(peer.TXRate),
		}
		if peer.LastError != nil {
			info.LastError = peer.LastError.Error()
		}
		peers = append(peers, info)
	}

	return peers
}

// GetPeerConnectionsJSON returns peer connection information as JSON string
// Returns empty array if no transport available
// Deprecated: Use GetPeerConnections() instead for better type safety
func (s *YggmailService) GetPeerConnectionsJSON() string {
	peers := s.GetPeerConnections()
	if peers == nil || len(peers) == 0 {
		return "[]"
	}

	// Manually build JSON to avoid external dependencies
	var sb strings.Builder
	sb.WriteString("[")
	for i, peer := range peers {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString("{")
		sb.WriteString(fmt.Sprintf("\"uri\":\"%s\",", peer.URI))
		sb.WriteString(fmt.Sprintf("\"up\":%t,", peer.Up))
		sb.WriteString(fmt.Sprintf("\"inbound\":%t,", peer.Inbound))
		sb.WriteString(fmt.Sprintf("\"lastError\":\"%s\",", peer.LastError))
		sb.WriteString(fmt.Sprintf("\"key\":\"%s\",", peer.Key))
		sb.WriteString(fmt.Sprintf("\"uptime\":%d,", peer.Uptime))
		sb.WriteString(fmt.Sprintf("\"latencyMs\":%d,", peer.LatencyMs))
		sb.WriteString(fmt.Sprintf("\"rxBytes\":%d,", peer.RXBytes))
		sb.WriteString(fmt.Sprintf("\"txBytes\":%d,", peer.TXBytes))
		sb.WriteString(fmt.Sprintf("\"rxRate\":%d,", peer.RXRate))
		sb.WriteString(fmt.Sprintf("\"txRate\":%d", peer.TXRate))
		sb.WriteString("}")
	}
	sb.WriteString("]")
	return sb.String()
}

// UpdatePeers updates peer configuration without restarting the service
// Uses Yggdrasil Core's AddPeer/RemovePeer methods for live updates
func (s *YggmailService) UpdatePeers(peers string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running || s.transport == nil {
		return fmt.Errorf("service not running or transport not initialized")
	}

	s.logger.Println("UpdatePeers called - applying live peer configuration changes...")

	// Parse new peer list
	var newPeerList []string
	if peers != "" {
		for _, p := range strings.Split(peers, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				newPeerList = append(newPeerList, p)
			}
		}
	}

	// Parse old peer list
	var oldPeerList []string
	if s.lastPeers != "" {
		for _, p := range strings.Split(s.lastPeers, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				oldPeerList = append(oldPeerList, p)
			}
		}
	}

	// Get Yggdrasil Core for peer management
	core := s.transport.GetCore()
	if core == nil {
		return fmt.Errorf("failed to get Yggdrasil core")
	}

	// Remove peers that are no longer in the new list
	for _, oldPeer := range oldPeerList {
		found := false
		for _, newPeer := range newPeerList {
			if oldPeer == newPeer {
				found = true
				break
			}
		}
		if !found {
			// Parse URI and remove peer
			u, err := url.Parse(oldPeer)
			if err != nil {
				s.logger.Printf("Warning: failed to parse old peer URI %s: %v\n", oldPeer, err)
				continue
			}
			if err := core.RemovePeer(u, ""); err != nil {
				s.logger.Printf("Warning: failed to remove peer %s: %v\n", oldPeer, err)
			} else {
				s.logger.Printf("Removed peer: %s\n", oldPeer)
			}
		}
	}

	// Add new peers that weren't in the old list
	for _, newPeer := range newPeerList {
		found := false
		for _, oldPeer := range oldPeerList {
			if newPeer == oldPeer {
				found = true
				break
			}
		}
		if !found {
			// Parse URI and add peer
			u, err := url.Parse(newPeer)
			if err != nil {
				s.logger.Printf("Warning: failed to parse new peer URI %s: %v\n", newPeer, err)
				continue
			}
			if err := core.AddPeer(u, ""); err != nil {
				s.logger.Printf("Warning: failed to add peer %s: %v\n", newPeer, err)
			} else {
				s.logger.Printf("Added peer: %s\n", newPeer)
			}
		}
	}

	// Store new configuration
	s.lastPeers = peers

	s.logger.Printf("Peer configuration updated successfully: %d peers configured\n", len(newPeerList))

	return nil
}

// logWriter is a custom writer that forwards logs to the callback
type logWriter struct {
	service *YggmailService
}

func (w *logWriter) Write(p []byte) (n int, err error) {
	if w.service.logCallback != nil {
		msg := string(p)
		msg = strings.TrimSuffix(msg, "\n")
		w.service.logCallback.OnLog("INFO", "Yggmail", msg)
	}
	// Also write to stdout for debugging
	return os.Stdout.Write(p)
}
