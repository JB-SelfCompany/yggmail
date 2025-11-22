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
	lastMulticast     bool
	lastMulticastRegex string
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
		databasePath: databasePath,
		smtpAddr:     smtpAddr,
		imapAddr:     imapAddr,
		stopChan:     make(chan struct{}),
		smtpDone:     make(chan struct{}),
		overlayDone:  make(chan struct{}),
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
// enableMulticast: enable LAN peer discovery
// multicastRegex: regex for multicast interface filtering (default ".*")
func (s *YggmailService) Start(peers string, enableMulticast bool, multicastRegex string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return fmt.Errorf("service already running")
	}

	if s.storage == nil {
		return fmt.Errorf("service not initialized, call Initialize() first")
	}

	if multicastRegex == "" {
		multicastRegex = ".*"
	}

	// Parse peers
	var peerList []string
	if peers != "" {
		peerList = strings.Split(peers, ",")
		for i, p := range peerList {
			peerList[i] = strings.TrimSpace(p)
		}
	}

	if !enableMulticast && len(peerList) == 0 {
		return fmt.Errorf("must specify either static peers or enable multicast")
	}

	// Initialize Yggdrasil transport
	rawLogger := log.New(s.logger.Writer(), "", 0)
	transport, err := transport.NewYggdrasilTransport(
		rawLogger,
		s.config.PrivateKey,
		s.config.PublicKey,
		peerList,
		enableMulticast,
		multicastRegex,
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

	// Store connection parameters for potential reconnection
	s.lastPeers = peers
	s.lastMulticast = enableMulticast
	s.lastMulticastRegex = multicastRegex

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

// startOverlaySMTP starts the overlay SMTP server for Yggdrasil network
func (s *YggmailService) startOverlaySMTP() {
	defer close(s.overlayDone)

	overlayBackend := &smtpserver.Backend{
		Log:     s.logger,
		Mode:    smtpserver.BackendModeExternal,
		Config:  s.config,
		Storage: s.storage,
		Queues:  s.queues,
		Notify:  s.imapNotify,
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

	if err := storage.ConfigSetPassword(strings.TrimSpace(password)); err != nil {
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
	multicast := s.lastMulticast
	multicastRegex := s.lastMulticastRegex
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
		multicast,
		multicastRegex,
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

	stats := fmt.Sprintf("Running: %v, Peers: %s, Multicast: %v",
		s.running, s.lastPeers, s.lastMulticast)
	return stats
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
