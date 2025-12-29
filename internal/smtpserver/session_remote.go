/*
 *  Copyright (c) 2021 Neil Alexander
 *
 *  This Source Code Form is subject to the terms of the Mozilla Public
 *  License, v. 2.0. If a copy of the MPL was not distributed with this
 *  file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package smtpserver

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"io"
	"time"

	"github.com/emersion/go-message"
	"github.com/emersion/go-smtp"
	"github.com/JB-SelfCompany/yggmail/internal/storage/types"
	"github.com/JB-SelfCompany/yggmail/internal/utils"
)

type SessionRemote struct {
	backend *Backend
	state   *smtp.ConnectionState
	public  ed25519.PublicKey
	from    string
}

func (s *SessionRemote) Mail(from string, opts smtp.MailOptions) error {
	pk, err := utils.ParseAddress(from)
	if err != nil {
		return fmt.Errorf("mail.ParseAddress: %w", err)
	}

	if s.state == nil || s.state.RemoteAddr == nil {
		return fmt.Errorf("invalid connection state")
	}
	if remote := s.state.RemoteAddr.String(); hex.EncodeToString(pk) != remote {
		return fmt.Errorf("not allowed to send incoming mail as %s", from)
	}

	// RFC 1870 SIZE extension: Check message size limit BEFORE accepting data transfer
	// This prevents wasting network bandwidth when message is too large
	s.backend.Log.Printf("MAIL FROM: from=%s, opts.Size=%d, opts=%+v", from, opts.Size, opts)
	if opts.Size > 0 {
		incomingSize := int64(opts.Size)
		s.backend.Log.Printf("MAIL FROM SIZE extension: incoming message size=%d bytes (%.2f MB)",
			incomingSize, float64(incomingSize)/(1024*1024))

		maxSize, err := s.backend.Storage.ConfigGetMaxMessageSize()
		if err != nil {
			s.backend.Log.Printf("Warning: failed to get message size limit in MAIL FROM: %v", err)
		} else {
			// Check if message size exceeds the limit
			if incomingSize > maxSize {
				s.backend.Log.Printf("REJECTED (MAIL FROM): Message size %d bytes exceeds limit of %d bytes - %.2f MB / %.2f MB",
					incomingSize, maxSize,
					float64(incomingSize)/(1024*1024),
					float64(maxSize)/(1024*1024))
				return fmt.Errorf("552 message size limit exceeded: %.2f MB exceeds limit of %.2f MB",
					float64(incomingSize)/(1024*1024),
					float64(maxSize)/(1024*1024))
			}
			s.backend.Log.Printf("MAIL FROM size check passed: %d <= %d bytes",
				incomingSize, maxSize)
		}
	}

	s.from = from
	return nil
}

func (s *SessionRemote) Rcpt(to string) error {
	pk, err := utils.ParseAddress(to)
	if err != nil {
		return fmt.Errorf("mail.ParseAddress: %w", err)
	}

	if !pk.Equal(s.backend.Config.PublicKey) {
		return fmt.Errorf("unexpected recipient for wrong domain")
	}

	return nil
}

func (s *SessionRemote) Data(r io.Reader) error {
	// Peek first chunk to determine message size and parse headers
	// We need to read enough to determine if this is a large message
	peekBuf := new(bytes.Buffer)
	peekBuf.Grow(int(types.SmallMessageThreshold) + 1)

	// Use TeeReader to copy data to peekBuf while reading
	teeReader := io.TeeReader(r, peekBuf)
	limitedReader := io.LimitReader(teeReader, int64(types.SmallMessageThreshold)+1)

	// Read up to threshold + 1 byte
	peekedData := make([]byte, types.SmallMessageThreshold+1)
	n, err := io.ReadFull(limitedReader, peekedData)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return fmt.Errorf("failed to peek message data: %w", err)
	}
	peekedData = peekedData[:n]

	// Determine if this is a large message
	isLarge := n > int(types.SmallMessageThreshold)
	estimatedSize := int64(n)

	// Fallback size check for clients that don't support SIZE extension (RFC 1870)
	// Modern clients should be rejected earlier in Mail() method based on SIZE parameter
	// This is an approximate check based on peek buffer size.
	maxSize, err := s.backend.Storage.ConfigGetMaxMessageSize()
	if err != nil {
		s.backend.Log.Printf("Warning: failed to get message size limit: %v", err)
	} else {
		// Check if message size exceeds the limit
		if estimatedSize > maxSize {
			s.backend.Log.Printf("REJECTED (DATA fallback): Message size %d bytes exceeds limit of %d bytes (%.2f MB / %.2f MB)",
				estimatedSize, maxSize,
				float64(estimatedSize)/(1024*1024),
				float64(maxSize)/(1024*1024))
			return fmt.Errorf("552 message size limit exceeded: %.2f MB exceeds limit of %.2f MB",
				float64(estimatedSize)/(1024*1024),
				float64(maxSize)/(1024*1024))
		}
	}

	// Parse headers from peeked data
	m, err := message.Read(bytes.NewReader(peekedData))
	if err != nil {
		return fmt.Errorf("message.Read: %w", err)
	}

	// Add Yggmail-specific headers
	m.Header.Add(
		"Received", fmt.Sprintf("from Yggmail %s; %s",
			hex.EncodeToString(s.public),
			time.Now().String(),
		),
	)
	m.Header.Add(
		"Delivery-Date", time.Now().UTC().Format(time.RFC822),
	)

	// Start large mail logging if needed
	var opID string
	if isLarge && s.backend.LargeMailLogger != nil {
		opID = fmt.Sprintf("RCV-%s-%d", hex.EncodeToString(s.public)[:8], time.Now().Unix())
		s.backend.LargeMailLogger.StartOperation(opID, 0, estimatedSize, "RECEIVE")
	}

	// Create a reader that combines modified headers with remaining data
	var headerBuf bytes.Buffer
	fields := m.Header.Fields()
	for fields.Next() {
		headerBuf.WriteString(fields.Key())
		headerBuf.WriteString(": ")
		headerBuf.WriteString(fields.Value())
		headerBuf.WriteString("\r\n")
	}
	headerBuf.WriteString("\r\n")

	// Skip the original headers in peeked data by reading body from message
	bodyReader := m.Body

	// Combine: modified headers + body from peeked data + remaining data from r
	fullReader := io.MultiReader(
		&headerBuf,
		bodyReader,
		r, // remaining data not yet read
	)

	// Store the message
	var id int
	if isLarge && s.backend.FileStore != nil && s.backend.LargeMailLogger != nil {
		// Large message - use streaming storage
		s.backend.LargeMailLogger.LogMilestone(opID, "storage_start", estimatedSize, "Starting file storage")
		id, err = s.backend.Storage.MailCreateFromStream("INBOX", fullReader, s.backend.FileStore)
		if err != nil {
			s.backend.LargeMailLogger.EndOperation(opID, false, fmt.Sprintf("storage failed: %v", err))
			return fmt.Errorf("s.backend.Storage.MailCreateFromStream: %w", err)
		}

		// Post-storage size check for large messages (accurate size after storage)
		_, storedMail, err := s.backend.Storage.MailSelect("INBOX", id)
		if err != nil {
			s.backend.LargeMailLogger.EndOperation(opID, false, fmt.Sprintf("failed to get stored mail: %v", err))
			return fmt.Errorf("failed to verify stored message: %w", err)
		}

		actualSize := storedMail.Size
		maxSize, maxSizeErr := s.backend.Storage.ConfigGetMaxMessageSize()
		if maxSizeErr == nil && actualSize > maxSize {
			// Size limit exceeded - delete the just-stored message
			s.backend.Storage.MailDelete("INBOX", id)
			s.backend.Storage.MailExpungeWithFileStore("INBOX", s.backend.FileStore)
			s.backend.LargeMailLogger.EndOperation(opID, false, "size limit exceeded after storage")
			s.backend.Log.Printf("REJECTED (post-storage): Message from %s exceeds size limit (%d bytes > %d bytes) - %.2f MB / %.2f MB",
				s.from, actualSize, maxSize,
				float64(actualSize)/(1024*1024), float64(maxSize)/(1024*1024))
			return fmt.Errorf("552 message size limit exceeded: %.2f MB exceeds limit of %.2f MB",
				float64(actualSize)/(1024*1024),
				float64(maxSize)/(1024*1024))
		}

		s.backend.LargeMailLogger.EndOperation(opID, true, "")
		s.backend.Log.Printf("Stored large mail from %s (MailID=%d, Size=%.2f MB)", s.from, id, float64(actualSize)/(1024*1024))
	} else {
		// Small message - read all into memory and use traditional storage
		var b bytes.Buffer
		copied, err := io.Copy(&b, fullReader)
		if err != nil {
			return fmt.Errorf("failed to read message data: %w", err)
		}
		id, err = s.backend.Storage.MailCreate("INBOX", b.Bytes())
		if err != nil {
			return fmt.Errorf("s.backend.Storage.MailCreate: %w", err)
		}

		// Post-storage size check (in case message was larger than peek buffer)
		actualSize := int64(len(b.Bytes()))
		maxSize, maxSizeErr := s.backend.Storage.ConfigGetMaxMessageSize()
		if maxSizeErr == nil && actualSize > maxSize {
			// Size limit exceeded - delete the just-stored message
			s.backend.Storage.MailDelete("INBOX", id)
			s.backend.Storage.MailExpunge("INBOX")
			s.backend.Log.Printf("REJECTED (post-storage): Message from %s exceeds size limit (%d bytes > %d bytes) - %.2f MB / %.2f MB",
				s.from, actualSize, maxSize,
				float64(actualSize)/(1024*1024), float64(maxSize)/(1024*1024))
			return fmt.Errorf("552 message size limit exceeded: %.2f MB exceeds limit of %.2f MB",
				float64(actualSize)/(1024*1024),
				float64(maxSize)/(1024*1024))
		}

		s.backend.Log.Printf("Stored mail from %s (MailID=%d, Size=%.2f MB)", s.from, id, float64(copied)/(1024*1024))
	}

	// Notify IMAP clients
	if count, err := s.backend.Storage.MailCount("INBOX"); err == nil {
		if err := s.backend.Notify.NotifyNew(id, count); err != nil {
			s.backend.Log.Println("Failed to notify:", s.from)
		}
	}

	// Trigger mail callback to notify mobile app
	if s.backend.MailCallback != nil {
		s.backend.MailCallback.OnNewMail(s.from, id)
	}

	return nil
}

func (s *SessionRemote) Reset() {}

func (s *SessionRemote) Logout() error {
	return nil
}
