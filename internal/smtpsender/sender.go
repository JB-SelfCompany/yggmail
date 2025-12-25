/*
 *  Copyright (c) 2021 Neil Alexander
 *
 *  This Source Code Form is subject to the terms of the Mozilla Public
 *  License, v. 2.0. If a copy of the MPL was not distributed with this
 *  file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package smtpsender

import (
	"bytes"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"math/rand"
	"net/mail"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/JB-SelfCompany/yggmail/internal/config"
	"github.com/JB-SelfCompany/yggmail/internal/logging"
	"github.com/JB-SelfCompany/yggmail/internal/storage"
	"github.com/JB-SelfCompany/yggmail/internal/storage/filestore"
	"github.com/JB-SelfCompany/yggmail/internal/storage/types"
	"github.com/JB-SelfCompany/yggmail/internal/transport"
	"github.com/JB-SelfCompany/yggmail/internal/utils"
	"go.uber.org/atomic"
)

const (
	// Battery-optimized retry strategy with long delays for mobile networks
	// Retries at: 60, 180, 420, 900, 1860, 3720 seconds from start (then capped at 3600)
	MIN_BACKOFF_SECONDS        = 60    // Start at 60 seconds (reduced from 30 for battery)
	MAX_BACKOFF_SECONDS        = 3600  // Cap at 60 minutes (increased from 32 for battery)
	BACKOFF_MULTIPLIER         = 2.0   // Exponential growth factor
	UNDELIVERABLE_TIMEOUT_SECS = 604800 // 7 days - report as undeliverable after this time

	// Adaptive queue manager intervals for battery optimization
	MANAGER_INTERVAL_ACTIVE = 60  // 1 minute when there are queued messages
	MANAGER_INTERVAL_IDLE   = 300 // 5 minutes when queue is empty
)

type Queues struct {
	Config          *config.Config
	Log             *log.Logger
	Transport       transport.Transport
	Storage         storage.Storage
	FileStore       *filestore.FileStore
	LargeMailLogger *logging.LargeMailLogger
	queues          sync.Map // servername -> *Queue
	triggerCh       chan struct{} // Channel to trigger immediate queue processing
}

func NewQueues(config *config.Config, log *log.Logger, transport transport.Transport, storage storage.Storage) *Queues {
	qs := &Queues{
		Config:    config,
		Log:       log,
		Transport: transport,
		Storage:   storage,
		triggerCh: make(chan struct{}, 1), // Buffered channel to avoid blocking
	}
	time.AfterFunc(time.Second*5, qs.manager)
	return qs
}

func (qs *Queues) manager() {
	destinations, err := qs.Storage.QueueListDestinations()
	if err != nil {
		return
	}
	for _, destination := range destinations {
		_, _ = qs.queueFor(destination)
	}

	// Adaptive interval based on queue status for battery optimization
	// Active interval (60s) when messages are queued, idle interval (5min) when empty
	// This reduces unnecessary wakeups from 2,880/day to 288/day when idle
	interval := MANAGER_INTERVAL_IDLE
	if len(destinations) > 0 {
		interval = MANAGER_INTERVAL_ACTIVE
	}

	time.AfterFunc(time.Second*time.Duration(interval), qs.manager)
}

func (qs *Queues) QueueFor(from string, rcpts []string, content []byte) error {
	var pid int
	var err error

	// Check if content is large enough to use file storage
	if int64(len(content)) > types.SmallMessageThreshold && qs.FileStore != nil {
		// Large message - use streaming storage
		fmt.Printf("[QueueFor] Large message (%d bytes, %.2f MB) - using file storage\n",
			len(content), float64(len(content))/(1024*1024))
		reader := bytes.NewReader(content)
		pid, err = qs.Storage.MailCreateFromStream("Outbox", reader, qs.FileStore)
		if err != nil {
			return fmt.Errorf("q.queues.Storage.MailCreateFromStream: %w", err)
		}
	} else {
		// Small message - use BLOB storage
		fmt.Printf("[QueueFor] Small message (%d bytes, %.2f MB) - using BLOB storage\n",
			len(content), float64(len(content))/(1024*1024))
		pid, err = qs.Storage.MailCreate("Outbox", content)
		if err != nil {
			return fmt.Errorf("q.queues.Storage.MailCreate: %w", err)
		}
	}

	for _, rcpt := range rcpts {
		addr, err := mail.ParseAddress(rcpt)
		if err != nil {
			return fmt.Errorf("mail.ParseAddress: %w", err)
		}
		pk, err := utils.ParseAddress(addr.Address)
		if err != nil {
			return fmt.Errorf("parseAddress: %w", err)
		}
		host := hex.EncodeToString(pk)

		if err := qs.Storage.QueueInsertDestinationForID(host, pid, from, rcpt); err != nil {
			return fmt.Errorf("qs.Storage.QueueInsertDestinationForID: %w", err)
		}

		_, _ = qs.queueFor(host)
	}

	// Trigger immediate queue processing for faster delivery
	select {
	case qs.triggerCh <- struct{}{}:
		// Successfully triggered immediate processing
	default:
		// Channel already has a trigger pending, skip
	}

	return nil
}

// QueueForStream queues an email message from a reader for delivery to recipients
// This method supports streaming large messages without loading them entirely into memory
func (qs *Queues) QueueForStream(from string, rcpts []string, reader io.Reader) error {
	// Peek data to determine if this is a small or large message
	peekBuf := new(bytes.Buffer)
	peekBuf.Grow(int(types.SmallMessageThreshold) + 1)

	teeReader := io.TeeReader(reader, peekBuf)
	limitedReader := io.LimitReader(teeReader, int64(types.SmallMessageThreshold)+1)

	peekedData := make([]byte, types.SmallMessageThreshold+1)
	n, err := io.ReadFull(limitedReader, peekedData)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return fmt.Errorf("failed to peek message data: %w", err)
	}
	peekedData = peekedData[:n]

	isLarge := n > int(types.SmallMessageThreshold)

	// Create mail in Outbox
	var pid int
	if isLarge && qs.FileStore != nil {
		// Large message - use streaming storage
		fmt.Printf("[QueueForStream] Creating large message: peekedDataLen=%d bytes\n", len(peekedData))
		fullReader := io.MultiReader(bytes.NewReader(peekedData), reader)
		pid, err = qs.Storage.MailCreateFromStream("Outbox", fullReader, qs.FileStore)
		if err != nil {
			return fmt.Errorf("qs.Storage.MailCreateFromStream: %w", err)
		}
		qs.Log.Printf("Queued large message (MailID=%d, Size~%d MB)", pid, n/(1024*1024))
	} else {
		// Small message - read all into memory
		var b bytes.Buffer
		b.Write(peekedData)
		if _, err := io.Copy(&b, reader); err != nil {
			return fmt.Errorf("failed to read message data: %w", err)
		}
		pid, err = qs.Storage.MailCreate("Outbox", b.Bytes())
		if err != nil {
			return fmt.Errorf("qs.Storage.MailCreate: %w", err)
		}
	}

	// Queue for each recipient
	for _, rcpt := range rcpts {
		addr, err := mail.ParseAddress(rcpt)
		if err != nil {
			return fmt.Errorf("mail.ParseAddress: %w", err)
		}
		pk, err := utils.ParseAddress(addr.Address)
		if err != nil {
			return fmt.Errorf("parseAddress: %w", err)
		}
		host := hex.EncodeToString(pk)

		if err := qs.Storage.QueueInsertDestinationForID(host, pid, from, rcpt); err != nil {
			return fmt.Errorf("qs.Storage.QueueInsertDestinationForID: %w", err)
		}

		_, _ = qs.queueFor(host)
	}

	// Trigger immediate queue processing
	select {
	case qs.triggerCh <- struct{}{}:
	default:
	}

	return nil
}

func (qs *Queues) queueFor(server string) (*Queue, error) {
	v, _ := qs.queues.LoadOrStore(server, &Queue{
		queues:      qs,
		destination: server,
	})
	q, ok := v.(*Queue)
	if !ok {
		return nil, fmt.Errorf("type assertion error")
	}
	if q.running.CompareAndSwap(false, true) {
		go q.run()
	}
	return q, nil
}

// ResetRetryCounters clears all retry counters and triggers immediate queue processing
// This should be called when network conditions change (WiFi <-> Mobile) or peer connections change
func (qs *Queues) ResetRetryCounters() {
	qs.Log.Println("[Battery Optimization] Resetting all retry counters due to network/peer change")
	qs.queues.Range(func(key, value interface{}) bool {
		if q, ok := value.(*Queue); ok {
			q.retryCount = 0
			q.lastAttempt = time.Time{} // Reset last attempt to allow immediate retry
			q.permanentFailure = false
		}
		return true
	})

	// Trigger immediate queue processing
	select {
	case qs.triggerCh <- struct{}{}:
		qs.Log.Println("[Battery Optimization] Triggered immediate queue processing after reset")
	default:
		// Channel already has a trigger pending
	}
}

type Queue struct {
	queues           *Queues
	destination      string
	running          atomic.Bool
	retryCount       int
	lastAttempt      time.Time
	permanentFailure bool // Mark as permanently failed after max retries
}

func (q *Queue) run() {
	defer q.running.Store(false)
	defer q.queues.Storage.MailExpunge("Outbox") // nolint:errcheck

	// Battery-optimized exponential backoff with jitter
	if !q.lastAttempt.IsZero() && q.retryCount > 0 {
		backoffSeconds := calculateBackoff(q.retryCount)
		waitTime := time.Duration(backoffSeconds) * time.Second
		elapsed := time.Since(q.lastAttempt)
		if elapsed < waitTime {
			remaining := waitTime - elapsed
			q.queues.Log.Printf("[Battery Optimization] Waiting %v before retry to %s (attempt %d)\n",
				remaining, q.destination, q.retryCount+1)
			time.Sleep(remaining)
		}
	}
	q.lastAttempt = time.Now()

	refs, err := q.queues.Storage.QueueMailIDsForDestination(q.destination)
	if err != nil {
		q.queues.Log.Println("Error with queue:", err)
		q.retryCount++
		return
	}

	for _, ref := range refs {
		_, mail, err := q.queues.Storage.MailSelect("Outbox", ref.ID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				q.queues.Storage.QueueDeleteDestinationForID("Outbox", ref.ID)
			} else {
				q.queues.Log.Println("Failed to get mail", ref.ID, "due to error:", err)
			}
			continue
		}

		// Check if message has been undeliverable for too long
		messageAge := time.Since(mail.Date)
		if messageAge > time.Duration(UNDELIVERABLE_TIMEOUT_SECS)*time.Second {
			q.queues.Log.Printf("[Battery Optimization] Message %d to %s is undeliverable (age: %v, max: %v) - marking as failed\n",
				ref.ID, q.destination, messageAge, time.Duration(UNDELIVERABLE_TIMEOUT_SECS)*time.Second)

			// Remove from queue
			q.queues.Storage.QueueDeleteDestinationForID(q.destination, ref.ID)
			if remaining, err := q.queues.Storage.QueueSelectIsMessagePendingSend("Outbox", ref.ID); err == nil && !remaining {
				q.queues.Storage.MailDelete("Outbox", ref.ID)
			}
			// TODO: Move to "Failed" mailbox or notify user
			continue
		}

		// Check if this is a self-send (loopback)
		myAddress := hex.EncodeToString(q.queues.Config.PublicKey)
		isSelfSend := q.destination == myAddress

		if isSelfSend {
			// Local delivery - avoid network connection race condition
			q.queues.Log.Println("Local delivery from", ref.From, "to", q.destination, "(self-send)")

			// Directly store the mail in the Inbox - support both file and BLOB
			var deliveryErr error
			if mail.MailFile != "" && q.queues.FileStore != nil {
				// Large message - copy file to INBOX
				file, err := q.queues.FileStore.ReadMail(mail.MailFile)
				if err != nil {
					deliveryErr = fmt.Errorf("failed to read mail file: %w", err)
				} else {
					defer file.Close() // nolint:errcheck
					_, deliveryErr = q.queues.Storage.MailCreateFromStream("INBOX", file, q.queues.FileStore)
				}
			} else {
				// Small message - use BLOB
				_, deliveryErr = q.queues.Storage.MailCreate("INBOX", mail.Mail)
			}

			if deliveryErr != nil {
				q.retryCount++
				q.queues.Log.Printf("Failed local delivery to %s (retry count: %d): %v\n", q.destination, q.retryCount, deliveryErr)
				continue
			}

			// Remove from queue
			if err := q.queues.Storage.QueueDeleteDestinationForID(q.destination, ref.ID); err != nil {
				q.queues.Log.Printf("Failed to remove from queue: %v\n", err)
			}

			if remaining, err := q.queues.Storage.QueueSelectIsMessagePendingSend("Outbox", ref.ID); err != nil {
				q.queues.Log.Printf("Failed to check pending: %v\n", err)
			} else if !remaining {
				// Move from Outbox to Sent - preserves the message for record keeping
				if q.queues.FileStore != nil {
					q.queues.Storage.MailMoveWithFileStore("Outbox", ref.ID, "Sent", q.queues.FileStore)
				} else {
					q.queues.Storage.MailMove("Outbox", ref.ID, "Sent")
				}
				q.queues.Log.Printf("Moved mail %d from Outbox to Sent\n", ref.ID)
			}

			q.retryCount = 0
			q.queues.Log.Println("Local delivery successful from", ref.From, "to", q.destination)
			continue
		}

		// Remote delivery via QUIC
		q.queues.Log.Println("Sending mail from", ref.From, "to", q.destination)

		if err := func() error {
			// Prepare mail reader (file or BLOB)
			var mailReader io.ReadCloser
			var mailSize int64
			if mail.MailFile != "" && q.queues.FileStore != nil {
				// Large message - read from file
				file, err := q.queues.FileStore.ReadMail(mail.MailFile)
				if err != nil {
					return fmt.Errorf("failed to read mail file: %w", err)
				}
				mailReader = file
				mailSize = mail.Size
			} else {
				// Small message - read from BLOB
				mailReader = io.NopCloser(bytes.NewReader(mail.Mail))
				mailSize = int64(len(mail.Mail))
			}
			defer mailReader.Close() // nolint:errcheck

			// Start large mail logging if needed
			var opID string
			isLarge := mailSize > types.SmallMessageThreshold
			if isLarge && q.queues.LargeMailLogger != nil {
				opID = fmt.Sprintf("SND-%s-%d", q.destination[:8], ref.ID)
				q.queues.LargeMailLogger.StartOperation(opID, ref.ID, mailSize, "SEND")
			}

			// Establish connection and send
			conn, err := q.queues.Transport.Dial(q.destination)
			if err != nil {
				if isLarge && q.queues.LargeMailLogger != nil {
					q.queues.LargeMailLogger.EndOperation(opID, false, err.Error())
				}
				return fmt.Errorf("q.queues.Transport.Dial: %w", err)
			}
			defer conn.Close() // nolint:errcheck

			client, err := smtp.NewClient(conn, q.destination)
			if err != nil {
				if isLarge && q.queues.LargeMailLogger != nil {
					q.queues.LargeMailLogger.EndOperation(opID, false, err.Error())
				}
				return fmt.Errorf("smtp.NewClient: %w", err)
			}
			defer client.Close() // nolint:errcheck

			// Enable debug logging for SMTP protocol to diagnose SIZE extension issue
			if false { // Set to true to enable detailed SMTP client protocol logging
				client.DebugWriter = q.queues.Log.Writer()
			}

			if err := client.Hello(hex.EncodeToString(q.queues.Config.PublicKey)); err != nil {
				q.queues.Log.Println("Remote server", q.destination, "did not accept HELLO:", err)
				if isLarge && q.queues.LargeMailLogger != nil {
					q.queues.LargeMailLogger.EndOperation(opID, false, err.Error())
				}
				return fmt.Errorf("client.Hello: %w", err)
			}

			// DEBUG: Log all extensions received from server
			q.queues.Log.Printf("DEBUG: Checking extensions after EHLO to %s", q.destination)
			allExts := []string{}
			for _, extName := range []string{"SIZE", "8BITMIME", "PIPELINING", "ENHANCEDSTATUSCODES", "AUTH", "STARTTLS"} {
				supported, param := client.Extension(extName)
				if supported {
					if param != "" {
						allExts = append(allExts, fmt.Sprintf("%s=%s", extName, param))
					} else {
						allExts = append(allExts, extName)
					}
				}
			}
			q.queues.Log.Printf("DEBUG: Server %s extensions: %v", q.destination, allExts)

			// RFC 1870 SIZE extension: Inform recipient of message size
			// This allows recipient to reject BEFORE data transfer if quota exceeded
			mailOpts := &smtp.MailOptions{
				Size: int(mailSize), // int in v0.15.0
			}

			// Check if server supports SIZE extension (v0.15.0)
			sizeSupported, sizeParam := client.Extension("SIZE")
			if sizeSupported {
				q.queues.Log.Printf("Server %s supports SIZE extension, param=%s", q.destination, sizeParam)
			} else {
				q.queues.Log.Printf("WARNING: Server %s does NOT support SIZE extension", q.destination)
			}

			q.queues.Log.Printf("Sending MAIL FROM with SIZE=%d bytes (%.2f MB) to %s (SIZE supported: %v)",
				mailSize, float64(mailSize)/(1024*1024), q.destination, sizeSupported)

			if err := client.Mail(ref.From, mailOpts); err != nil {
				q.queues.Log.Printf("Remote server %s REJECTED MAIL FROM (SIZE check): %v", q.destination, err)
				if isLarge && q.queues.LargeMailLogger != nil {
					q.queues.LargeMailLogger.EndOperation(opID, false, err.Error())
				}
				return fmt.Errorf("client.Mail: %w", err)
			}

			if err := client.Rcpt(ref.Rcpt); err != nil {
				q.queues.Log.Println("Remote server", q.destination, "did not accept RCPT:", err)
				if isLarge && q.queues.LargeMailLogger != nil {
					q.queues.LargeMailLogger.EndOperation(opID, false, err.Error())
				}
				return fmt.Errorf("client.Rcpt: %w", err)
			}

			writer, err := client.Data()
			if err != nil {
				if isLarge && q.queues.LargeMailLogger != nil {
					q.queues.LargeMailLogger.EndOperation(opID, false, err.Error())
				}
				return fmt.Errorf("client.Data: %w", err)
			}
			defer writer.Close() // nolint:errcheck

			// Streaming send with chunking and progress logging
			buffer := make([]byte, types.ChunkSize) // 128 KB chunks
			totalSent := int64(0)
			lastLoggedAt := int64(0)
			const logInterval = 5 * 1024 * 1024 // Log every 5 MB

			for {
				n, readErr := mailReader.Read(buffer)
				if n > 0 {
					if _, writeErr := writer.Write(buffer[:n]); writeErr != nil {
						if isLarge && q.queues.LargeMailLogger != nil {
							q.queues.LargeMailLogger.EndOperation(opID, false, writeErr.Error())
						}
						return fmt.Errorf("writer.Write: %w", writeErr)
					}
					totalSent += int64(n)

					// Log progress every 5 MB for large messages
					if isLarge && q.queues.LargeMailLogger != nil && totalSent-lastLoggedAt >= logInterval {
						q.queues.LargeMailLogger.LogMilestone(opID, "sending", totalSent,
							fmt.Sprintf("Sent %d MB", totalSent/(1024*1024)))
						lastLoggedAt = totalSent
					}
				}

				if readErr == io.EOF {
					break
				}
				if readErr != nil {
					if isLarge && q.queues.LargeMailLogger != nil {
						q.queues.LargeMailLogger.EndOperation(opID, false, readErr.Error())
					}
					return fmt.Errorf("mailReader.Read: %w", readErr)
				}
			}

			// Log final completion for large messages
			if isLarge && q.queues.LargeMailLogger != nil {
				q.queues.LargeMailLogger.EndOperation(opID, true, "")
			}

			// Remove from queue
			if err := q.queues.Storage.QueueDeleteDestinationForID(q.destination, ref.ID); err != nil {
				return fmt.Errorf("q.queues.Storage.QueueDeleteDestinationForID: %w", err)
			}

			// Check if this was the last recipient for this message
			if remaining, err := q.queues.Storage.QueueSelectIsMessagePendingSend("Outbox", ref.ID); err != nil {
				return fmt.Errorf("q.queues.Storage.QueueSelectIsMessagePendingSend: %w", err)
			} else if !remaining {
				// Last recipient - move from Outbox to Sent (preserves the message for record keeping)
				var moveErr error
				if q.queues.FileStore != nil {
					moveErr = q.queues.Storage.MailMoveWithFileStore("Outbox", ref.ID, "Sent", q.queues.FileStore)
				} else {
					moveErr = q.queues.Storage.MailMove("Outbox", ref.ID, "Sent")
				}
				if moveErr != nil {
					return fmt.Errorf("failed to move mail to Sent: %w", moveErr)
				}
				q.queues.Log.Printf("Moved mail %d from Outbox to Sent\n", ref.ID)
			}

			return nil
		}(); err != nil {
			// Classify error type for intelligent retry
			if isNetworkError(err) {
				q.retryCount++
				q.queues.Log.Printf("[Battery Optimization] Network error sending to %s (retry %d): %v\n",
					q.destination, q.retryCount, err)
				// Will retry on next manager run with exponential backoff
			} else if isPermanentError(err) {
				q.permanentFailure = true
				q.queues.Log.Printf("[Battery Optimization] Permanent error sending to %s - stopping retries: %v\n",
					q.destination, err)
				// Delete from queue to prevent retries
				q.queues.Storage.QueueDeleteDestinationForID(q.destination, ref.ID)
				if remaining, err := q.queues.Storage.QueueSelectIsMessagePendingSend("Outbox", ref.ID); err == nil && !remaining {
					q.queues.Storage.MailDelete("Outbox", ref.ID)
				}
				// TODO: Notify user of permanent failure
				return
			} else {
				// Unknown error - treat as temporary
				q.retryCount++
				q.queues.Log.Printf("Failed to send to %s (retry %d): %v\n",
					q.destination, q.retryCount, err)
				// Will retry on next manager run with exponential backoff
			}
		} else {
			q.retryCount = 0 // Reset retry count on success
			q.permanentFailure = false
			q.queues.Log.Println("Sent mail from", ref.From, "to", q.destination)
		}
	}
}

// calculateBackoff calculates exponential backoff with jitter
func calculateBackoff(retryCount int) int {
	// Exponential backoff: 30, 60, 120, 240, 480, 960, 1920, 1920...
	backoff := float64(MIN_BACKOFF_SECONDS) * math.Pow(BACKOFF_MULTIPLIER, float64(retryCount-1))

	// Cap at maximum
	if backoff > float64(MAX_BACKOFF_SECONDS) {
		backoff = float64(MAX_BACKOFF_SECONDS)
	}

	// Add jitter (±20%) to prevent thundering herd
	jitter := rand.Float64()*0.4 - 0.2 // -20% to +20%
	backoff = backoff * (1.0 + jitter)

	return int(backoff)
}

// isNetworkError checks if error is network-related (temporary)
func isNetworkError(err error) bool {
	errStr := err.Error()
	return strings.Contains(errStr, "context deadline exceeded") ||
		strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "network is unreachable") ||
		strings.Contains(errStr, "no route to host") ||
		strings.Contains(errStr, "Transport.Dial") ||
		strings.Contains(errStr, "i/o timeout")
}

// isPermanentError checks if error is permanent (don't retry)
func isPermanentError(err error) bool {
	errStr := err.Error()
	return strings.Contains(errStr, "invalid address") ||
		strings.Contains(errStr, "mailbox not found") ||
		strings.Contains(errStr, "permanent failure") ||
		strings.Contains(errStr, "recipient rejected") ||
		strings.Contains(errStr, "552 unread quota exceeded") || // RFC 1870 SIZE quota rejection
		strings.Contains(errStr, "unread quota exceeded")
}
