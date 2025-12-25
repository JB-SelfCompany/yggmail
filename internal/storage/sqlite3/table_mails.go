/*
 *  Copyright (c) 2021 Neil Alexander
 *
 *  This Source Code Form is subject to the terms of the Mozilla Public
 *  License, v. 2.0. If a copy of the MPL was not distributed with this
 *  file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package sqlite3

import (
	"bytes"
	"database/sql"
	"fmt"
	"io"
	"time"

	"github.com/JB-SelfCompany/yggmail/internal/storage/filestore"
	"github.com/JB-SelfCompany/yggmail/internal/storage/types"
)

type TableMails struct {
	db               *sql.DB
	writer           *Writer
	selectMails      *sql.Stmt
	selectMail       *sql.Stmt
	selectMailNextID *sql.Stmt
	selectIDForSeq   *sql.Stmt
	searchMail       *sql.Stmt
	createMail       *sql.Stmt
	createMailFile   *sql.Stmt
	countMails       *sql.Stmt
	countUnseenMails *sql.Stmt
	updateMailFlags  *sql.Stmt
	deleteMail       *sql.Stmt
	expungeMail      *sql.Stmt
	moveMail         *sql.Stmt
}

const mailsSchema = `
	CREATE TABLE IF NOT EXISTS mails (
		mailbox 	TEXT NOT NULL,
		id			INTEGER NOT NULL DEFAULT 1,
		mail 		BLOB,
		mail_file   TEXT,
		size        INTEGER NOT NULL DEFAULT 0,
		datetime    INTEGER NOT NULL,
		seen		BOOLEAN NOT NULL DEFAULT 0, -- the mail has been read
		answered	BOOLEAN NOT NULL DEFAULT 0, -- the mail has been replied to
		flagged		BOOLEAN NOT NULL DEFAULT 0, -- the mail has been flagged for later attention
		deleted		BOOLEAN NOT NULL DEFAULT 0, -- the email is marked for deletion at next EXPUNGE
		PRIMARY KEY (mailbox, id),
		FOREIGN KEY (mailbox) REFERENCES mailboxes(mailbox) ON DELETE CASCADE ON UPDATE CASCADE,
		CHECK ((mail IS NOT NULL AND mail_file IS NULL) OR (mail IS NULL AND mail_file IS NOT NULL))
	);

	CREATE VIEW IF NOT EXISTS inboxes AS SELECT * FROM (
		SELECT ROW_NUMBER() OVER (PARTITION BY mailbox) AS seq, * FROM mails
	)
	ORDER BY mailbox, id;
`

const selectMailsStmt = `
	SELECT * FROM inboxes
	ORDER BY mailbox, id
`

const selectMailStmt = `
	SELECT seq, id, mail, mail_file, size, datetime, seen, answered, flagged, deleted FROM inboxes
	WHERE mailbox = $1 AND id = $2
	ORDER BY mailbox, id
`

const selectMailCountStmt = `
	SELECT COUNT(*) FROM mails WHERE mailbox = $1
`

const selectMailUnseenStmt = `
	SELECT COUNT(*) FROM mails WHERE mailbox = $1 AND seen = 0
`

const searchMailStmt = `
	SELECT id FROM mails
	WHERE mailbox = $1
	ORDER BY mailbox, id
`

const insertMailStmt = `
	INSERT INTO mails (mailbox, id, mail, size, datetime) VALUES(
		$1, (
			SELECT IFNULL(MAX(id)+1,1) AS id FROM mails
			WHERE mailbox = $1
		), $2, $3, $4
	)
	RETURNING id;
`

const insertMailFileStmt = `
	INSERT INTO mails (mailbox, id, mail, mail_file, size, datetime) VALUES(
		$1, (
			SELECT IFNULL(MAX(id)+1,1) AS id FROM mails
			WHERE mailbox = $1
		), NULL, $2, $3, $4
	)
	RETURNING id;
`

const selectIDForSeqStmt = `
	SELECT id FROM inboxes
	WHERE mailbox = $1 AND seq = $2
`

const selectMailNextID = `
	SELECT IFNULL(MAX(id)+1,1) AS id FROM mails
	WHERE mailbox = $1	
`

const updateMailFlagsStmt = `
	UPDATE mails SET seen = $1, answered = $2, flagged = $3, deleted = $4 WHERE mailbox = $5 AND id = $6
`

const deleteMailStmt = `
	UPDATE mails SET deleted = 1 WHERE mailbox = $1 AND id = $2
`

const expungeMailStmt = `
	DELETE FROM mails WHERE mailbox = $1 AND deleted = 1
`

const moveMailStmt = `
	UPDATE mails SET mailbox = $1 WHERE mailbox = $2 AND id = $3
`

func NewTableMails(db *sql.DB, writer *Writer) (*TableMails, error) {
	t := &TableMails{
		db:     db,
		writer: writer,
	}
	_, err := db.Exec(mailsSchema)
	if err != nil {
		return nil, fmt.Errorf("db.Exec: %w", err)
	}
	t.selectMails, err = db.Prepare(selectMailsStmt)
	if err != nil {
		return nil, fmt.Errorf("db.Prepare(selectMailsStmt): %w", err)
	}
	t.selectMail, err = db.Prepare(selectMailStmt)
	if err != nil {
		return nil, fmt.Errorf("db.Prepare(selectMailStmt): %w", err)
	}
	t.selectMailNextID, err = db.Prepare(selectMailNextID)
	if err != nil {
		return nil, fmt.Errorf("db.Prepare(selectMailNextID): %w", err)
	}
	t.selectIDForSeq, err = db.Prepare(selectIDForSeqStmt)
	if err != nil {
		return nil, fmt.Errorf("db.Prepare(selectPIDForIDStmt): %w", err)
	}
	t.searchMail, err = db.Prepare(searchMailStmt)
	if err != nil {
		return nil, fmt.Errorf("db.Prepare(selectPIDForIDStmt): %w", err)
	}
	t.createMail, err = db.Prepare(insertMailStmt)
	if err != nil {
		return nil, fmt.Errorf("db.Prepare(insertMailStmt): %w", err)
	}
	t.createMailFile, err = db.Prepare(insertMailFileStmt)
	if err != nil {
		return nil, fmt.Errorf("db.Prepare(insertMailFileStmt): %w", err)
	}
	t.updateMailFlags, err = db.Prepare(updateMailFlagsStmt)
	if err != nil {
		return nil, fmt.Errorf("db.Prepare(updateMailSeenStmt): %w", err)
	}
	t.deleteMail, err = db.Prepare(deleteMailStmt)
	if err != nil {
		return nil, fmt.Errorf("db.Prepare(deleteMailStmt): %w", err)
	}
	t.expungeMail, err = db.Prepare(expungeMailStmt)
	if err != nil {
		return nil, fmt.Errorf("db.Prepare(expungeMailStmt): %w", err)
	}
	t.countMails, err = db.Prepare(selectMailCountStmt)
	if err != nil {
		return nil, fmt.Errorf("db.Prepare(selectMailCountStmt): %w", err)
	}
	t.countUnseenMails, err = db.Prepare(selectMailUnseenStmt)
	if err != nil {
		return nil, fmt.Errorf("db.Prepare(selectMailUnseenStmt): %w", err)
	}
	t.moveMail, err = db.Prepare(moveMailStmt)
	if err != nil {
		return nil, fmt.Errorf("db.Prepare(moveMailStmt): %w", err)
	}
	return t, nil
}

func (t *TableMails) MailCreate(mailbox string, data []byte) (int, error) {
	var id int
	size := int64(len(data))
	err := t.writer.Do(t.db, nil, func(txn *sql.Tx) error {
		return t.createMail.QueryRow(mailbox, data, size, time.Now().Unix()).Scan(&id)
	})
	return id, err
}

// MailCreateFromStream creates a mail from a stream, automatically choosing
// between BLOB storage (small messages) and file storage (large messages)
func (t *TableMails) MailCreateFromStream(mailbox string, reader io.Reader, fs *filestore.FileStore) (int, error) {
	// Read data into buffer to determine size
	// Use a buffer that can hold SmallMessageThreshold + 1 byte to detect large messages
	peekBuf := new(bytes.Buffer)
	peekBuf.Grow(int(types.SmallMessageThreshold) + 1)

	limited := io.LimitReader(reader, types.SmallMessageThreshold+1)
	written, err := peekBuf.ReadFrom(limited)
	if err != nil && err != io.EOF {
		return 0, fmt.Errorf("failed to read data: %w", err)
	}

	// Check if message is small enough for BLOB storage
	// Use < instead of <= so that exactly 10MB goes to file storage
	if written < types.SmallMessageThreshold {
		// Small message - read remaining data if any and store in BLOB
		remainingData, err := io.ReadAll(reader)
		if err != nil {
			return 0, fmt.Errorf("failed to read remaining data: %w", err)
		}

		allData := append(peekBuf.Bytes(), remainingData...)
		return t.MailCreate(mailbox, allData)
	}

	// Large message - need to store in file
	// First, get the next ID for this mailbox
	nextID, err := t.MailNextID(mailbox)
	if err != nil {
		return 0, fmt.Errorf("failed to get next mail ID: %w", err)
	}

	// Create a multi-reader combining peek buffer and remaining stream
	fullReader := io.MultiReader(peekBuf, reader)

	// Store to file and get actual size written
	filePath, fileSize, err := fs.StoreMail(nextID, mailbox, fullReader)
	if err != nil {
		return 0, fmt.Errorf("failed to store mail to file: %w", err)
	}

	// Use actual file size from StoreMail (accurate byte count from io.Copy)
	size := fileSize
	fmt.Printf("[TableMails] MailCreateFromStream: mailbox=%s, nextID=%d, peekBuf.Len=%d, fileSize=%d (%.2f MB)\n",
		mailbox, nextID, peekBuf.Len(), fileSize, float64(fileSize)/(1024*1024))

	// Insert database record with file path
	var id int
	err = t.writer.Do(t.db, nil, func(txn *sql.Tx) error {
		return t.createMailFile.QueryRow(mailbox, filePath, size, time.Now().Unix()).Scan(&id)
	})

	if err != nil {
		// Failed to insert DB record, clean up file
		fs.DeleteMail(filePath)
		return 0, fmt.Errorf("failed to insert mail record: %w", err)
	}

	return id, nil
}

func (t *TableMails) MailSelect(mailbox string, id int) (int, *types.Mail, error) {
	var seq int
	var datetime int64
	var mailData sql.NullString // For mail_file (can be NULL)
	mail := &types.Mail{
		Mailbox: mailbox,
	}
	err := t.selectMail.QueryRow(mailbox, id).Scan(
		&seq, &mail.ID, &mail.Mail, &mailData, &mail.Size, &datetime,
		&mail.Seen, &mail.Answered, &mail.Flagged, &mail.Deleted,
	)
	mail.Date = time.Unix(datetime, 0)
	if mailData.Valid {
		mail.MailFile = mailData.String
	}
	// If Size is 0 and Mail is not empty, calculate size from Mail field (backward compatibility)
	if mail.Size == 0 && len(mail.Mail) > 0 {
		mail.Size = int64(len(mail.Mail))
	}
	return seq, mail, err
}

func (t *TableMails) MailSearch(mailbox string) ([]uint32, error) {
	var ids []uint32
	rows, err := t.searchMail.Query(mailbox)
	if err != nil {
		return nil, fmt.Errorf("t.searchMail.Query: %w", err)
	}
	defer rows.Close() // nolint:errcheck
	for rows.Next() {
		var id uint32
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("rows.Scan: %w", err)
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func (t *TableMails) MailNextID(mailbox string) (int, error) {
	var id int
	err := t.selectMailNextID.QueryRow(mailbox).Scan(&id)
	return id, err
}

func (t *TableMails) MailIDForSeq(mailbox string, seq int) (int, error) {
	var id int
	err := t.selectIDForSeq.QueryRow(mailbox, seq).Scan(&id)
	return id, err
}

func (t *TableMails) MailUnseen(mailbox string) (int, error) {
	var unseen int
	err := t.countUnseenMails.QueryRow(mailbox).Scan(&unseen)
	return unseen, err
}

// MailGetUnreadSize returns the total size in bytes of all messages across all mailboxes
// Note: Despite the name, this now returns total mailbox size, not just unread
// (kept for API compatibility)
func (t *TableMails) MailGetUnreadSize() (int64, error) {
	var totalSize sql.NullInt64
	err := t.db.QueryRow(`
		SELECT IFNULL(SUM(size), 0)
		FROM mails
	`).Scan(&totalSize)

	if err != nil {
		return 0, fmt.Errorf("failed to calculate total mailbox size: %w", err)
	}

	if !totalSize.Valid {
		return 0, nil
	}

	return totalSize.Int64, nil
}

// MailGetUnreadSizeForMailbox returns the total size in bytes of all messages in a specific mailbox
// Note: Despite the name, this now returns total mailbox size, not just unread
// (kept for API compatibility)
func (t *TableMails) MailGetUnreadSizeForMailbox(mailbox string) (int64, error) {
	var totalSize sql.NullInt64
	err := t.db.QueryRow(`
		SELECT IFNULL(SUM(size), 0)
		FROM mails
		WHERE mailbox = ?
	`, mailbox).Scan(&totalSize)

	if err != nil {
		return 0, fmt.Errorf("failed to calculate total size for mailbox: %w", err)
	}

	if !totalSize.Valid {
		return 0, nil
	}

	return totalSize.Int64, nil
}

func (t *TableMails) MailUpdateFlags(mailbox string, id int, seen, answered, flagged, deleted bool) error {
	return t.writer.Do(t.db, nil, func(txn *sql.Tx) error {
		_, err := t.updateMailFlags.Exec(seen, answered, flagged, deleted, mailbox, id)
		return err
	})
}

func (t *TableMails) MailDelete(mailbox string, id int) error {
	return t.writer.Do(t.db, nil, func(txn *sql.Tx) error {
		_, err := t.deleteMail.Exec(mailbox, id)
		return err
	})
}

func (t *TableMails) MailExpunge(mailbox string) error {
	return t.MailExpungeWithFileStore(mailbox, nil)
}

func (t *TableMails) MailExpungeWithFileStore(mailbox string, fs *filestore.FileStore) error {
	return t.writer.Do(t.db, nil, func(txn *sql.Tx) error {
		// If fileStore is provided, delete associated files first
		if fs != nil {
			// Get all mail_file paths for messages marked for deletion
			rows, err := t.db.Query("SELECT mail_file FROM mails WHERE mailbox = ? AND deleted = 1 AND mail_file IS NOT NULL", mailbox)
			if err != nil {
				return fmt.Errorf("failed to query mail files: %w", err)
			}
			defer rows.Close() // nolint:errcheck

			filesToDelete := []string{}
			for rows.Next() {
				var filePath string
				if err := rows.Scan(&filePath); err != nil {
					return fmt.Errorf("failed to scan file path: %w", err)
				}
				filesToDelete = append(filesToDelete, filePath)
			}

			// Delete files
			for _, filePath := range filesToDelete {
				if err := fs.DeleteMail(filePath); err != nil {
					// Log error but don't fail the entire expunge
					// The database record will still be deleted
					fmt.Printf("Warning: failed to delete mail file %s: %v\n", filePath, err)
				}
			}
		}

		// Delete database records
		_, err := t.expungeMail.Exec(mailbox)
		return err
	})
}

func (t *TableMails) MailCount(mailbox string) (int, error) {
	var count int
	err := t.countMails.QueryRow(mailbox).Scan(&count)
	return count, err
}

func (t *TableMails) MailMove(mailbox string, id int, destination string) error {
	return t.MailMoveWithFileStore(mailbox, id, destination, nil)
}

func (t *TableMails) MailMoveWithFileStore(mailbox string, id int, destination string, fs *filestore.FileStore) error {
	return t.writer.Do(t.db, nil, func(txn *sql.Tx) error {
		// If fileStore is provided, move the file first
		if fs != nil {
			// Get current mail_file path
			var mailFile sql.NullString
			err := t.db.QueryRow("SELECT mail_file FROM mails WHERE mailbox = ? AND id = ?", mailbox, id).Scan(&mailFile)
			if err != nil && err != sql.ErrNoRows {
				return fmt.Errorf("failed to query mail_file: %w", err)
			}

			// If message has a file, move it
			if mailFile.Valid && mailFile.String != "" {
				// Move file to new mailbox directory
				newPath, err := fs.MoveMail(mailFile.String, destination, id)
				if err != nil {
					return fmt.Errorf("failed to move mail file: %w", err)
				}

				// Update mail_file path in database
				_, err = t.db.Exec("UPDATE mails SET mail_file = ? WHERE mailbox = ? AND id = ?", newPath, mailbox, id)
				if err != nil {
					// Try to move file back on error
					fs.MoveMail(newPath, mailbox, id)
					return fmt.Errorf("failed to update mail_file path: %w", err)
				}
			}
		}

		// Update mailbox
		_, err := t.moveMail.Exec(destination, mailbox, id)
		return err
	})
}

// MailGetAllFilePaths returns a map of all mail file paths currently stored in the database
// Used by CleanupOrphanedFiles to identify which files are still in use
func (t *TableMails) MailGetAllFilePaths() (map[string]bool, error) {
	validPaths := make(map[string]bool)

	rows, err := t.db.Query("SELECT mail_file FROM mails WHERE mail_file IS NOT NULL")
	if err != nil {
		return nil, fmt.Errorf("failed to query mail files: %w", err)
	}
	defer rows.Close() // nolint:errcheck

	for rows.Next() {
		var filePath string
		if err := rows.Scan(&filePath); err != nil {
			return nil, fmt.Errorf("failed to scan file path: %w", err)
		}
		validPaths[filePath] = true
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating rows: %w", err)
	}

	return validPaths, nil
}

