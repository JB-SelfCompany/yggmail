package sqlite3

import (
	"bytes"
	"database/sql"
	"fmt"
	"log"

	"github.com/JB-SelfCompany/yggmail/internal/storage/filestore"
)

const (
	currentSchemaVersion = 2
)

// GetSchemaVersion returns the current schema version from the database
// Returns 1 if the schema_version table doesn't exist (legacy database)
func GetSchemaVersion(db *sql.DB) (int, error) {
	// Check if schema_version table exists
	var tableName string
	err := db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version'").Scan(&tableName)
	if err == sql.ErrNoRows {
		// Legacy database without schema_version table
		return 1, nil
	}
	if err != nil {
		return 0, fmt.Errorf("failed to check schema_version table: %w", err)
	}

	// Get version
	var version int
	err = db.QueryRow("SELECT version FROM schema_version ORDER BY version DESC LIMIT 1").Scan(&version)
	if err == sql.ErrNoRows {
		return 1, nil
	}
	if err != nil {
		return 0, fmt.Errorf("failed to query schema version: %w", err)
	}

	return version, nil
}

// SetSchemaVersion sets the schema version in the database
func SetSchemaVersion(db *sql.DB, version int) error {
	// Create schema_version table if it doesn't exist
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS schema_version (
			version INTEGER NOT NULL,
			applied_at INTEGER NOT NULL
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create schema_version table: %w", err)
	}

	// Insert version
	_, err = db.Exec("INSERT INTO schema_version (version, applied_at) VALUES (?, strftime('%s', 'now'))", version)
	if err != nil {
		return fmt.Errorf("failed to insert schema version: %w", err)
	}

	return nil
}

// migrateV1toV2 migrates the database schema from version 1 to version 2
// Adds mail_file and size columns to the mails table
func migrateV1toV2(db *sql.DB) error {
	log.Println("Migrating database schema from v1 to v2...")

	// Check if table exists first
	var tableExists int
	err := db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='mails'").Scan(&tableExists)
	if err != nil {
		return fmt.Errorf("failed to check for mails table: %w", err)
	}

	if tableExists == 0 {
		// Table doesn't exist yet - it will be created with the new schema
		log.Println("Table 'mails' doesn't exist yet, will be created with new schema")
		return nil
	}

	// Check if columns already exist (in case of partial migration)
	var columnExists int
	err = db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('mails') WHERE name='mail_file'").Scan(&columnExists)
	if err != nil {
		return fmt.Errorf("failed to check for mail_file column: %w", err)
	}

	if columnExists > 0 {
		log.Println("Column mail_file already exists, migration already completed")
		return nil
	}

	// SQLite doesn't support modifying column constraints
	// We need to recreate the table with the new schema
	log.Println("Recreating table with new schema...")

	// Start transaction
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Create new table with correct schema
	_, err = tx.Exec(`
		CREATE TABLE mails_new (
			mailbox 	TEXT NOT NULL,
			id			INTEGER NOT NULL DEFAULT 1,
			mail 		BLOB,
			mail_file   TEXT,
			size        INTEGER NOT NULL DEFAULT 0,
			datetime    INTEGER NOT NULL,
			seen		BOOLEAN NOT NULL DEFAULT 0,
			answered	BOOLEAN NOT NULL DEFAULT 0,
			flagged		BOOLEAN NOT NULL DEFAULT 0,
			deleted		BOOLEAN NOT NULL DEFAULT 0,
			PRIMARY KEY (mailbox, id),
			FOREIGN KEY (mailbox) REFERENCES mailboxes(mailbox) ON DELETE CASCADE ON UPDATE CASCADE,
			CHECK ((mail IS NOT NULL AND mail_file IS NULL) OR (mail IS NULL AND mail_file IS NOT NULL))
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create new table: %w", err)
	}

	// Copy data from old table, calculating size
	_, err = tx.Exec(`
		INSERT INTO mails_new (mailbox, id, mail, mail_file, size, datetime, seen, answered, flagged, deleted)
		SELECT mailbox, id, mail, NULL, LENGTH(mail), datetime, seen, answered, flagged, deleted
		FROM mails
	`)
	if err != nil {
		return fmt.Errorf("failed to copy data: %w", err)
	}

	// Drop view first (it depends on the table)
	_, err = tx.Exec("DROP VIEW IF EXISTS inboxes")
	if err != nil {
		return fmt.Errorf("failed to drop view: %w", err)
	}

	// Drop old table
	_, err = tx.Exec("DROP TABLE mails")
	if err != nil {
		return fmt.Errorf("failed to drop old table: %w", err)
	}

	// Rename new table
	_, err = tx.Exec("ALTER TABLE mails_new RENAME TO mails")
	if err != nil {
		return fmt.Errorf("failed to rename table: %w", err)
	}

	// Recreate view
	_, err = tx.Exec(`
		CREATE VIEW IF NOT EXISTS inboxes AS SELECT * FROM (
			SELECT ROW_NUMBER() OVER (PARTITION BY mailbox) AS seq, * FROM mails
		)
		ORDER BY mailbox, id
	`)
	if err != nil {
		return fmt.Errorf("failed to recreate view: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	log.Println("Migration to v2 completed successfully")
	return nil
}

// RunMigrations executes all necessary migrations to bring the database to the current schema version
func RunMigrations(db *sql.DB) error {
	version, err := GetSchemaVersion(db)
	if err != nil {
		return fmt.Errorf("failed to get schema version: %w", err)
	}

	log.Printf("Current database schema version: %d, target version: %d", version, currentSchemaVersion)

	if version >= currentSchemaVersion {
		log.Println("Database schema is up to date")
		return nil
	}

	// Execute migrations sequentially
	for v := version; v < currentSchemaVersion; v++ {
		switch v {
		case 1:
			if err := migrateV1toV2(db); err != nil {
				return fmt.Errorf("migration v1->v2 failed: %w", err)
			}
			if err := SetSchemaVersion(db, 2); err != nil {
				return fmt.Errorf("failed to set schema version to 2: %w", err)
			}
		default:
			return fmt.Errorf("unknown migration version: %d", v)
		}
	}

	log.Println("All migrations completed successfully")
	return nil
}

// MigrateLargeMessagesToFiles migrates large messages from BLOB storage to file storage
// This is run asynchronously in the background after initialization
// threshold: messages larger than this will be migrated to files (e.g., 10MB)
func MigrateLargeMessagesToFiles(db *sql.DB, fs *filestore.FileStore, threshold int64) error {
	log.Printf("Starting background migration of large messages to file storage (threshold: %.2f MB)...", float64(threshold)/(1024*1024))

	// Find all messages larger than threshold that are still in BLOB storage
	rows, err := db.Query(`
		SELECT mailbox, id, mail, LENGTH(mail) as size
		FROM mails
		WHERE mail IS NOT NULL
		AND mail_file IS NULL
		AND LENGTH(mail) > ?
		ORDER BY LENGTH(mail) DESC
	`, threshold)
	if err != nil {
		return fmt.Errorf("failed to query large messages: %w", err)
	}
	defer rows.Close() // nolint:errcheck

	migratedCount := 0
	var totalSize int64

	for rows.Next() {
		var mailbox string
		var id int
		var mailData []byte
		var size int64

		if err := rows.Scan(&mailbox, &id, &mailData, &size); err != nil {
			log.Printf("Failed to scan message row: %v", err)
			continue
		}

		// Store message to file
		reader := bytes.NewReader(mailData)
		filePath, fileSize, err := fs.StoreMail(id, mailbox, reader)
		if err != nil {
			log.Printf("Failed to store message %s:%d to file: %v", mailbox, id, err)
			continue
		}

		// Update database record with actual file size
		_, err = db.Exec(`
			UPDATE mails
			SET mail = NULL, mail_file = ?, size = ?
			WHERE mailbox = ? AND id = ?
		`, filePath, fileSize, mailbox, id)
		if err != nil {
			log.Printf("Failed to update database for message %s:%d: %v", mailbox, id, err)
			// Try to clean up the file
			fs.DeleteMail(filePath)
			continue
		}

		migratedCount++
		totalSize += size
		log.Printf("Migrated message %s:%d (%.2f MB) to file storage", mailbox, id, float64(size)/(1024*1024))
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("error iterating messages: %w", err)
	}

	if migratedCount > 0 {
		log.Printf("Background migration completed: migrated %d messages (%.2f MB total) to file storage",
			migratedCount, float64(totalSize)/(1024*1024))
	} else {
		log.Println("Background migration completed: no large messages found to migrate")
	}

	return nil
}

// EstimateMigrationSize returns the number of messages and total size that would be migrated
func EstimateMigrationSize(db *sql.DB, threshold int64) (count int, size int64, err error) {
	err = db.QueryRow(`
		SELECT COUNT(*), IFNULL(SUM(LENGTH(mail)), 0)
		FROM mails
		WHERE mail IS NOT NULL
		AND mail_file IS NULL
		AND LENGTH(mail) > ?
	`, threshold).Scan(&count, &size)
	return count, size, err
}

// GetStorageStats returns storage statistics for the database
type StorageStats struct {
	BlobCount    int
	BlobSize     int64
	FileCount    int
	FileSize     int64
	TotalCount   int
	TotalSize    int64
	LargestBlob  int64
	LargestFile  int64
}

// GetStorageStats queries the database for storage statistics
func GetStorageStats(db *sql.DB) (*StorageStats, error) {
	stats := &StorageStats{}

	// Get BLOB storage stats
	err := db.QueryRow(`
		SELECT
			COUNT(*),
			IFNULL(SUM(size), 0),
			IFNULL(MAX(size), 0)
		FROM mails
		WHERE mail IS NOT NULL AND mail_file IS NULL
	`).Scan(&stats.BlobCount, &stats.BlobSize, &stats.LargestBlob)
	if err != nil {
		return nil, fmt.Errorf("failed to get BLOB stats: %w", err)
	}

	// Get file storage stats
	err = db.QueryRow(`
		SELECT
			COUNT(*),
			IFNULL(SUM(size), 0),
			IFNULL(MAX(size), 0)
		FROM mails
		WHERE mail_file IS NOT NULL AND mail IS NULL
	`).Scan(&stats.FileCount, &stats.FileSize, &stats.LargestFile)
	if err != nil {
		return nil, fmt.Errorf("failed to get file stats: %w", err)
	}

	stats.TotalCount = stats.BlobCount + stats.FileCount
	stats.TotalSize = stats.BlobSize + stats.FileSize

	return stats, nil
}
