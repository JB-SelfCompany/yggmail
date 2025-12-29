/*
 *  Copyright (c) 2021 Neil Alexander
 *
 *  This Source Code Form is subject to the terms of the Mozilla Public
 *  License, v. 2.0. If a copy of the MPL was not distributed with this
 *  file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package sqlite3

import (
	"database/sql"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

type TableConfig struct {
	db     *sql.DB
	writer *Writer
	get    *sql.Stmt
	set    *sql.Stmt
}

const configSchema = `
	CREATE TABLE IF NOT EXISTS config (
		key 		TEXT NOT NULL,
		value 		TEXT NOT NULL,
		PRIMARY KEY(key)
	);
`

const configGet = `
	SELECT value FROM config WHERE key = $1
`

const configSet = `
	INSERT OR REPLACE INTO config (key, value) VALUES($1, $2)
`

func NewTableConfig(db *sql.DB, writer *Writer) (*TableConfig, error) {
	t := &TableConfig{
		db:     db,
		writer: writer,
	}
	_, err := db.Exec(configSchema)
	if err != nil {
		return nil, fmt.Errorf("db.Exec: %w", err)
	}
	t.get, err = db.Prepare(configGet)
	if err != nil {
		return nil, fmt.Errorf("db.Prepare(get): %w", err)
	}
	t.set, err = db.Prepare(configSet)
	if err != nil {
		return nil, fmt.Errorf("db.Prepare(set): %w", err)
	}
	return t, nil
}

func (t *TableConfig) ConfigGet(key string) (string, error) {
	var value string
	err := t.get.QueryRow(key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return value, err
}

func (t *TableConfig) ConfigSet(key, value string) error {
	return t.writer.Do(t.db, nil, func(txn *sql.Tx) error {
		_, err := t.set.Exec(key, value)
		return err
	})
}

func (t *TableConfig) ConfigSetPassword(passwordHash string) error {
	return t.ConfigSet("password", passwordHash)
}

func (t *TableConfig) ConfigTryPassword(password string) (bool, error) {
	dbPasswordHash, err := t.ConfigGet("password")
	if err != nil {
		return false, err
	}
	if dbPasswordHash == "" {
		return true, nil // TODO: Do we want to allow login if no password is set?
	}
	err = bcrypt.CompareHashAndPassword([]byte(dbPasswordHash), []byte(password))
	if err == nil {
		return true, nil
	}
	return false, err
}

// ConfigGetMaxMessageSize returns the maximum message size in bytes
// Returns default of 10 MB if not set
func (t *TableConfig) ConfigGetMaxMessageSize() (int64, error) {
	value, err := t.ConfigGet("max_message_size_bytes")
	if err != nil {
		return 0, fmt.Errorf("failed to get max message size: %w", err)
	}
	if value == "" {
		// Default: 10 MB
		return 10 * 1024 * 1024, nil
	}

	var maxSize int64
	if _, err := fmt.Sscanf(value, "%d", &maxSize); err != nil {
		return 0, fmt.Errorf("failed to parse max message size value: %w", err)
	}
	return maxSize, nil
}

// ConfigSetMaxMessageSize sets the maximum message size in bytes
func (t *TableConfig) ConfigSetMaxMessageSize(bytes int64) error {
	if bytes < 0 {
		return fmt.Errorf("max message size cannot be negative")
	}
	value := fmt.Sprintf("%d", bytes)
	return t.ConfigSet("max_message_size_bytes", value)
}
