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

	_ "github.com/mattn/go-sqlite3"
	"github.com/JB-SelfCompany/yggmail/internal/storage/filestore"
	"go.uber.org/atomic"
)

type SQLite3Storage struct {
	*TableConfig
	*TableMailboxes
	*TableMails
	*TableQueue
	db     *sql.DB
	writer *Writer
}

func NewSQLite3StorageStorage(filename string) (*SQLite3Storage, error) {
	db, err := sql.Open("sqlite3", "file:"+filename+"?_foreign_keys=on")
	if err != nil {
		return nil, fmt.Errorf("sql.Open: %w", err)
	}

	// Run migrations BEFORE creating prepared statements
	// This ensures that mail_file and size columns exist if restoring from old backup
	if err := RunMigrations(db); err != nil {
		return nil, fmt.Errorf("RunMigrations: %w", err)
	}

	s := &SQLite3Storage{
		db: db,
		writer: &Writer{
			todo: make(chan writerTask),
		},
	}
	s.TableConfig, err = NewTableConfig(db, s.writer)
	if err != nil {
		return nil, fmt.Errorf("NewTableConfig: %w", err)
	}
	s.TableMailboxes, err = NewTableMailboxes(db, s.writer)
	if err != nil {
		return nil, fmt.Errorf("NewTableMailboxes: %w", err)
	}
	s.TableMails, err = NewTableMails(db, s.writer)
	if err != nil {
		return nil, fmt.Errorf("NewTableMails: %w", err)
	}
	s.TableQueue, err = NewTableQueue(db, s.writer)
	if err != nil {
		return nil, fmt.Errorf("NewTableQueue: %w", err)
	}
	return s, nil
}

func (s *SQLite3Storage) Close() error {
	return s.db.Close()
}

type Writer struct {
	running atomic.Bool
	todo    chan writerTask
}

type writerTask struct {
	db   *sql.DB
	txn  *sql.Tx
	f    func(txn *sql.Tx) error
	wait chan error
}

func (w *Writer) Do(db *sql.DB, txn *sql.Tx, f func(txn *sql.Tx) error) error {
	if !w.running.Load() {
		go w.run()
	}
	task := writerTask{
		db:   db,
		txn:  txn,
		f:    f,
		wait: make(chan error, 1),
	}
	w.todo <- task
	return <-task.wait
}

func (w *Writer) run() {
	if !w.running.CompareAndSwap(false, true) {
		return
	}
	defer w.running.Store(false)
	for task := range w.todo {
		if task.db != nil && task.txn != nil {
			task.wait <- task.f(task.txn)
		} else if task.db != nil && task.txn == nil {
			func() {
				txn, err := task.db.Begin()
				if err != nil {
					return
				}
				err = task.f(txn)
				task.wait <- err
				if err == nil {
					_ = txn.Commit()
				} else {
					_ = txn.Rollback()
				}
			}()
		} else {
			task.wait <- task.f(nil)
		}
		close(task.wait)
	}
}

// RunMigrations executes database schema migrations
// This is a wrapper around the standalone RunMigrations function
func (s *SQLite3Storage) RunMigrations() error {
	return RunMigrations(s.db)
}

// MigrateLargeMessagesToFiles migrates large messages from BLOB to file storage
// This is a wrapper around the standalone MigrateLargeMessagesToFiles function
func (s *SQLite3Storage) MigrateLargeMessagesToFiles(fs *filestore.FileStore, threshold int64) error {
	return MigrateLargeMessagesToFiles(s.db, fs, threshold)
}

// GetStorageStatistics returns storage statistics
func (s *SQLite3Storage) GetStorageStatistics() (*StorageStats, error) {
	return GetStorageStats(s.db)
}
