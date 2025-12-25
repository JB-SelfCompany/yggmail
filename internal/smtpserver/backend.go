/*
 *  Copyright (c) 2021 Neil Alexander
 *
 *  This Source Code Form is subject to the terms of the Mozilla Public
 *  License, v. 2.0. If a copy of the MPL was not distributed with this
 *  file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package smtpserver

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/emersion/go-smtp"
	"github.com/JB-SelfCompany/yggmail/internal/config"
	"github.com/JB-SelfCompany/yggmail/internal/imapserver"
	"github.com/JB-SelfCompany/yggmail/internal/logging"
	"github.com/JB-SelfCompany/yggmail/internal/smtpsender"
	"github.com/JB-SelfCompany/yggmail/internal/storage"
	"github.com/JB-SelfCompany/yggmail/internal/storage/filestore"
	"github.com/JB-SelfCompany/yggmail/internal/utils"
)

type BackendMode int

const (
	BackendModeInternal BackendMode = iota
	BackendModeExternal
)

type Backend struct {
	Mode            BackendMode
	Log             *log.Logger
	Config          *config.Config
	Queues          *smtpsender.Queues
	Storage         storage.Storage
	Notify          *imapserver.IMAPNotify
	MailCallback    MailCallback
	FileStore       *filestore.FileStore
	LargeMailLogger *logging.LargeMailLogger
}

// MailCallback interface for mail event notifications
type MailCallback interface {
	OnNewMail(from string, mailID int)
}

func (b *Backend) Login(state *smtp.ConnectionState, username, password string) (smtp.Session, error) {
	switch b.Mode {
	case BackendModeInternal:
		// If our username is email-like, then take just the localpart
		if pk, err := utils.ParseAddress(username); err == nil {
			if !pk.Equal(b.Config.PublicKey) {
				return nil, fmt.Errorf("failed to authenticate: wrong domain in username")
			}
		}
		username = hex.EncodeToString(b.Config.PublicKey)
		// The connection came from our local listener
		if authed, err := b.Storage.ConfigTryPassword(password); err != nil {
			b.Log.Printf("Failed to authenticate SMTP user %q due to error: %s", username, err)
			return nil, fmt.Errorf("failed to authenticate: %w", err)
		} else if !authed {
			b.Log.Printf("Failed to authenticate SMTP user %q\n", username)
			return nil, smtp.ErrAuthRequired
		}
		remoteAddr := "unknown"
		if state != nil && state.RemoteAddr != nil {
			remoteAddr = state.RemoteAddr.String()
		}
		defer b.Log.Printf("Authenticated SMTP user from %s as %q\n", remoteAddr, username)
		return &SessionLocal{
			backend: b,
			state:   state,
		}, nil

	case BackendModeExternal:
		return nil, fmt.Errorf("not expecting authenticated connection on external backend")
	}

	return nil, fmt.Errorf("authenticated login failed")
}

func (b *Backend) AnonymousLogin(state *smtp.ConnectionState) (smtp.Session, error) {
	switch b.Mode {
	case BackendModeInternal:
		return nil, fmt.Errorf("not expecting anonymous connection on internal backend")

	case BackendModeExternal:
		// The connection came from our overlay listener, so we should check
		// that they are who they claim to be
		if state == nil || state.RemoteAddr == nil {
			return nil, fmt.Errorf("invalid connection state")
		}
		pks, err := hex.DecodeString(state.RemoteAddr.String())
		if err != nil {
			return nil, fmt.Errorf("hex.DecodeString: %w", err)
		}
		remote := hex.EncodeToString(pks)
		if state.Hostname != remote {
			return nil, fmt.Errorf("you are not who you claim to be")
		}

		b.Log.Printf("Incoming SMTP session from %s (server state: %+v)", remote, state)
		return &SessionRemote{
			backend: b,
			state:   state,
			public:  pks[:],
		}, nil
	}

	return nil, fmt.Errorf("anonymous login failed")
}
