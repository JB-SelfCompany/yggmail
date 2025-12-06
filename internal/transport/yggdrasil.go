/*
 *  Copyright (c) 2021 Neil Alexander
 *
 *  This Source Code Form is subject to the terms of the Mozilla Public
 *  License, v. 2.0. If a copy of the MPL was not distributed with this
 *  file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package transport

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/fatih/color"
	gologme "github.com/gologme/log"
	"github.com/quic-go/quic-go"
	"github.com/yggdrasil-network/yggdrasil-go/src/config"
	"github.com/yggdrasil-network/yggdrasil-go/src/core"
	"github.com/yggdrasil-network/yggquic"
)

type YggdrasilTransport struct {
	yggquic *yggquic.YggdrasilTransport
	core    *core.Core
}

func NewYggdrasilTransport(log *log.Logger, sk ed25519.PrivateKey, pk ed25519.PublicKey, peers []string) (*YggdrasilTransport, error) {
	yellow := color.New(color.FgYellow).SprintfFunc()
	glog := gologme.New(log.Writer(), fmt.Sprintf("[ %s ] ", yellow("Yggdrasil")), gologme.LstdFlags|gologme.Lmsgprefix)
	glog.EnableLevel("warn")
	glog.EnableLevel("error")
	glog.EnableLevel("info")

	cfg := config.GenerateConfig()
	copy(cfg.PrivateKey, sk)
	if err := cfg.GenerateSelfSignedCertificate(); err != nil {
		return nil, err
	}

	var ygg *core.Core
	var err error

	// Setup the Yggdrasil node itself.
	{
		options := []core.SetupOption{
			core.NodeInfo(map[string]interface{}{
				"name": hex.EncodeToString(pk) + "@yggmail",
			}),
			core.NodeInfoPrivacy(true),
		}
		for _, peer := range peers {
			options = append(options, core.Peer{URI: peer})
		}
		if ygg, err = core.New(cfg.Certificate, glog, options...); err != nil {
			panic(err)
		}
	}

	// Configure QUIC with mobile-optimized settings optimized for low latency
	// CRITICAL: KeepAlivePeriod must be set to keep connections alive and responsive
	// Without it, the remote peer won't accept incoming streams until we initiate new activity
	quicConfig := &quic.Config{
		HandshakeIdleTimeout:    time.Second * 10,       // 10s handshake
		MaxIdleTimeout:          time.Minute * 5,        // 5min idle timeout
		KeepAlivePeriod:         time.Millisecond * 500, // 500ms VERY AGGRESSIVE - keeps connection responsive
		EnableDatagrams:         false,                  // Disable for better reliability
		DisablePathMTUDiscovery: true,                   // Critical for Yggdrasil overlay
		// Use smaller packet size to force more frequent sends and reduce buffering
		InitialPacketSize: 512, // Small packets = less buffering delay
	}

	yq, err := yggquic.New(ygg, *cfg.Certificate, quicConfig, 300)
	if err != nil {
		panic(err)
	}

	return &YggdrasilTransport{
		yggquic: yq,
		core:    ygg,
	}, nil
}

func (t *YggdrasilTransport) Dial(host string) (net.Conn, error) {
	c, err := t.yggquic.Dial("yggdrasil", host)
	if err != nil {
		return nil, err
	}
	// Needed to kick the stream so the other side "speaks first"
	// This is critical for SMTP protocol where server must send greeting first
	_, err = c.Write([]byte(" "))
	if err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

func (t *YggdrasilTransport) Listener() net.Listener {
	return t.yggquic
}

// GetCore returns the underlying Yggdrasil core for peer management
func (t *YggdrasilTransport) GetCore() *core.Core {
	return t.core
}

// GetPeers returns information about all connected peers
func (t *YggdrasilTransport) GetPeers() []core.PeerInfo {
	if t.core == nil {
		return nil
	}
	return t.core.GetPeers()
}
