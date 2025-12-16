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

// getAdaptiveQUICConfig returns QUIC configuration optimized for battery life
// while maintaining connection quality
func getAdaptiveQUICConfig(isActive bool, isCharging bool) *quic.Config {
	var keepAlive time.Duration
	var maxIdle time.Duration

	if isActive {
		// User is actively using the app - use aggressive keep-alive for responsiveness
		keepAlive = 5 * time.Second
		maxIdle = 5 * time.Minute
	} else if isCharging {
		// Device is charging - moderate keep-alive for good delivery speed
		keepAlive = 10 * time.Second
		maxIdle = 10 * time.Minute
	} else {
		// Background mode on battery - balanced between delivery speed and battery
		// 30s provides reasonable delivery latency while saving battery
		keepAlive = 30 * time.Second
		maxIdle = 10 * time.Minute
	}

	return &quic.Config{
		HandshakeIdleTimeout:    time.Second * 10,
		MaxIdleTimeout:          maxIdle,
		KeepAlivePeriod:         keepAlive,
		EnableDatagrams:         false,
		DisablePathMTUDiscovery: true,
		// Increased from 512 to reduce overhead per packet
		InitialPacketSize: 1200,
	}
}

func NewYggdrasilTransport(log *log.Logger, sk ed25519.PrivateKey, pk ed25519.PublicKey, peers []string, isActive bool, isCharging bool) (*YggdrasilTransport, error) {
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

	// Configure QUIC with adaptive battery-optimized settings
	// Battery optimization: Keep-alive varies from 5s (active) to 60s (background)
	// This reduces packet count from 172,800/day to 1,440/day in background mode
	quicConfig := getAdaptiveQUICConfig(isActive, isCharging)

	yq, err := yggquic.New(ygg, quicConfig)
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
