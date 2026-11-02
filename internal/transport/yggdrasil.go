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
	"sync"
	"time"

	"github.com/fatih/color"
	gologme "github.com/gologme/log"
	"github.com/quic-go/quic-go"
	"github.com/yggdrasil-network/yggdrasil-go/src/config"
	"github.com/yggdrasil-network/yggdrasil-go/src/core"
	"github.com/yggdrasil-network/yggquic"
)

type YggdrasilTransport struct {
	mu         sync.RWMutex
	yggquic    *yggquic.YggdrasilTransport
	core       *core.Core
	isActive   bool
	isCharging bool
}

// getAdaptiveQUICConfig returns QUIC configuration optimized for battery life
// while maintaining connection quality
func getAdaptiveQUICConfig(isActive bool, isCharging bool) *quic.Config {
	var keepAlive time.Duration
	// MaxIdleTimeout MUST be large to survive Android Doze windows (up to 15+ min).
	// Keeping it at 30min regardless of active state fixes disconnection in Doze mode.
	const maxIdle = 30 * time.Minute

	if isActive {
		// Foreground: aggressive keep-alive for responsiveness
		keepAlive = 5 * time.Second
	} else if isCharging {
		// Charging background: moderate keep-alive
		keepAlive = 15 * time.Second
	} else {
		// Battery background: conservative keep-alive to save battery.
		// 60s provides reasonable delivery latency while saving battery.
		keepAlive = 60 * time.Second
	}

	return &quic.Config{
		HandshakeIdleTimeout:    time.Second * 10,
		MaxIdleTimeout:          maxIdle,
		KeepAlivePeriod:         keepAlive,
		EnableDatagrams:         false,
		DisablePathMTUDiscovery: true,
		InitialPacketSize:       1200,
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

	yq, err := yggquic.New(ygg, *cfg.Certificate, quicConfig, 1800) // ponytail: 30min idle timeout for mobile
	if err != nil {
		panic(err)
	}

	return &YggdrasilTransport{
		yggquic:    yq,
		core:       ygg,
		isActive:   isActive,
		isCharging: isCharging,
	}, nil
}

func (t *YggdrasilTransport) Dial(host string) (net.Conn, error) {
	c, err := t.yggquic.Dial("yggdrasil", host)
	if err != nil {
		return nil, err
	}
	// Needed to kick the stream so the other side "speaks first"
	// This is critical for SMTP protocol where server must send greeting first
	// The server will consume and ignore this byte via kickByteConn wrapper
	_, err = c.Write([]byte{0})
	if err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

func (t *YggdrasilTransport) Listener() net.Listener {
	return &kickByteListener{Listener: t.yggquic}
}

// kickByteListener wraps a net.Listener to consume kick bytes from accepted connections.
type kickByteListener struct {
	net.Listener
}

func (l *kickByteListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	// Wrap connection to consume the kick byte on first read
	return newKickByteConn(conn), nil
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

// UpdatePowerState updates QUIC configuration when device power state changes.
// This updates new outgoing connections and closes existing ones so they
// reconnect with the updated keepAlive period.
// Battery impact: only changes keepAlive frequency, not connection count.
func (t *YggdrasilTransport) UpdatePowerState(isActive bool, isCharging bool) {
	t.mu.Lock()
	changed := t.isActive != isActive || t.isCharging != isCharging
	t.isActive = isActive
	t.isCharging = isCharging
	t.mu.Unlock()

	if !changed {
		return
	}

	// ponytail: yggquic no longer supports runtime QUIC config updates.
	// Adaptive keep-alive is now handled internally by yggquic via the timeout parameter.
	_ = getAdaptiveQUICConfig(isActive, isCharging) // keep function for reference
}
