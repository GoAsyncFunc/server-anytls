package service

import (
	"context"
	"fmt"
	"sync"
	"time"

	"net"

	api "github.com/GoAsyncFunc/uniproxy/pkg"
	log "github.com/sirupsen/logrus"
)

type Config struct {
	NodeID                 int
	FetchUsersInterval     time.Duration
	ReportTrafficsInterval time.Duration
	HeartbeatInterval      time.Duration
	Cert                   *CertConfig
}

type CertConfig struct {
	CertFile string
	KeyFile  string
}

type Builder struct {
	config    *Config
	nodeInfo  *api.NodeInfo
	apiClient *api.Client

	// Traffic Stats
	trafficStats *TrafficStats

	// Users
	userList []api.UserInfo

	mu sync.Mutex

	fetchUsersMonitorPeriodic      *Periodic
	reportTrafficsMonitorPeriodic  *Periodic
	heartbeatMonitorPeriodic       *Periodic
	checkNodeConfigMonitorPeriodic *Periodic

	ctx    context.Context
	cancel context.CancelFunc

	listener net.Listener
}

// Simple Periodic task wrapper
type Periodic struct {
	Interval time.Duration
	Execute  func() error
	stop     chan struct{}
}

func (p *Periodic) Start() error {
	p.stop = make(chan struct{})
	go func() {
		ticker := time.NewTicker(p.Interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := p.Execute(); err != nil {
					log.Errorf("Periodic task error: %v", err)
				}
			case <-p.stop:
				return
			}
		}
	}()
	return nil
}

func (p *Periodic) Close() {
	if p.stop != nil {
		close(p.stop)
	}
}

func New(ctx context.Context, config *Config, nodeInfo *api.NodeInfo, apiClient *api.Client) *Builder {
	ctx, cancel := context.WithCancel(ctx)
	return &Builder{
		config:       config,
		nodeInfo:     nodeInfo,
		apiClient:    apiClient,
		ctx:          ctx,
		cancel:       cancel,
		trafficStats: NewTrafficStats(),
	}
}

func (b *Builder) Start() error {
	if err := b.startAnyTls(); err != nil {
		return err
	}

	// Initial user fetch
	userList, err := b.apiClient.GetUserList(b.ctx)
	if err != nil {
		return err
	}
	b.updateUsers(userList)
	b.userList = userList

	b.fetchUsersMonitorPeriodic = &Periodic{
		Interval: b.config.FetchUsersInterval,
		Execute:  b.fetchUsersMonitor,
	}
	b.reportTrafficsMonitorPeriodic = &Periodic{
		Interval: b.config.ReportTrafficsInterval,
		Execute:  b.reportTrafficsMonitor,
	}

	log.Infoln("Start monitoring for user acquisition")
	if err := b.fetchUsersMonitorPeriodic.Start(); err != nil {
		return err
	}

	log.Infoln("Start traffic reporting monitoring")
	if err := b.reportTrafficsMonitorPeriodic.Start(); err != nil {
		return err
	}

	// Use same interval as fetch users for node config check, or 60s default
	checkInterval := b.config.FetchUsersInterval
	if checkInterval == 0 {
		checkInterval = time.Minute
	}
	b.checkNodeConfigMonitorPeriodic = &Periodic{
		Interval: checkInterval,
		Execute:  b.checkNodeConfigMonitor,
	}
	log.Infoln("Start node config monitoring")
	if err := b.checkNodeConfigMonitorPeriodic.Start(); err != nil {
		return err
	}

	if b.config.HeartbeatInterval > 0 {
		b.heartbeatMonitorPeriodic = &Periodic{
			Interval: b.config.HeartbeatInterval,
			Execute:  b.heartbeatMonitor,
		}
		log.Infoln("Start heartbeat monitoring")
		if err := b.heartbeatMonitorPeriodic.Start(); err != nil {
			return err
		}
	}

	return nil
}

func (b *Builder) startAnyTls() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.startAnyTlsInternal()
}

func (b *Builder) startAnyTlsInternal() error {
	if b.listener != nil {
		b.listener.Close()
		b.listener = nil
	}

	anyTlsInfo := b.nodeInfo.AnyTls
	if anyTlsInfo == nil {
		return fmt.Errorf("node info missing AnyTLS config")
	}

	listenAddr := fmt.Sprintf(":%d", anyTlsInfo.ServerPort)
	log.Infof("Starting AnyTLS server on %s", listenAddr)

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen TCP: %w", err)
	}
	b.listener = ln

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				if b.ctx.Err() != nil {
					return
				}
				log.Debugf("Accept stopping: %v", err)
				return
			}
			go b.handleConnection(conn)
		}
	}()

	return nil
}

func (b *Builder) handleConnection(conn net.Conn) {
	defer conn.Close()
	// TODO: Implement AnyTLS specific handshake or forwarding logic here.
	// Currently just a TCP listener.
	// We can add ShadowTLS handshake logic if the library becomes available.

	// Example: Log connection
	// log.Debugf("New connection from %s", conn.RemoteAddr())
}

func (b *Builder) Close() error {
	b.cancel()
	if b.fetchUsersMonitorPeriodic != nil {
		b.fetchUsersMonitorPeriodic.Close()
	}
	if b.reportTrafficsMonitorPeriodic != nil {
		b.reportTrafficsMonitorPeriodic.Close()
	}
	if b.checkNodeConfigMonitorPeriodic != nil {
		b.checkNodeConfigMonitorPeriodic.Close()
	}
	if b.heartbeatMonitorPeriodic != nil {
		b.heartbeatMonitorPeriodic.Close()
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.listener != nil {
		b.listener.Close()
		b.listener = nil
	}
	return nil
}

func (b *Builder) fetchUsersMonitor() error {
	newUserList, err := b.apiClient.GetUserList(b.ctx)
	if err != nil {
		log.Errorln(err)
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.updateUsers(newUserList)
	b.userList = newUserList
	return nil
}

func (b *Builder) reportTrafficsMonitor() error {
	stats := b.trafficStats.GetAndReset()
	if len(stats) == 0 {
		return nil
	}

	userTraffic := make([]api.UserTraffic, 0, len(stats))
	for uidStr, s := range stats {
		var uid int
		fmt.Sscanf(uidStr, "%d", &uid)
		if uid > 0 && (s.Tx > 0 || s.Rx > 0) {
			userTraffic = append(userTraffic, api.UserTraffic{
				UID:      uid,
				Upload:   int64(s.Tx),
				Download: int64(s.Rx),
			})
		}
	}

	if len(userTraffic) > 0 {
		log.Infof("%d user traffic needs to be reported", len(userTraffic))
		err := b.apiClient.ReportUserTraffic(b.ctx, userTraffic)
		if err != nil {
			log.Errorln("server error when submitting traffic", err)
			return nil
		}
	}
	return nil
}

func (b *Builder) updateUsers(users []api.UserInfo) {
	// Update users in service
	log.Debugf("Updated %d users", len(users))
}

// TrafficStats

func (b *Builder) checkNodeConfigMonitor() error {
	newNodeInfo, err := b.apiClient.GetNodeInfo(b.ctx)
	if err != nil {
		log.Errorln("Failed to fetch node info:", err)
		return nil
	}
	if newNodeInfo == nil || newNodeInfo.AnyTls == nil {
		return nil
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	// Check for changes
	if b.nodeInfo != nil && b.nodeInfo.AnyTls != nil {
		if b.nodeInfo.AnyTls.ServerPort == newNodeInfo.AnyTls.ServerPort {
			// Add more checks if AnyTls has more fields
			return nil // No change
		}
	}

	log.Infoln("Node configuration changed, reloading AnyTLS server...")
	b.nodeInfo = newNodeInfo

	if err := b.startAnyTlsInternal(); err != nil {
		log.Errorf("Failed to restart AnyTLS server: %v", err)
	}

	return nil
}

func (b *Builder) heartbeatMonitor() error {
	data := make(map[int][]string)
	err := b.apiClient.ReportNodeOnlineUsers(b.ctx, data)
	if err != nil {
		log.Errorln("server error when sending heartbeat", err)
	}
	return nil
}

type TrafficStats struct {
	stats map[string]*ConnStats // auth_id (uid as string) -> stats
	mu    sync.Mutex
}

type ConnStats struct {
	Tx uint64
	Rx uint64
}

func NewTrafficStats() *TrafficStats {
	return &TrafficStats{
		stats: make(map[string]*ConnStats),
	}
}

func (s *TrafficStats) LogTraffic(id string, tx, rx uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.stats[id]; !ok {
		s.stats[id] = &ConnStats{}
	}
	s.stats[id].Tx += tx
	s.stats[id].Rx += rx
	return true
}

func (s *TrafficStats) GetAndReset() map[string]*ConnStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.stats
	s.stats = make(map[string]*ConnStats)
	return r
}
