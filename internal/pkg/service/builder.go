// builder.go drives the AnyTLS node lifecycle: it owns the sing-anytls
// service, the TLS listener, the four periodic control-plane tasks, and
// the runtime user / traffic / online tables. The transport layer pieces
// live in inboundbuilder.go and handler.go.
package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	api "github.com/GoAsyncFunc/uniproxy/pkg"
	anytls "github.com/anytls/sing-anytls"
	log "github.com/sirupsen/logrus"

	"github.com/GoAsyncFunc/server-anytls/internal/pkg/devlimit"
	"github.com/GoAsyncFunc/server-anytls/internal/pkg/limiter"
	"github.com/GoAsyncFunc/server-anytls/internal/pkg/router"
)

const defaultInboundTag = "anytls-in"

// Config carries CLI-derived runtime settings into the Builder.
type Config struct {
	NodeID                 int
	FetchUsersInterval     time.Duration
	ReportTrafficsInterval time.Duration
	HeartbeatInterval      time.Duration
	CheckNodeInterval      time.Duration
	Cert                   *CertConfig
	AllowPrivateOutbound   bool
}

// CertConfig holds paths to the TLS material loaded for inbound listeners.
type CertConfig struct {
	CertFile string
	KeyFile  string
}

// Builder runs the data plane and the panel control plane for one node.
type Builder struct {
	config    *Config
	nodeInfo  *api.NodeInfo
	apiClient *api.Client

	inboundTag string

	mu       sync.Mutex
	listener net.Listener
	tlsCert  []byte // raw cert bytes for change detection
	tlsKey   []byte
	service  *anytls.Service

	trafficStats *TrafficStats
	online       *OnlineTracker
	router       *router.Router

	userList []api.UserInfo

	fetchUsersMonitorPeriodic      *Periodic
	reportTrafficsMonitorPeriodic  *Periodic
	heartbeatMonitorPeriodic       *Periodic
	checkNodeConfigMonitorPeriodic *Periodic

	ctx    context.Context
	cancel context.CancelFunc
}

// New constructs a Builder. The returned instance is inert until Start.
func New(ctx context.Context, config *Config, nodeInfo *api.NodeInfo, apiClient *api.Client) *Builder {
	ctx, cancel := context.WithCancel(ctx)
	return &Builder{
		config:       config,
		nodeInfo:     nodeInfo,
		apiClient:    apiClient,
		ctx:          ctx,
		cancel:       cancel,
		inboundTag:   defaultInboundTag,
		trafficStats: NewTrafficStats(),
		online:       NewOnlineTracker(),
	}
}

// Start opens the inbound listener, fetches the initial user list, and
// schedules the four periodic control-plane tasks.
func (b *Builder) Start() error {
	if err := b.startInbound(); err != nil {
		return err
	}

	userList, err := b.apiClient.GetUserList(b.ctx)
	if err != nil {
		return err
	}
	b.applyUsers(userList)

	b.fetchUsersMonitorPeriodic = &Periodic{
		Interval: b.config.FetchUsersInterval,
		Execute:  b.fetchUsersMonitor,
	}
	b.reportTrafficsMonitorPeriodic = &Periodic{
		Interval: b.config.ReportTrafficsInterval,
		Execute:  b.reportTrafficsMonitor,
	}

	checkInterval := b.config.CheckNodeInterval
	if checkInterval <= 0 {
		checkInterval = b.config.FetchUsersInterval
	}
	if checkInterval <= 0 {
		checkInterval = time.Minute
	}
	b.checkNodeConfigMonitorPeriodic = &Periodic{
		Interval: checkInterval,
		Execute:  b.checkNodeConfigMonitor,
	}

	log.Infoln("Start monitoring for user acquisition")
	if err := b.fetchUsersMonitorPeriodic.Start(); err != nil {
		return err
	}
	log.Infoln("Start traffic reporting monitoring")
	if err := b.reportTrafficsMonitorPeriodic.Start(); err != nil {
		return err
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

// Close stops every periodic, closes the listener, and cancels the
// context. Idempotent.
func (b *Builder) Close() error {
	b.cancel()
	for _, p := range []*Periodic{
		b.fetchUsersMonitorPeriodic,
		b.reportTrafficsMonitorPeriodic,
		b.checkNodeConfigMonitorPeriodic,
		b.heartbeatMonitorPeriodic,
	} {
		if p != nil {
			p.Close()
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.listener != nil {
		_ = b.listener.Close()
		b.listener = nil
	}
	return nil
}

// applyUsers refreshes the in-memory user table, the sing-anytls service
// password set, and the per-user limiter / device-limit quotas.
func (b *Builder) applyUsers(users []api.UserInfo) {
	b.mu.Lock()
	prev := b.userList
	b.userList = append([]api.UserInfo(nil), users...)
	svc := b.service
	b.mu.Unlock()

	anytlsUsers := BuildUsers(b.inboundTag, users)
	if svc != nil {
		svc.UpdateUsers(anytlsUsers)
	}

	seen := make(map[int]struct{}, len(users))
	for _, u := range users {
		seen[u.Id] = struct{}{}
		limiter.Set(u.Id, u.SpeedLimit)
		devlimit.SetQuota(u.Id, u.DeviceLimit)
	}
	for _, u := range prev {
		if _, ok := seen[u.Id]; !ok {
			limiter.Remove(u.Id)
			devlimit.RemoveUser(u.Id)
		}
	}

	log.Debugf("Applied %d users", len(users))
}

func (b *Builder) fetchUsersMonitor() error {
	users, err := b.apiClient.GetUserList(b.ctx)
	if err != nil {
		log.Errorln(err)
		return nil
	}
	b.applyUsers(users)
	return nil
}

func (b *Builder) reportTrafficsMonitor() error {
	// Snapshot first; only subtract once the panel has accepted the
	// payload. If the request fails or returns an error we keep the
	// counter intact so the next tick retries with cumulative bytes.
	snap := b.trafficStats.Snapshot()
	if len(snap) == 0 {
		return nil
	}
	report := make([]api.UserTraffic, 0, len(snap))
	for uid, s := range snap {
		if uid <= 0 || (s.Tx == 0 && s.Rx == 0) {
			continue
		}
		report = append(report, api.UserTraffic{
			UID:      uid,
			Upload:   int64(s.Tx),
			Download: int64(s.Rx),
		})
	}
	if len(report) == 0 {
		// Filtered everything (e.g. all uid<=0); drain the snapshot so
		// stale zero entries don't accumulate forever.
		b.trafficStats.SubtractSnapshot(snap)
		return nil
	}
	log.Infof("%d user traffic needs to be reported", len(report))
	if err := b.apiClient.ReportUserTraffic(b.ctx, report); err != nil {
		log.Errorln("server error when submitting traffic", err)
		return nil // counters retained for next attempt
	}
	b.trafficStats.SubtractSnapshot(snap)
	return nil
}

func (b *Builder) heartbeatMonitor() error {
	data := b.online.Snapshot()
	if err := b.apiClient.ReportNodeOnlineUsers(b.ctx, data); err != nil {
		log.Errorln("server error when sending heartbeat", err)
	}
	return nil
}

func (b *Builder) checkNodeConfigMonitor() error {
	newNodeInfo, err := b.apiClient.GetNodeInfo(b.ctx)
	if err != nil {
		log.Errorln("Failed to fetch node info:", err)
		return nil
	}
	if newNodeInfo == nil || newNodeInfo.AnyTls == nil {
		return nil
	}
	if !b.nodeChanged(newNodeInfo) {
		return nil
	}

	log.Infoln("Node configuration changed, reloading inbound...")
	if err := b.applyNodeInfoSafely(newNodeInfo, b.startInbound); err != nil {
		// nodeInfo has been rolled back inside applyNodeInfoSafely so the
		// next tick still observes a delta and retries.
		log.Errorf("Failed to restart inbound: %v", err)
	}
	return nil
}

// applyNodeInfoSafely swaps in next, runs start, and reverts to the
// previous nodeInfo on failure. The pre/post check pattern is what keeps
// nodeChanged() honest: a half-applied reload that left b.nodeInfo
// pointing at next would silence further retries because the next panel
// poll would report no delta.
func (b *Builder) applyNodeInfoSafely(next *api.NodeInfo, start func() error) error {
	b.mu.Lock()
	prev := b.nodeInfo
	b.nodeInfo = next
	b.mu.Unlock()

	if err := start(); err != nil {
		b.mu.Lock()
		b.nodeInfo = prev
		b.mu.Unlock()
		return err
	}
	return nil
}

// nodeChanged returns true when any AnyTLS-relevant field, the routes
// hash, or the on-disk cert content has changed since the last successful
// start.
func (b *Builder) nodeChanged(next *api.NodeInfo) bool {
	b.mu.Lock()
	cur := b.nodeInfo
	curCert, curKey := b.tlsCert, b.tlsKey
	b.mu.Unlock()
	if cur == nil || cur.AnyTls == nil {
		return true
	}
	if cur.AnyTls.ServerPort != next.AnyTls.ServerPort {
		return true
	}
	if cur.AnyTls.ServerName != next.AnyTls.ServerName {
		return true
	}
	if !equalStringSlice(cur.AnyTls.PaddingScheme, next.AnyTls.PaddingScheme) {
		return true
	}
	if routesHash(cur.Routes) != routesHash(next.Routes) {
		return true
	}
	if b.config.Cert != nil {
		newCert, newKey := readCertFiles(b.config.Cert.CertFile, b.config.Cert.KeyFile)
		if !bytesEqual(curCert, newCert) || !bytesEqual(curKey, newKey) {
			return true
		}
	}
	return false
}

func equalStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func routesHash(routes []api.Route) string {
	if len(routes) == 0 {
		return ""
	}
	buf, err := json.Marshal(routes)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(buf)
	return hex.EncodeToString(sum[:])
}

// readCertFiles reads cert and key from disk; missing files yield nil
// without an error so callers can decide whether to surface the issue.
func readCertFiles(cert, key string) (certBuf, keyBuf []byte) {
	if cert != "" {
		if c, err := os.ReadFile(cert); err == nil {
			certBuf = c
		}
	}
	if key != "" {
		if k, err := os.ReadFile(key); err == nil {
			keyBuf = k
		}
	}
	return certBuf, keyBuf
}

// trimPaddingScheme returns the v2board padding scheme as a single newline
// joined byte slice, ready for sing-anytls/padding.UpdatePaddingScheme.
func trimPaddingScheme(scheme []string) []byte {
	if len(scheme) == 0 {
		return nil
	}
	return []byte(strings.Join(scheme, "\n"))
}

// formatListenAddr renders the v2board AnyTLS listen port as a TCP bind
// string. Centralised so tests can override host injection if needed.
func formatListenAddr(port int) string {
	return fmt.Sprintf(":%d", port)
}
