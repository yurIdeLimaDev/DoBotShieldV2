package ratelimit

import (
	"container/list"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

type visitor struct {
	ip          string
	tokens      float64
	lastRefill  time.Time
	activeConns int
	element     *list.Element
	mu          sync.Mutex
}

func (v *visitor) allow(rateLimit float64, burstLimit, maxConns int) (bool, string) {
	v.mu.Lock()
	defer v.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(v.lastRefill).Seconds()
	if elapsed < 0 {
		elapsed = 0
	}
	v.tokens += elapsed * rateLimit
	if v.tokens > float64(burstLimit) {
		v.tokens = float64(burstLimit)
	}
	v.lastRefill = now

	if v.activeConns >= maxConns {
		return false, "Too many concurrent connections"
	}
	if v.tokens >= 1.0 {
		v.tokens -= 1.0
		v.activeConns++
		return true, ""
	}
	return false, "Rate limit exceeded"
}

func (v *visitor) release() {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.activeConns > 0 {
		v.activeConns--
	}
}

type Manager struct {
	mu         sync.Mutex
	visitors   map[string]*visitor
	lru        *list.List
	maxIPs     int
	rateLimit  float64
	burstLimit int
	maxConns   int
}

type stateFile struct {
	Version  int          `json:"version"`
	SavedAt  time.Time    `json:"saved_at"`
	Visitors []stateEntry `json:"visitors"`
}

type stateEntry struct {
	IP             string  `json:"ip"`
	Tokens         float64 `json:"tokens"`
	LastRefillUnix int64   `json:"last_refill_unix_nano"`
}

func NewManager(maxIPs int, rateLimit float64, burstLimit, maxConns int) *Manager {
	if maxIPs <= 0 {
		maxIPs = 10000
	}

	return &Manager{
		visitors:   make(map[string]*visitor),
		lru:        list.New(),
		maxIPs:     maxIPs,
		rateLimit:  rateLimit,
		burstLimit: burstLimit,
		maxConns:   maxConns,
	}
}

func (m *Manager) getVisitor(ip string) (*visitor, bool, string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	v, exists := m.visitors[ip]
	if !exists {
		if len(m.visitors) >= m.maxIPs {
			if !m.evictLeastRecentlyUsed() {
				return nil, false, "Too many tracked IPs"
			}
		}
		v = &visitor{ip: ip, tokens: float64(m.burstLimit), lastRefill: time.Now()}
		v.element = m.lru.PushFront(v)
		m.visitors[ip] = v
		return v, true, ""
	}

	if v.element != nil {
		m.lru.MoveToFront(v.element)
	}
	return v, true, ""
}

func (m *Manager) evictLeastRecentlyUsed() bool {
	for element := m.lru.Back(); element != nil; element = element.Prev() {
		v, ok := element.Value.(*visitor)
		if !ok || v == nil {
			m.lru.Remove(element)
			continue
		}

		v.mu.Lock()
		active := v.activeConns
		v.mu.Unlock()
		if active > 0 {
			continue
		}

		delete(m.visitors, v.ip)
		m.lru.Remove(element)
		v.element = nil
		return true
	}
	return false
}

func (m *Manager) Allow(ip string) (bool, string) {
	v, ok, reason := m.getVisitor(ip)
	if !ok {
		return false, reason
	}
	return v.allow(m.rateLimit, m.burstLimit, m.maxConns)
}

func (m *Manager) Release(ip string) {
	m.mu.Lock()
	v, exists := m.visitors[ip]
	m.mu.Unlock()
	if exists {
		v.release()
	}
}

func (m *Manager) Cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for ip, v := range m.visitors {
		v.mu.Lock()
		idle := now.Sub(v.lastRefill)
		if idle > 5*time.Minute && v.activeConns == 0 {
			delete(m.visitors, ip)
			if v.element != nil {
				m.lru.Remove(v.element)
				v.element = nil
			}
		}
		v.mu.Unlock()
	}
}

func (m *Manager) SaveState(path string) error {
	if path == "" {
		return nil
	}

	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}

	payload, err := json.MarshalIndent(stateFile{
		Version:  1,
		SavedAt:  time.Now().UTC(),
		Visitors: m.snapshot(),
	}, "", "  ")
	if err != nil {
		return err
	}

	temp, err := os.CreateTemp(dir, ".ratelimit-*.tmp")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(0600); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.Write(payload); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}

	if err := os.Rename(tempPath, path); err != nil {
		if runtime.GOOS != "windows" || !os.IsExist(err) {
			return err
		}
		if removeErr := os.Remove(path); removeErr != nil && !os.IsNotExist(removeErr) {
			return removeErr
		}
		if renameErr := os.Rename(tempPath, path); renameErr != nil {
			return renameErr
		}
	}
	return nil
}

func (m *Manager) LoadState(path string) error {
	if path == "" {
		return nil
	}

	payload, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var state stateFile
	if err := json.Unmarshal(payload, &state); err != nil {
		return err
	}
	if state.Version != 1 {
		return fmt.Errorf("unsupported rate-limit state version: %d", state.Version)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.visitors = make(map[string]*visitor)
	m.lru = list.New()

	now := time.Now()
	for _, entry := range state.Visitors {
		if len(m.visitors) >= m.maxIPs {
			break
		}
		if net.ParseIP(entry.IP) == nil {
			continue
		}

		tokens := entry.Tokens
		if tokens < 0 {
			tokens = 0
		}
		if tokens > float64(m.burstLimit) {
			tokens = float64(m.burstLimit)
		}

		lastRefill := time.Unix(0, entry.LastRefillUnix)
		if entry.LastRefillUnix <= 0 || lastRefill.After(now) {
			lastRefill = now
		}
		elapsed := now.Sub(lastRefill).Seconds()
		if elapsed > 0 {
			tokens += elapsed * m.rateLimit
			if tokens > float64(m.burstLimit) {
				tokens = float64(m.burstLimit)
			}
		}

		v := &visitor{
			ip:         entry.IP,
			tokens:     tokens,
			lastRefill: now,
		}
		v.element = m.lru.PushFront(v)
		m.visitors[v.ip] = v
	}

	return nil
}

func (m *Manager) snapshot() []stateEntry {
	m.mu.Lock()
	defer m.mu.Unlock()

	entries := make([]stateEntry, 0, len(m.visitors))
	for _, v := range m.visitors {
		v.mu.Lock()
		entries = append(entries, stateEntry{
			IP:             v.ip,
			Tokens:         v.tokens,
			LastRefillUnix: v.lastRefill.UnixNano(),
		})
		v.mu.Unlock()
	}
	return entries
}
