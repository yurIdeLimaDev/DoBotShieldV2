package ratelimit

import (
	"path/filepath"
	"testing"
	"time"
)

func TestManagerEvictsLeastRecentlyUsedInactiveVisitor(t *testing.T) {
	manager := NewManager(2, 10, 10, 1)

	if allowed, reason := manager.Allow("192.0.2.1"); !allowed {
		t.Fatalf("expected first IP to be allowed: %s", reason)
	}
	manager.Release("192.0.2.1")

	if allowed, reason := manager.Allow("192.0.2.2"); !allowed {
		t.Fatalf("expected second IP to be allowed: %s", reason)
	}
	manager.Release("192.0.2.2")

	if allowed, reason := manager.Allow("192.0.2.3"); !allowed {
		t.Fatalf("expected third IP to be allowed after eviction: %s", reason)
	}
	manager.Release("192.0.2.3")

	if _, exists := manager.visitors["192.0.2.1"]; exists {
		t.Fatalf("expected least recently used IP to be evicted")
	}
}

func TestManagerDoesNotEvictActiveVisitorsForNewIP(t *testing.T) {
	manager := NewManager(1, 10, 10, 1)

	if allowed, reason := manager.Allow("192.0.2.1"); !allowed {
		t.Fatalf("expected first IP to be allowed: %s", reason)
	}

	allowed, reason := manager.Allow("192.0.2.2")
	if allowed {
		t.Fatalf("expected new IP to be blocked while only tracked visitor is active")
	}
	if reason != "Too many tracked IPs" {
		t.Fatalf("unexpected block reason: %q", reason)
	}

	manager.Release("192.0.2.1")
}

func TestManagerPersistsTokenState(t *testing.T) {
	statePath := t.TempDir() + "/ratelimit.json"
	manager := NewManager(10, 1, 2, 1)

	if allowed, reason := manager.Allow("192.0.2.10"); !allowed {
		t.Fatalf("expected request to be allowed: %s", reason)
	}
	manager.Release("192.0.2.10")
	if allowed, reason := manager.Allow("192.0.2.10"); !allowed {
		t.Fatalf("expected second request to be allowed: %s", reason)
	}
	manager.Release("192.0.2.10")

	if err := manager.SaveState(statePath); err != nil {
		t.Fatalf("unexpected save error: %v", err)
	}

	restored := NewManager(10, 1, 2, 1)
	if err := restored.LoadState(statePath); err != nil {
		t.Fatalf("unexpected load error: %v", err)
	}

	allowed, reason := restored.Allow("192.0.2.10")
	if allowed {
		t.Fatalf("expected restored token state to throttle immediately")
	}
	if reason != "Rate limit exceeded" {
		t.Fatalf("unexpected block reason: %q", reason)
	}
}

func TestCleanupKeepsActiveVisitors(t *testing.T) {
	manager := NewManager(10, 10, 10, 1)
	if allowed, reason := manager.Allow("192.0.2.40"); !allowed {
		t.Fatalf("expected request to be allowed: %s", reason)
	}
	manager.visitors["192.0.2.40"].lastRefill = time.Now().Add(-time.Hour)

	manager.Cleanup()
	if _, exists := manager.visitors["192.0.2.40"]; !exists {
		t.Fatal("active visitor must not be removed during cleanup")
	}
	manager.Release("192.0.2.40")
}

func TestSaveStateCanReplaceExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	manager := NewManager(10, 10, 10, 1)
	if err := manager.SaveState(path); err != nil {
		t.Fatalf("first save failed: %v", err)
	}
	if err := manager.SaveState(path); err != nil {
		t.Fatalf("replacement save failed: %v", err)
	}
}
