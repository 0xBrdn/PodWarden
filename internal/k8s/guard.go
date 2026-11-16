package k8s

import (
	"sync"
	"time"
)

// guard protects the cluster from PodWarden itself:
//   - reserve() deduplicates alert bursts for the same pod;
//   - allowAction() is a circuit breaker capping destructive actions per minute,
//     so a noisy rule or a flood of false positives cannot wipe a namespace.
type guard struct {
	mu      sync.Mutex
	window  time.Duration
	max     int
	seen    map[string]time.Time
	actions []time.Time
	now     func() time.Time
}

func newGuard(window time.Duration, maxPerMinute int) *guard {
	return &guard{
		window: window,
		max:    maxPerMinute,
		seen:   make(map[string]time.Time),
		now:    time.Now,
	}
}

// reserve returns false when the key was already seen within the window.
func (g *guard) reserve(key string) bool {
	if g.window <= 0 {
		return true
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	now := g.now()
	for k, t := range g.seen {
		if now.Sub(t) >= g.window {
			delete(g.seen, k)
		}
	}
	if _, dup := g.seen[key]; dup {
		return false
	}
	g.seen[key] = now
	return true
}

// release forgets a reservation (used when processing failed before any action).
func (g *guard) release(key string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.seen, key)
}

// allowAction returns true if one more destructive action fits in the budget.
func (g *guard) allowAction() bool {
	if g.max <= 0 {
		return true
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	now := g.now()
	cutoff := now.Add(-time.Minute)
	kept := g.actions[:0]
	for _, t := range g.actions {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	g.actions = kept

	if len(g.actions) >= g.max {
		return false
	}
	g.actions = append(g.actions, now)
	return true
}
