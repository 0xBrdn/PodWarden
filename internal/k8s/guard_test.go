package k8s

import (
	"testing"
	"time"
)

func TestGuardDedup(t *testing.T) {
	g := newGuard(30*time.Second, 0)
	clock := time.Now()
	g.now = func() time.Time { return clock }

	if !g.reserve("prod/a") {
		t.Fatal("first alert must be accepted")
	}
	if g.reserve("prod/a") {
		t.Fatal("duplicate within window must be rejected")
	}
	if !g.reserve("prod/b") {
		t.Fatal("a different pod must be accepted")
	}

	clock = clock.Add(31 * time.Second)
	if !g.reserve("prod/a") {
		t.Fatal("alert after the window must be accepted again")
	}
}

func TestGuardDedupDisabled(t *testing.T) {
	g := newGuard(0, 0)
	if !g.reserve("x") || !g.reserve("x") {
		t.Fatal("window=0 must disable deduplication")
	}
}

func TestGuardRelease(t *testing.T) {
	g := newGuard(time.Minute, 0)
	g.reserve("x")
	g.release("x")
	if !g.reserve("x") {
		t.Fatal("released key must be reservable again")
	}
}

func TestGuardCircuitBreaker(t *testing.T) {
	g := newGuard(0, 2)
	clock := time.Now()
	g.now = func() time.Time { return clock }

	if !g.allowAction() || !g.allowAction() {
		t.Fatal("first two actions must be allowed")
	}
	if g.allowAction() {
		t.Fatal("third action within a minute must be blocked")
	}

	clock = clock.Add(61 * time.Second)
	if !g.allowAction() {
		t.Fatal("budget must be restored after a minute")
	}
}

func TestGuardBreakerDisabled(t *testing.T) {
	g := newGuard(0, 0)
	for i := 0; i < 100; i++ {
		if !g.allowAction() {
			t.Fatal("max=0 must disable the breaker")
		}
	}
}
