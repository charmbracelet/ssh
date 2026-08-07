package ssh

import (
	"net"
	"sync"
	"testing"
	"time"
)

// handleConn clears the handshake deadline once gossh.NewServerConn returns, by
// which point the crypto/ssh read loop is already running and consulting that
// same deadline through updateDeadline on every Read. Reproduce that access
// pattern directly: without the mutex guarding handshakeDeadline, -race reports
// it on every run.
func TestHandshakeDeadlineConcurrentWithUpdate(t *testing.T) {
	t.Parallel()

	_, server := net.Pipe()
	defer server.Close() //nolint:errcheck

	c := &serverConn{Conn: server, idleTimeout: time.Minute}
	c.setHandshakeDeadline(time.Now().Add(time.Minute))

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 2000 {
				c.updateDeadline()
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		c.clearHandshakeDeadline()
	}()

	wg.Wait()

	// The handshake deadline is gone, so only the idle timeout should bound the
	// connection now.
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.handshakeDeadline.IsZero() {
		t.Errorf("handshakeDeadline = %v; want zero", c.handshakeDeadline)
	}
}
