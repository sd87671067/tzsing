package policy

import (
	"io"
	"net"
	"os"
	"sync"
	"time"
)

var once sync.Once
var runtimeLedger *Ledger
var runtimeErr error

// Runtime is opt-in for a dedicated sing-box service only. Probe instances and
// installations without this environment retain their original behavior.
func Runtime() (*Ledger, error) {
	once.Do(func() {
		if p := os.Getenv("TZSING_POLICY_DB"); p != "" {
			runtimeLedger, runtimeErr = Open(p)
			if runtimeErr == nil {
				runtimeLedger.Heartbeat()
				go func() {
					for range time.Tick(time.Second) {
						runtimeLedger.Heartbeat()
					}
				}()
			}
		}
	})
	return runtimeLedger, runtimeErr
}
func Admit(in, user string, n int64) error {
	l, e := Runtime()
	if e != nil {
		return e
	}
	if l == nil || user == "" {
		return nil
	}
	return l.Charge(in, user, n)
}

type meteredConn struct {
	net.Conn
	in, user string
}

// No Upstream or replaceable-reader hooks: optimized copies must pass this gate.
func Wrap(conn net.Conn, in, user string) net.Conn {
	if os.Getenv("TZSING_POLICY_DB") == "" || user == "" {
		return conn
	}
	c := &meteredConn{conn, in, user}
	if Admit(in, user, 0) != nil {
		conn.Close()
	}
	return c
}
func (c *meteredConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	l, e := Runtime()
	if e != nil {
		return 0, e
	}
	if l == nil {
		return c.Conn.Read(b)
	}
	r, e := l.Reserve(c.in, c.user, "upload", int64(min(len(b), 32<<10)))
	if e != nil {
		return 0, e
	}
	n, e := c.Conn.Read(b[:r.Amount])
	if x := l.Settle(r.Token, int64(n)); x != nil {
		c.Conn.Close()
		return 0, x
	}
	return n, e
}
func (c *meteredConn) Write(b []byte) (int, error) {
	total := 0
	for len(b) > 0 {
		l, e := Runtime()
		if e != nil {
			return total, e
		}
		if l == nil {
			n, e := c.Conn.Write(b)
			return total + n, e
		}
		r, e := l.Reserve(c.in, c.user, "download", int64(min(len(b), 32<<10)))
		if e != nil {
			return total, e
		}
		n, e := c.Conn.Write(b[:r.Amount])
		if x := l.Settle(r.Token, int64(n)); x != nil {
			c.Conn.Close()
			return total + n, x
		}
		total += n
		if e != nil {
			return total, e
		}
		if int64(n) != r.Amount {
			return total, io.ErrShortWrite
		}
		b = b[n:]
	}
	return total, nil
}
