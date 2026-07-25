package smtp

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// connCapBackend captures the server-side *Conn created for each session so a
// test can reach the connection (e.g. to call Conn.Close) from another
// goroutine.
type connCapBackend struct{ ch chan *Conn }

func (b connCapBackend) NewSession(c *Conn) (Session, error) {
	b.ch <- c
	return nopSession{}, nil
}

// TestStartTLSCloseRace drives a real STARTTLS upgrade to the point where the
// server has completed the TLS handshake and is about to swap c.conn for the
// *tls.Conn, then calls Conn.Close() from another goroutine so the swap races
// the locked read in Close(). Before the fix the swap was written without
// holding c.locker, so `go test -race` reports a data race on c.conn; with the
// swap done under the lock (setConn) the two accesses are serialized.
//
// The upgrade hook parks the connection goroutine at the swap and both that
// goroutine and the Conn.Close() goroutine are released together, so the write
// and the read overlap tightly. The scenario is repeated so a scheduling that
// happens to order them on one round is caught on another.
func TestStartTLSCloseRace(t *testing.T) {
	cert, err := tls.X509KeyPair(localhostCert, localhostKey)
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	connCh := make(chan *Conn, 1)
	s := NewServer(connCapBackend{ch: connCh})
	s.Domain = "localhost"
	s.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
	go s.Serve(ln)  //nolint:errcheck // Serve returns on s.Close()
	defer s.Close() //nolint:errcheck // best-effort cleanup

	// atSwap/release are re-created per round; the hook reads the current pair
	// under swapMu so it always sees a consistent set.
	var swapMu sync.Mutex
	var atSwap, release chan struct{}
	testHookStartTLSUpgrade = func() {
		swapMu.Lock()
		as, rel := atSwap, release
		swapMu.Unlock()
		close(as)
		<-rel
	}
	defer func() { testHookStartTLSUpgrade = nil }()

	for i := 0; i < 50; i++ {
		swapMu.Lock()
		atSwap, release = make(chan struct{}), make(chan struct{})
		as, rel := atSwap, release
		swapMu.Unlock()

		startTLSCloseRound(t, ln.Addr().String(), connCh, as, rel)
	}
}

// startTLSCloseRound performs one connection: it upgrades via STARTTLS up to the
// parked swap, then releases the swap and Conn.Close() together.
func startTLSCloseRound(t *testing.T, addr string, connCh chan *Conn, atSwap, release chan struct{}) {
	t.Helper()

	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close() //nolint:errcheck // best-effort cleanup
	br := bufio.NewReader(raw)

	readLine := func() string {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		return line
	}

	_ = readLine() // greeting
	if _, err := io.WriteString(raw, "EHLO localhost\r\n"); err != nil {
		t.Fatal(err)
	}
	for !strings.HasPrefix(readLine(), "250 ") {
	}
	if _, err := io.WriteString(raw, "STARTTLS\r\n"); err != nil {
		t.Fatal(err)
	}
	if line := readLine(); !strings.HasPrefix(line, "220 ") {
		t.Fatalf("expected 220 ready to start TLS, got %q", line)
	}
	// The server blocks reading the ClientHello after the 220, so no TLS bytes
	// are buffered past it and the raw conn is safe to hand to the TLS client.
	if n := br.Buffered(); n != 0 {
		t.Fatalf("unexpected %d buffered bytes after 220", n)
	}

	// Complete the client side of the handshake so the server reaches the swap.
	hsDone := make(chan struct{})
	go func() {
		defer close(hsDone)
		tc := tls.Client(raw, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test-only client
		_ = tc.Handshake()
	}()

	var serverConn *Conn
	select {
	case serverConn = <-connCh:
	case <-time.After(5 * time.Second):
		t.Fatal("server never created a session Conn")
	}

	select {
	case <-atSwap:
	case <-time.After(5 * time.Second):
		t.Fatal("server never reached the STARTTLS swap")
	}

	// Park a Conn.Close() on the same release, then free the swap and the close
	// together: on the unfixed code the unlocked c.conn write races Close()'s
	// locked read of c.conn.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-release
		_ = serverConn.Close()
	}()
	close(release)
	wg.Wait()

	<-hsDone
}
