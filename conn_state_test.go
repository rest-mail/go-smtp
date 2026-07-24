package smtp_test

import (
	"bufio"
	"net"
	"sync"
	"testing"
	"time"

	smtp "github.com/rest-mail/go-smtp"
)

// TestServerConnState verifies the Server.ConnState hook fires StateNew when a
// connection is accepted and StateClosed when it is torn down.
func TestServerConnState(t *testing.T) {
	var mu sync.Mutex
	var states []smtp.ConnState
	record := func(_ net.Conn, st smtp.ConnState) {
		mu.Lock()
		states = append(states, st)
		mu.Unlock()
	}
	snapshot := func() []smtp.ConnState {
		mu.Lock()
		defer mu.Unlock()
		return append([]smtp.ConnState(nil), states...)
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := smtp.NewServer(new(backend))
	s.Domain = "localhost"
	s.ConnState = record
	go s.Serve(l)
	defer s.Close()

	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(c)
	if !scanner.Scan() { // greeting implies the connection was accepted (StateNew)
		t.Fatalf("no greeting: %v", scanner.Err())
	}
	c.Close() // client hangs up → server observes EOF → StateClosed on teardown

	deadline := time.Now().Add(3 * time.Second)
	for {
		got := snapshot()
		if len(got) >= 2 {
			if got[0] != smtp.StateNew {
				t.Errorf("first state = %v, want StateNew", got[0])
			}
			if got[len(got)-1] != smtp.StateClosed {
				t.Errorf("last state = %v, want StateClosed", got[len(got)-1])
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("did not observe StateNew+StateClosed within 3s; got %v", got)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
