package smtp_test

import (
	"sync"
	"testing"

	"github.com/rest-mail/go-smtp"
)

// TestServerCloseConcurrent verifies that concurrent calls to Server.Close do
// not race on the internal done channel (previously two callers could both
// close it, panicking with "close of closed channel"). Exactly one caller
// should perform the shutdown; every other caller must observe ErrServerClosed.
func TestServerCloseConcurrent(t *testing.T) {
	const iterations = 200
	const closers = 8

	for i := 0; i < iterations; i++ {
		s := smtp.NewServer(new(backend))

		var wg sync.WaitGroup
		start := make(chan struct{})
		results := make([]error, closers)

		for j := 0; j < closers; j++ {
			wg.Add(1)
			go func(j int) {
				defer wg.Done()
				<-start
				results[j] = s.Close()
			}(j)
		}

		close(start) // release all closers simultaneously
		wg.Wait()

		nonClosed := 0
		for _, err := range results {
			if err != smtp.ErrServerClosed {
				nonClosed++
			}
		}
		if nonClosed != 1 {
			t.Fatalf("iteration %d: expected exactly one non-ErrServerClosed result, got %d", i, nonClosed)
		}
	}
}
