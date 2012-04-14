// Programmer: Chris Bunch
// sieves - a sample app that does some computation in parallel via
// goroutines to test running parallel computation in the Go App Engine SDK
// This is more or less the sieves sample app that is available
// with go but made into an App Engine app

package sieves

import (
	"fmt"
	"http"
	"time"
)

// Send the sequence 2, 3, 4, ... to channel 'ch'.
func generate(ch chan int) {
	for i := 2; ; i++ {
		ch <- i // Send 'i' to channel 'ch'.
	}
}

// Copy the values from channel 'in' to channel 'out',
// removing those divisible by 'prime'.
func filter(in, out chan int, prime int) {
	for {
		i := <-in // Receive value of new variable 'i' from 'in'.
		if i%prime != 0 {
			out <- i // Send 'i' to channel 'out'.
		}
	}
}

func init() {
	http.HandleFunc("/", sieves)
}

const NUM_PRIMES = 1000

// The prime sieve: Daisy-chain filter processes together.
func sieves(w http.ResponseWriter, r *http.Request) {
	start := time.Seconds()
	fmt.Fprintf(w, "the first %v prime numbers are:<br />", NUM_PRIMES)
	ch := make(chan int)              // Create a new channel.
	go generate(ch)                   // Start generate() as a goroutine.
	for i := 0; i < NUM_PRIMES; i++ { // Print the first hundred primes.
		prime := <-ch
		fmt.Fprintf(w, "%v<br />", prime)
		ch1 := make(chan int)
		go filter(ch, ch1, prime)
		ch = ch1
	}
	end := time.Seconds()
	fmt.Fprintf(w, "<br /><br />the computation took %v seconds", end-start)
}
