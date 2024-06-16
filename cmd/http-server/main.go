package main

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httputil"
	"os"
	"os/signal"
	"strconv"
	"sync/atomic"
	"syscall"

	"golang.org/x/sync/errgroup"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	failRate, _ := strconv.Atoi(os.Getenv("FAIL_RATE"))

	n := uint64(0)
	hostname := os.Getenv("HOSTNAME")
	version := os.Getenv("VERSION")

	var b bytes.Buffer
	b.WriteString("Hello from the http-server service! Hostname: ")
	b.WriteString(hostname)
	b.WriteString(" Version: ")
	b.WriteString(version)

	mux := http.NewServeMux()
	mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		// Dump the request
		dump, err := httputil.DumpRequest(r, true)
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			fmt.Println("Failed to process request")
			return
		}
		fmt.Printf("Request #%d\n", atomic.AddUint64(&n, 1))
		fmt.Println(string(dump))
		fmt.Println("---")

		// Simulate failure
		if failRate > 0 {
			// Get a random number between 0 and 100
			n := rand.Intn(100)
			if n < failRate {
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				fmt.Println("Failed to process request")
				return
			}
		}

		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write(b.Bytes())
	})

	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		<-ctx.Done()
		return server.Shutdown(context.Background())
	})

	g.Go(func() error {
		return server.ListenAndServe()
	})

	if err := g.Wait(); err != nil {
		if err != http.ErrServerClosed {
			panic(err)
		}
	}
}
