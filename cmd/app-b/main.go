package main

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"strconv"

	"golang.org/x/sync/errgroup"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	failRate, _ := strconv.Atoi(os.Getenv("FAIL_RATE"))

	mux := http.NewServeMux()
	mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
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

		w.Write([]byte("Hello from app-b service! Version: " + os.Getenv("VERSION")))
		fmt.Println("Processed request")
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
