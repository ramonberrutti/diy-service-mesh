package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"time"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	httpClient := &http.Client{}

	// This application will call the `app-b` every second
	ticker := time.NewTicker(time.Second)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://app-b.app-b.svc.cluster.local./hello", nil)
			if err != nil {
				panic(err)
			}

			resp, err := httpClient.Do(req)
			if err != nil {
				panic(err)
			}

			body, _ := io.ReadAll(resp.Body)
			fmt.Printf("Response status code: %d, body: %s\n", resp.StatusCode, body)

			resp.Body.Close()
		}
	}
}
