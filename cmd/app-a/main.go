package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httputil"
	"os"
	"os/signal"
	"time"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	n := 0
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

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				panic(err)
			}

			dump, err := httputil.DumpResponse(resp, true)
			if err != nil {
				panic(err)
			}
			resp.Body.Close()

			n++
			fmt.Printf("Response #%d\n", n)
			fmt.Println(string(dump))
		}
	}
}
