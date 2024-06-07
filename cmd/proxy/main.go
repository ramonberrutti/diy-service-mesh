package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/sync/errgroup"
)

const (
	SO_ORIGINAL_DST = 80
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	httpClient := http.Client{}

	g, ctx := errgroup.WithContext(ctx)
	// Inbound connection
	g.Go(func() error {
		l, err := net.Listen("tcp", ":4000")
		if err != nil {
			return fmt.Errorf("failed to listen: %w", err)
		}
		defer l.Close()
		go func() {
			<-ctx.Done()
			l.Close()
		}()

		for {
			conn, err := l.Accept()
			if err != nil {
				return fmt.Errorf("failed to accept: %w", err)
			}

			go func(c net.Conn) {
				defer c.Close()

				fmt.Printf("Accepted connection from Local: %+v  Remote: %+v\n", c.LocalAddr(), c.RemoteAddr())

				// Get original destination
				cFile, err := c.(*net.TCPConn).File()
				if err != nil {
					return
				}
				defer cFile.Close()

				addr, err := syscall.GetsockoptIPv6Mreq(int(cFile.Fd()), syscall.IPPROTO_IP, SO_ORIGINAL_DST)
				if err != nil {
					return
				}

				destPort := uint16(addr.Multiaddr[2])<<8 + uint16(addr.Multiaddr[3])

				// Read the request
				req, err := http.ReadRequest(bufio.NewReader(c))
				if err != nil {
					return
				}

				req.RequestURI = ""
				req.URL.Scheme = "http"
				req.URL.Host = fmt.Sprintf("127.0.0.1:%d", destPort)

				// Perform the request
				resp, err := httpClient.Do(req)
				if err != nil {
					body := fmt.Sprintf("Failed to process request (inbound: %s): %v", os.Getenv("HOSTNAME"), err)
					rp := http.Response{
						Status:        http.StatusText(http.StatusInternalServerError),
						StatusCode:    http.StatusInternalServerError,
						Proto:         "HTTP/1.1",
						ProtoMajor:    1,
						ProtoMinor:    1,
						Body:          io.NopCloser(bytes.NewBufferString(body)),
						ContentLength: int64(len(body)),
						Header:        make(http.Header),
					}

					rp.Write(c)
					return
				}
				defer resp.Body.Close()

				fmt.Printf("Request: %s Respond: %d\n", req.URL.Path, resp.StatusCode)
				resp.Write(c)
			}(conn)
		}
	})

	// Outbound connection
	g.Go(func() error {
		l, err := net.Listen("tcp", ":5000")
		if err != nil {
			return fmt.Errorf("failed to listen: %w", err)
		}
		defer l.Close()
		go func() {
			<-ctx.Done()
			l.Close()
		}()

		for {
			conn, err := l.Accept()
			if err != nil {
				return fmt.Errorf("failed to accept: %w", err)
			}

			go func(c net.Conn) {
				defer c.Close()

				// Read the request
				req, err := http.ReadRequest(bufio.NewReader(c))
				if err != nil {
					return
				}

				req.RequestURI = ""
				req.URL.Scheme = "http"
				req.URL.Host = req.Host

				// Write the response
				resp, err := httpClient.Do(req)
				if err != nil {
					body := fmt.Sprintf("Failed to process request (outbound: %s): %v", os.Getenv("HOSTNAME"), err)
					rp := http.Response{
						Status:        http.StatusText(http.StatusInternalServerError),
						StatusCode:    http.StatusInternalServerError,
						Proto:         "HTTP/1.1",
						ProtoMajor:    1,
						ProtoMinor:    1,
						Body:          io.NopCloser(bytes.NewBufferString(body)),
						ContentLength: int64(len(body)),
						Header:        make(http.Header),
					}

					rp.Write(c)
					return
				}
				defer resp.Body.Close()

				fmt.Printf("Request: %s Respond: %d\n", req.URL.Path, resp.StatusCode)
				resp.Write(c)
			}(conn)
		}
	})

	if err := g.Wait(); err != nil {
		panic(err)
	}
}
