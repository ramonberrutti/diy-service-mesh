package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	smv1pb "github.com/ramonberrutti/diy-service-mesh/protogen/apis/sm/v1"
)

const (
	SO_ORIGINAL_DST = 80
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	// Connect to the controller:
	grpcConn, err := grpc.NewClient("controller.service-mesh.svc.cluster.local.:8080", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		panic(err)
	}
	defer grpcConn.Close()

	// Create our controller client:
	smv1Client := smv1pb.NewServiceMeshServiceClient(grpcConn)
	_ = smv1Client

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

				reqDump, err := httputil.DumpRequest(req, true)
				if err != nil {
					return
				}
				fmt.Println("Request Inbound Dump:")
				fmt.Println(string(reqDump))

				req.RequestURI = ""
				req.URL.Scheme = "http"
				req.URL.Host = req.Host

				inboundClient := http.Client{
					Transport: &http.Transport{
						DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
							return net.Dial(network, fmt.Sprintf("127.0.0.1:%d", destPort))
						},
					},
				}

				// Perform the request
				resp, err := inboundClient.Do(req)
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

	outboundClient := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				// Get the services from the controller
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}

				if !strings.HasSuffix(host, ".svc.cluster.local") && !strings.HasSuffix(host, ".svc.cluster.local.") {
					return net.Dial(network, addr)
				}

				parts := strings.Split(host, ".")
				if len(parts) < 5 {
					return net.Dial(network, addr)
				}

				services, err := smv1Client.GetServices(ctx, &smv1pb.GetServicesRequest{
					Services: []string{parts[1] + "/" + parts[0]},
				})
				if err != nil {
					return nil, err
				}

				if len(services.Services) == 0 {
					return net.Dial(network, addr)
				}

				fmt.Printf("Resolved %s to %+v\n", addr, services.Services[0])

				portInt, _ := strconv.ParseInt(port, 10, 32)
				// have port?
				finalPort := int32(0)
				for _, p := range services.Services[0].Ports {
					if p.Port == int32(portInt) {
						finalPort = p.TargetPort
						break
					}
				}

				if finalPort == 0 {
					return nil, fmt.Errorf("service %s does not have port %s", addr, port)
				}

				// Pick a random address from the list
				validAddress := make([]string, 0)
				for _, endpoint := range services.Services[0].Endpoints {
					if endpoint.Ready {
						validAddress = append(validAddress, endpoint.Addresses...)
					}
				}

				if len(validAddress) == 0 {
					return nil, fmt.Errorf("no valid endpoints for service %s", addr)
				}

				// Pick a random address from the list
				randomAddr := validAddress[rand.Intn(len(validAddress))]

				fmt.Printf("Resolved %s:%s to %s:%d\n", host, port, randomAddr, finalPort)
				// Look up the original destination
				return net.Dial(network, fmt.Sprintf("%s:%d", randomAddr, finalPort))
			},
		},
	}

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

				reqDump, err := httputil.DumpRequest(req, true)
				if err != nil {
					return
				}
				fmt.Println("Request Outbound Dump:")
				fmt.Println(string(reqDump))

				req.RequestURI = ""
				req.URL.Scheme = "http"
				req.URL.Host = req.Host

				// Write the response
				resp, err := outboundClient.Do(req)
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
