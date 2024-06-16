package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	smv1pb "github.com/ramonberrutti/diy-service-mesh/protogen/apis/sm/v1"
)

const (
	SO_ORIGINAL_DST = 80

	HTTP2_PREFACE = "PRI * HTTP/2.0"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
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

	serverTLSConfig, clientTLSConfig, err := getMTLSConfig(ctx, smv1Client)
	if err != nil {
		panic(err)
	}
	_ = clientTLSConfig

	g, ctx := errgroup.WithContext(ctx)
	// Inbound connection
	g.Go(func() error {
		return listen(ctx, ":4000", func(conn net.Conn) {
			handleInboundConnection(conn, serverTLSConfig)
		})
	})

	// Outbound connection
	g.Go(func() error {
		return listen(ctx, ":5000", func(conn net.Conn) {
			handleOutboundConnection(conn, clientTLSConfig)
		})
	})

	if err := g.Wait(); err != nil {
		panic(err)
	}
}

func listen(ctx context.Context, addr string, accept func(net.Conn)) error {
	l, err := net.Listen("tcp", addr)
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

		go accept(conn)
	}
}

func handleInboundConnection(c net.Conn, serverTLSConfig *tls.Config) {
	defer c.Close()

	_, destPort, err := getOriginalDestination(c)
	if err != nil {
		fmt.Printf("Failed to get original destination: %v\n", err)
		return
	}

	// To handle TLS and Plaintext connections
	// first we need to peek the ClientHello
	cp := &connPeek{c: c, peek: true, nowrite: true}
	clientHello, err := peekClientHello(cp)
	cp.applyPeek, cp.nowrite = true, false
	fmt.Printf("ClientHello: %+v\n", clientHello)
	if err != nil { // Plaintext
		fmt.Println("Plaintext connection")
		if err := responder(cp, destPort, "<unknown>"); err != nil {
			fmt.Printf("Failed to respond: %v\n", err)
		}
	} else { // TLS
		fmt.Println("TLS connection")
		tlsConn := tls.Server(cp, serverTLSConfig)
		if err := tlsConn.Handshake(); err != nil {
			return
		}

		state := tlsConn.ConnectionState()
		// Get common name
		caller := "<unknown>"
		for _, cert := range state.PeerCertificates {
			caller = cert.Subject.CommonName
			break
		}

		if err := responder(tlsConn, destPort, caller); err != nil {
			fmt.Printf("Failed to respond: %v\n", err)
		}
	}
}

func handleOutboundConnection(c net.Conn, _ *tls.Config) {
	defer c.Close()

	// Get the original destination
	ip, port, err := getOriginalDestination(c)
	if err != nil {
		fmt.Printf("Failed to get original destination: %v\n", err)
		return
	}

	b := bufio.NewReaderSize(c, 14)

	// Check if is http2
	peek, err := b.Peek(14)
	if err != nil {
		return
	}

	isH2 := string(peek) == HTTP2_PREFACE

	upstream, err := net.Dial("tcp", fmt.Sprintf("%s:%d", ip, port))
	// upstream, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", ip, port), clientTLSConfig)
	if err != nil {
		return
	}
	defer upstream.Close()

	if isH2 {
		// go func() {
		// 	io.Copy(upstream, b)
		// }()

		// io.Copy(c, io.TeeReader(upstream, os.Stdout))
		// return
		fmt.Println("HTTP/2 connection")

		// Read preface
		prefare := make([]byte, len(http2.ClientPreface))
		if _, err := io.ReadFull(b, prefare); err != nil {
			fmt.Printf("Failed to read preface: %v\n", err)
			return
		}

		fmt.Printf("Preface: %s\n", prefare)

		// Write preface
		if _, err := upstream.Write(prefare); err != nil {
			fmt.Printf("Failed to write preface: %v\n", err)
			return
		}

		framer := http2.NewFramer(c, b)
		framer.SetReuseFrames()
		framer.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
		framer.MaxHeaderListSize = uint32(16 << 20)

		upstreamFramer := http2.NewFramer(upstream, upstream)
		upstreamFramer.SetReuseFrames()
		upstreamFramer.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
		upstreamFramer.MaxHeaderListSize = uint32(16 << 20)

		go func() {
			for {
				frame, err := framer.ReadFrame()
				if err != nil {
					fmt.Printf("Failed to read outbound frame: %v\n", err)
					return
				}

				fmt.Printf("Outbound Frame: %+v\n", frame)

				switch frame := frame.(type) {
				case *http2.DataFrame:
					fmt.Println("Outbound DataFrame")

					fmt.Printf("Data: %s\n", frame.Data())

					if err := upstreamFramer.WriteData(frame.StreamID, frame.StreamEnded(), frame.Data()); err != nil {
						fmt.Printf("Failed to write frame: %v\n", err)
						return
					}

				case *http2.MetaHeadersFrame:
					fmt.Println("Outbound MetaHeadersFrame")

					hBuf := new(bytes.Buffer)
					hEnc := hpack.NewEncoder(hBuf)

					for _, f := range frame.Fields {
						fmt.Printf("Header: %s: %s\n", f.Name, f.Value)
						if err := hEnc.WriteField(f); err != nil {
							fmt.Printf("Failed to write field: %v\n", err)
						}
					}

					first, done := true, false
					for !done {
						size := hBuf.Len()
						if size > 16384 {
							size = 16384
						} else {
							done = true
						}

						if first {
							first = false
							if err := upstreamFramer.WriteHeaders(http2.HeadersFrameParam{
								StreamID:      frame.StreamID,
								EndStream:     frame.StreamEnded(),
								EndHeaders:    done,
								BlockFragment: hBuf.Next(size),
								Priority:      frame.Priority,
								PadLength:     0,
							}); err != nil {
								fmt.Printf("Failed to write frame: %v\n", err)
								return
							}
						} else {
							if err := upstreamFramer.WriteContinuation(frame.StreamID, done, hBuf.Next(size)); err != nil {
								fmt.Printf("Failed to write frame: %v\n", err)
								return
							}
						}
					}

				case *http2.HeadersFrame:
					// Print the headers
					fmt.Printf("Outbound Headers: %s\n", frame.HeaderBlockFragment())

					fmt.Println("HeadersFrame")
					if err := upstreamFramer.WriteHeaders(http2.HeadersFrameParam{
						StreamID:      frame.StreamID,
						EndStream:     frame.StreamEnded(),
						EndHeaders:    frame.HeadersEnded(),
						BlockFragment: frame.HeaderBlockFragment(),
						Priority:      frame.Priority,
						PadLength:     0,
					}); err != nil {
						fmt.Printf("Failed to write frame: %v\n", err)
						return
					}

				case *http2.PriorityFrame:
					fmt.Println("PriorityFrame")
					if err := upstreamFramer.WritePriority(frame.StreamID, frame.PriorityParam); err != nil {
						fmt.Printf("Failed to write frame: %v\n", err)
						return
					}

				case *http2.RSTStreamFrame:
					fmt.Println("RSTStreamFrame")
					if err := upstreamFramer.WriteRSTStream(frame.StreamID, frame.ErrCode); err != nil {
						fmt.Printf("Failed to write frame: %v\n", err)
						return
					}

				case *http2.SettingsFrame:
					fmt.Println("Outbound SettingsFrame")
					settings := make([]http2.Setting, frame.NumSettings())
					for i := 0; i < frame.NumSettings(); i++ {
						settings[i] = frame.Setting(i)
					}

					if frame.IsAck() {
						upstreamFramer.WriteSettingsAck()
					} else {
						upstreamFramer.WriteSettings(settings...)
					}

				case *http2.PushPromiseFrame:
					fmt.Println("PushPromiseFrame")
					if err := upstreamFramer.WritePushPromise(http2.PushPromiseParam{}); err != nil {
						fmt.Printf("Failed to write frame: %v\n", err)
						return
					}

				case *http2.PingFrame:
					fmt.Println("PingFrame")
					if err := upstreamFramer.WritePing(true, frame.Data); err != nil {
						fmt.Printf("Failed to write frame: %v\n", err)
						return
					}

				case *http2.GoAwayFrame:
					fmt.Println("GoAwayFrame")
					if err := upstreamFramer.WriteGoAway(frame.LastStreamID, frame.ErrCode, frame.DebugData()); err != nil {
						fmt.Printf("Failed to write frame: %v\n", err)
						return
					}

				case *http2.WindowUpdateFrame:
					fmt.Println("WindowUpdateFrame")
					if err := upstreamFramer.WriteWindowUpdate(frame.StreamID, frame.Increment); err != nil {
						fmt.Printf("Failed to write frame: %v\n", err)
						return
					}

				case *http2.ContinuationFrame:
					fmt.Println("ContinuationFrame")
					if err := upstreamFramer.WriteContinuation(frame.StreamID, frame.HeadersEnded(), frame.HeaderBlockFragment()); err != nil {
						fmt.Printf("Failed to write frame: %v\n", err)
						return
					}

				default:
					fmt.Printf("Unknown outgoing type %T frame: %+v\n", frame, frame)
				}
			}
		}()

		// Read the response
		for {
			frame, err := upstreamFramer.ReadFrame()
			if err != nil {
				fmt.Printf("Failed to read inbound frame: %v\n", err)
				return
			}

			fmt.Printf("Inbound Frame: %+v\n", frame)

			switch frame := frame.(type) {
			case *http2.DataFrame:
				fmt.Println("DataFrame")
				if err := framer.WriteData(frame.StreamID, frame.StreamEnded(), frame.Data()); err != nil {
					fmt.Printf("Failed to write frame: %v\n", err)
					return
				}

			case *http2.MetaHeadersFrame:
				fmt.Println("Inbound MetaHeadersFrame")

				hBuf := new(bytes.Buffer)
				hEnc := hpack.NewEncoder(hBuf)

				for _, f := range frame.Fields {
					fmt.Printf("Header: %s: %s\n", f.Name, f.Value)
					if err := hEnc.WriteField(f); err != nil {
						fmt.Printf("Failed to write field: %v\n", err)
					}
				}

				first, done := true, false
				for !done {
					size := hBuf.Len()
					if size > 16384 {
						size = 16384
					} else {
						done = true
					}

					if first {
						first = false
						if err := framer.WriteHeaders(http2.HeadersFrameParam{
							StreamID:      frame.StreamID,
							EndStream:     frame.StreamEnded(),
							EndHeaders:    done,
							BlockFragment: hBuf.Next(size),
							Priority:      frame.Priority,
							PadLength:     0,
						}); err != nil {
							fmt.Printf("Failed to write frame: %v\n", err)
							return
						}
					} else {
						if err := framer.WriteContinuation(frame.StreamID, done, hBuf.Next(size)); err != nil {
							fmt.Printf("Failed to write frame: %v\n", err)
							return
						}
					}
				}

			case *http2.HeadersFrame:
				fmt.Println("HeadersFrame")
				if err := framer.WriteHeaders(http2.HeadersFrameParam{
					StreamID:      frame.StreamID,
					EndStream:     frame.StreamEnded(),
					EndHeaders:    frame.HeadersEnded(),
					BlockFragment: frame.HeaderBlockFragment(),
					Priority:      frame.Priority,
					PadLength:     0,
				}); err != nil {
					fmt.Printf("Failed to write frame: %v\n", err)
					return
				}

			case *http2.PriorityFrame:
				fmt.Println("PriorityFrame")
				if err := framer.WritePriority(frame.StreamID, frame.PriorityParam); err != nil {
					fmt.Printf("Failed to write frame: %v\n", err)
					return
				}

			case *http2.RSTStreamFrame:
				fmt.Println("RSTStreamFrame")
				if err := framer.WriteRSTStream(frame.StreamID, frame.ErrCode); err != nil {
					fmt.Printf("Failed to write frame: %v\n", err)
					return
				}

			case *http2.SettingsFrame:
				fmt.Println("Inbound SettingsFrame")
				settings := make([]http2.Setting, frame.NumSettings())
				for i := 0; i < frame.NumSettings(); i++ {
					settings[i] = frame.Setting(i)
				}

				if frame.IsAck() {
					framer.WriteSettingsAck()
				} else {
					if err := framer.WriteSettings(settings...); err != nil {
						fmt.Printf("Failed to write frame: %v\n", err)
						return
					}
				}

			case *http2.PushPromiseFrame:
				fmt.Println("PushPromiseFrame")
				if err := framer.WritePushPromise(http2.PushPromiseParam{}); err != nil {
					fmt.Printf("Failed to write frame: %v\n", err)
					return
				}

			case *http2.PingFrame:
				fmt.Println("PingFrame")
				if err := framer.WritePing(true, frame.Data); err != nil {
					fmt.Printf("Failed to write frame: %v\n", err)
					return
				}

			case *http2.GoAwayFrame:
				fmt.Println("GoAwayFrame")
				if err := framer.WriteGoAway(frame.LastStreamID, frame.ErrCode, frame.DebugData()); err != nil {
					fmt.Printf("Failed to write frame: %v\n", err)
					return
				}

			case *http2.WindowUpdateFrame:
				fmt.Println("WindowUpdateFrame")
				if err := framer.WriteWindowUpdate(frame.StreamID, frame.Increment); err != nil {
					fmt.Printf("Failed to write frame: %v\n", err)
					return
				}

			case *http2.ContinuationFrame:
				fmt.Println("ContinuationFrame")
				if err := framer.WriteContinuation(frame.StreamID, frame.HeadersEnded(), frame.HeaderBlockFragment()); err != nil {
					fmt.Printf("Failed to write frame: %v\n", err)
					return
				}

			default:
				fmt.Printf("Unknown inbound frame: %+v\n", frame)
			}
		}
	} else {
		// Read the request
		req, err := http.ReadRequest(b)
		if err != nil {
			return
		}

		req.Write(os.Stdout)

		// Write the request
		if err := req.Write(upstream); err != nil {
			return
		}

		// Read the response
		resp, err := http.ReadResponse(bufio.NewReader(upstream), req)
		if err != nil {
			return
		}
		defer resp.Body.Close()

		// Write the response
		if err := resp.Write(c); err != nil {
			return
		}
	}
}

func responder(c io.ReadWriteCloser, destPort uint16, caller string) error {
	defer c.Close()

	// Read request
	req, err := http.ReadRequest(bufio.NewReader(c))
	if err != nil {
		return err
	}

	req.Header.Set("X-Called-By", caller)

	upstream, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", destPort))
	if err != nil {
		return err
	}
	defer upstream.Close()

	// Write request
	if err := req.Write(upstream); err != nil {
		return err
	}

	// Read response
	resp, err := http.ReadResponse(bufio.NewReader(upstream), req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Write response
	if err := resp.Write(c); err != nil {
		return err
	}

	return nil
}

func getOriginalDestination(c net.Conn) (string, uint16, error) {
	tcpConn, ok := c.(*net.TCPConn)
	if !ok {
		return "", 0, fmt.Errorf("not a TCP connection")
	}

	f, err := tcpConn.File()
	if err != nil {
		return "", 0, err
	}
	defer f.Close()

	addr, err := syscall.GetsockoptIPv6Mreq(int(f.Fd()), syscall.IPPROTO_IP, SO_ORIGINAL_DST)
	if err != nil {
		return "", 0, err
	}

	return net.IP(addr.Multiaddr[4:8]).String(), uint16(addr.Multiaddr[2])<<8 + uint16(addr.Multiaddr[3]), nil
}

// Generate a new certificate, request a signature from the controller
// and return the TLS configuration
func getMTLSConfig(ctx context.Context, smv1Client smv1pb.ServiceMeshServiceClient) (*tls.Config, *tls.Config, error) {
	// Read the service account token issued for diy-service-mesh audience
	token, err := os.ReadFile(os.Getenv("SERVICE_MESH_TOKEN_FILE"))
	if err != nil {
		return nil, nil, err
	}
	tokenStr := string(token)

	// Parse the token and get the service account name.
	sa, err := getServiceAccountFromToken(tokenStr)
	if err != nil {
		return nil, nil, err
	}

	// Generate a new key pair.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	// Generate a new certificate signing request with the service account name as the common name.
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: sa,
			Locality:   []string{os.Getenv("HOSTNAME")}, // Use the hostname as the locality
		},
	}, priv)
	if err != nil {
		return nil, nil, err
	}

	// Send the certificate signing request to the controller and get the signed certificate.
	// The controller is responsible for verifying the service account token and the certificate signing request.
	resp, err := smv1Client.SignCertificate(ctx, &smv1pb.SignCertificateRequest{
		Name:  sa,
		Token: tokenStr,
		Csr:   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}),
	})
	if err != nil {
		return nil, nil, err
	}

	// resp contains the signed certificate and the CA certificate.

	cert, _ := pem.Decode(resp.Cert)

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(resp.Ca)

	verifyPeerCertificate := func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		certs := make([]*x509.Certificate, 0, len(rawCerts))
		for _, rawCert := range rawCerts {
			cert, err := x509.ParseCertificate(rawCert)
			if err != nil {
				return fmt.Errorf("failed to parse certificate: %w", err)
			}
			certs = append(certs, cert)
		}

		if len(certs) == 0 {
			return fmt.Errorf("no certificates provided")
		}

		intermediates := x509.NewCertPool()
		for _, cert := range certs[1:] {
			intermediates.AddCert(cert)
		}

		opts := x509.VerifyOptions{
			Roots:         caCertPool,
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			CurrentTime:   time.Now(),
		}

		if _, err := certs[0].Verify(opts); err != nil {
			return fmt.Errorf("failed to verify certificate: %w", err)
		}

		return nil
	}

	serverTLSConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{cert.Bytes},
				PrivateKey:  priv,
			},
		},
		VerifyPeerCertificate: verifyPeerCertificate,
		ClientAuth:            tls.RequireAnyClientCert,
	}

	clientTLSConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{cert.Bytes},
				PrivateKey:  priv,
			},
		},
		VerifyPeerCertificate: verifyPeerCertificate,
		InsecureSkipVerify:    true,
	}

	return serverTLSConfig, clientTLSConfig, nil
}

func getServiceAccountFromToken(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid token")
	}

	claims, err := base64.RawStdEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}

	mapClaims := make(map[string]interface{})
	if err := json.Unmarshal(claims, &mapClaims); err != nil {
		return "", err
	}

	return mapClaims["sub"].(string), nil
}

func peekClientHello(c net.Conn) (*tls.ClientHelloInfo, error) {
	var hello *tls.ClientHelloInfo
	if err := tls.Server(c, &tls.Config{
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			hello = h
			return nil, nil
		},
	}).Handshake(); hello == nil {
		return nil, fmt.Errorf("failed to peek ClientHello: %w", err)
	}

	return hello, nil
}

type connPeek struct {
	c       net.Conn
	buf     bytes.Buffer
	nowrite bool

	peek      bool
	applyPeek bool
}

func (cp *connPeek) Read(p []byte) (int, error) {
	if cp.applyPeek && cp.buf.Len() > 0 {
		return cp.buf.Read(p)
	} else if !cp.applyPeek && cp.peek {
		n, err := cp.c.Read(p)
		if err != nil {
			return n, err
		}

		cp.buf.Write(p[:n])
		return n, nil
	}

	return cp.c.Read(p)
}

func (cp *connPeek) Write(p []byte) (int, error) {
	if cp.nowrite {
		return 0, io.ErrClosedPipe
	}

	return cp.c.Write(p)
}
func (cp *connPeek) Close() error                       { return cp.c.Close() }
func (cp *connPeek) LocalAddr() net.Addr                { return cp.c.LocalAddr() }
func (cp *connPeek) RemoteAddr() net.Addr               { return cp.c.RemoteAddr() }
func (cp *connPeek) SetDeadline(t time.Time) error      { return cp.c.SetDeadline(t) }
func (cp *connPeek) SetReadDeadline(t time.Time) error  { return cp.c.SetReadDeadline(t) }
func (cp *connPeek) SetWriteDeadline(t time.Time) error { return cp.c.SetWriteDeadline(t) }
