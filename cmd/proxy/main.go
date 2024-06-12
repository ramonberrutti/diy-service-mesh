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
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

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

	serverTLSConfig, clientTLSConfig, err := getMTLSConfig(ctx, smv1Client)
	if err != nil {
		panic(err)
	}

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

		responder := func(c io.ReadWriteCloser, destPort uint16, caller string) error {
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

			// Write response
			if err := resp.Write(c); err != nil {
				return err
			}

			return nil
		}

		for {
			conn, err := l.Accept()
			if err != nil {
				return fmt.Errorf("failed to accept: %w", err)
			}

			go func(c net.Conn) {
				defer c.Close()

				destPort, err := originalPort(c)
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
				// TODO: check the correct port. For now, we are assuming that the port is the same
				if portInt == 443 {
					portInt = 80
				}

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
				addrPicked, _ := rand.Int(rand.Reader, big.NewInt(int64(len(validAddress))))
				randomAddr := validAddress[addrPicked.Int64()]

				fmt.Printf("Resolved %s:%s to %s:%d\n", host, port, randomAddr, finalPort)
				// Look up the original destination
				return net.Dial(network, fmt.Sprintf("%s:%d", randomAddr, finalPort))
			},
			TLSClientConfig: clientTLSConfig,
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

				fmt.Printf("Request: %+v\n", req)

				req.RequestURI = ""
				req.URL.Scheme = "https"
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

				if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
					leaf := resp.TLS.PeerCertificates[0]
					resp.Header.Set("X-Served-By", leaf.Subject.CommonName)
					if len(leaf.Subject.Locality) > 0 {
						resp.Header.Set("X-Served-By-Location", leaf.Subject.Locality[0])
					}
				}

				fmt.Printf("Request: %s Respond: %d\n", req.URL.Path, resp.StatusCode)
				resp.Write(c)
			}(conn)
		}
	})

	if err := g.Wait(); err != nil {
		panic(err)
	}
}

// get original destination
func originalPort(c net.Conn) (uint16, error) {
	f, err := c.(*net.TCPConn).File()
	if err != nil {
		return 0, err
	}
	defer f.Close()

	addr, err := syscall.GetsockoptIPv6Mreq(int(f.Fd()), syscall.IPPROTO_IP, SO_ORIGINAL_DST)
	if err != nil {
		return 0, err
	}

	return uint16(addr.Multiaddr[2])<<8 + uint16(addr.Multiaddr[3]), nil
}

// Generate a new certificate, request a signature from the controller
// and return the TLS configuration
func getMTLSConfig(ctx context.Context, smv1Client smv1pb.ServiceMeshServiceClient) (*tls.Config, *tls.Config, error) {
	token, err := os.ReadFile(os.Getenv("SERVICE_MESH_TOKEN_FILE"))
	if err != nil {
		return nil, nil, err
	}

	tokenStr := string(token)

	sa, err := getServiceAccountFromToken(tokenStr)
	if err != nil {
		return nil, nil, err
	}

	// Generate a new key pair
	public, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	_ = public

	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: sa,
			Locality:   []string{os.Getenv("HOSTNAME")},
		},
	}, priv)
	if err != nil {
		return nil, nil, err
	}

	resp, err := smv1Client.SignCertificate(ctx, &smv1pb.SignCertificateRequest{
		Name:  sa,
		Token: tokenStr,
		Csr:   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}),
	})
	if err != nil {
		return nil, nil, err
	}

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
	h := &tls.ClientHelloInfo{}
	if err := tls.Server(c, &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			*h = *hello
			return nil, nil
		},
	}).Handshake(); h == nil {
		return nil, err
	}

	return h, nil
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
