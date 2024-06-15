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

func handleOutboundConnection(c net.Conn, clientTLSConfig *tls.Config) {
	defer c.Close()

	// Get the original destination
	ip, port, err := getOriginalDestination(c)
	if err != nil {
		fmt.Printf("Failed to get original destination: %v\n", err)
		return
	}

	fmt.Printf("Outbound connection to %s:%d\n", ip, port)

	// Read the request
	req, err := http.ReadRequest(bufio.NewReader(c))
	if err != nil {
		return
	}

	// upstream, err := net.Dial("tcp", fmt.Sprintf("%s:%d", ip, port))
	upstream, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", ip, port), clientTLSConfig)
	if err != nil {
		return
	}
	defer upstream.Close()

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
