# DIY Service Mesh

This is a Do-It-Yourself Service Mesh, which is a learning platform for understanding 
the internals of a service mesh. The goal of this project is to provide a simple, 
easy-to-understand reference implementation of a service mesh, which can be used 
to learn about the various concepts and technologies used in a service mesh.

## What are you going to learn?

- How to build a simple proxy and add service mesh features to it.
- How to use Netfilter to intercept and modify network packets.
- How to create a simple control plane to manage the service mesh.
- How to use gRPC to communicate between the data plane and the control plane.
- How to create a Admision Controller to validate and mutate Kubernetes resources.

## Some considerations

- This is only for learning propose, not a production-ready service mesh.
- We are going to use IPTables instead of eBPF or Nftables for simplicity.
- We are going to keep the code as simple as possible to make it easy to understand.


## What are we going to build?

We are going to keep the project in a monorepo, which will contain the following components:

- **init-container**: This is an init container that we are going to use to configure the network namespace of the pods.
- **data-plane**: This is the data plane of the service mesh, which is responsible for intercepting and modifying network packets.
- **control-plane**: This is the control plane of the service mesh, which is responsible for managing the data plane.
- **admission-controller**: This is an Admission Controller for Kubernetes, which is responsible for validating and mutating Kubernetes resources.
- **sample-app**: This is a sample application that we are going to use to test the service mesh with different scenarios.

## How to run this project?

We are going to use:

- [kind](https://kind.sigs.k8s.io/) to create a Kubernetes cluster locally.
- [Tilt](https://tilt.dev/) to run the project and watch for changes.
- [Buf](https://buf.build/) to lint and generate the Protobuf/gRPC code.
- [Docker](https://www.docker.com/) to build the Docker images.
- [k9s](https://k9scli.io/) to interact with the Kubernetes cluster. (Optional)

To start all the components, run the following command:

```bash
tilt up
```

Will build all the images and deploy all the components to the Kubernetes cluster.


## Architecture

The architecture of the service mesh is composed of the following components:

![Architecture](./docs/images/architecture.png)



## Creating the applications

We are going to create two applications:

- **app-a**: This application if going to call the `app-b` service.
- **app-b**: This application is going to be called by the `app-a` service.

We are going to deploy app-b two times, one with the version `v1` and another with the version `v2`.

app-a:

```go
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
```

As we can see, the `app-a` is going to call the `app-b` service every second, and print the response.

app-b:

```go
func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	failRate, _ := strconv.Atoi(os.Getenv("FAIL_RATE"))

	n := uint64(0)
	hostname := os.Getenv("HOSTNAME")
	version := os.Getenv("VERSION")

	var b bytes.Buffer
	b.WriteString("Hello from app-b service! Hostname: ")
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
```

The `app-b` service is going to respond with a message that contains the hostname and the version of the service. 
We are going to simulate failures by setting the `FAIL_RATE` environment variable.

Each service is going to be deployed in a different namespace:

- app-a: `app-a` Deployment in the `app-a` namespace: [app-a.yaml](./k8s/app-a.yaml)
- app-b: `app-b` Deployment in the `app-b` namespace: [app-b.yaml](./k8s/app-b.yaml)

## Testing the service mesh

We can check the logs of the `app-a` and `app-b` services to see the communication between them.

app-a logs:
```bash
Response #311
HTTP/1.1 200 OK
Content-Length: 71
Content-Type: text/plain
Date: Sat, 08 Jun 2024 19:38:27 GMT

Hello from app-b service! Hostname: app-b-799c77dc9b-56lmd Version: 1.0
```

app-b logs:
```bash
Request #171
GET /hello HTTP/1.1
Host: app-b.app-b.svc.cluster.local.
Accept-Encoding: gzip
User-Agent: Go-http-client/1.1
```

## We are going to implement a simple proxy that will intercept the network requests and responses.

As we see in the architecture diagram, the proxy is going to intercept the network packets and forward them to the destination service.
To do this we are going to listen in a specific port, intercept the packets, and forward them to the destination service, for inbound and outbound traffic.

This is a basic implementation of the proxy, that will intercept and forward the packets:

```go
func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

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

				destPort := "" // WE ARE GOING TO MODIFY THIS PART IN THE NEXT STEP

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
                // WE ARE GOING TO MODIFY THIS PART IN THE NEXT STEP
                return net.Dial(network, addr)
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
```

We are using port `4000` for the inbound traffic and port `5000` for the outbound traffic.
In the next steps we are going to add retries, metrics and canary deployments to the proxy and finally mTLS between the services.

## Kubernetes understanding

Each kubernetes pod shares the same network between the containers, so we can use the `localhost` to communicate between the containers.

What we are going to do is to intercept all the packets and send always to the proxy except the ones that are going out from the proxy container.

We are going to use the `iptables` to intercept the packets and send them to the proxy.

```go
func main() {
	// Configure the proxy
	commands := []*exec.Cmd{
		// Default accept for all nat chains
		exec.Command("iptables", "-t", "nat", "-P", "PREROUTING", "ACCEPT"),
		exec.Command("iptables", "-t", "nat", "-P", "INPUT", "ACCEPT"),
		exec.Command("iptables", "-t", "nat", "-P", "OUTPUT", "ACCEPT"),
		exec.Command("iptables", "-t", "nat", "-P", "POSTROUTING", "ACCEPT"),

		// Create custom chains so we can jump to them
		exec.Command("iptables", "-t", "nat", "-N", "PROXY_INBOUND"),
		exec.Command("iptables", "-t", "nat", "-N", "PROXY_OUTBOUND"),

		// Jump to custom chains, if something is not matched, will return to the default chains.
		exec.Command("iptables", "-t", "nat", "-A", "PREROUTING", "-p", "tcp", "-j", "PROXY_INBOUND"),
		exec.Command("iptables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-j", "PROXY_OUTBOUND"),

		// Set rules for custom chains: PROXY_INBOUND, redirect all inbound traffic to port 4000
		exec.Command("iptables", "-t", "nat", "-A", "PROXY_INBOUND", "-p", "tcp", "-j", "REDIRECT", "--to-port", "4000"),

		// Set rules for custom chains: PROXY_OUTBOUND
        // Ignore traffic between the containers.
		exec.Command("iptables", "-t", "nat", "-A", "PROXY_OUTBOUND", "-o", "lo", "-j", "RETURN"),
		exec.Command("iptables", "-t", "nat", "-A", "PROXY_OUTBOUND", "-d", "127.0.0.1/32", "-j", "RETURN"),

		// Ignore outbound traffic from the proxy container.
		exec.Command("iptables", "-t", "nat", "-A", "PROXY_OUTBOUND", "-m", "owner", "--uid-owner", "1337", "-j", "RETURN"),

		// Redirect all the outbound traffic to port 5000
		exec.Command("iptables", "-t", "nat", "-A", "PROXY_OUTBOUND", "-p", "tcp", "-j", "REDIRECT", "--to-port", "5000"),
	}

	for _, cmd := range commands {
		if err := cmd.Run(); err != nil {
			fmt.Printf("failed to run command: %v\n", err)
		}
	}

	fmt.Println("Proxy initialized successfully!")
}
```

Some important points:

- We are using the proxy UID to ignore the outbound traffic from the proxy container. `--uid-owner 1337`
- We are going to use `SO_ORIGINAL_DST` to get the original destination of the packet.


## Adding the proxy and proxy-init containers to the deployments:

```yaml
    spec:
      initContainers:
      - name: proxy-init
        image: diy-sm-proxy-init
        imagePullPolicy: IfNotPresent
        securityContext:
          capabilities:
            add:
              - NET_ADMIN
              - NET_RAW
            drop:
              - ALL
      containers:
      - name: proxy
        image: diy-sm-proxy
        imagePullPolicy: IfNotPresent
        securityContext:
          runAsUser: 1337
      - name: app-a
        image: diy-sm-app-a
        imagePullPolicy: IfNotPresent
```

The same configuration is going to be applied to the `app-b` deployment.

Some important points:

- proxy-init is a init container that is going to configure the network namespace of the pod and finish.
- We are using the `NET_ADMIN` and `NET_RAW` capabilities in the `proxy-init` container, 
  without these capabilities we can't use the `iptables` to intercept the packets.
- We are using the `runAsUser: 1337` in the `proxy` container, so we can ignore the outbound traffic from the proxy container.


Doing this is not so simple, we want to kubernetes inject the proxy and proxy-init containers in the pod for us.
Here is where the `Admission Controller` comes in.