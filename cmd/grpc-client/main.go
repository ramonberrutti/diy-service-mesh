package main

import (
	"context"
	"fmt"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	echov1pb "github.com/ramonberrutti/diy-service-mesh/protogen/apis/echo/v1"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	conn, err := grpc.NewClient("grpc-server.grpc-server.svc.cluster.local.:8080", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		panic(err)
	}

	echoServiceClient := echov1pb.NewEchoServiceClient(conn)

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return

		case <-ticker.C:
			resp, err := echoServiceClient.Echo(ctx, &echov1pb.EchoRequest{Message: "Hello, world!"})
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				continue
			}

			fmt.Printf("Response: %s\n", resp.Message)
		}
	}
}
