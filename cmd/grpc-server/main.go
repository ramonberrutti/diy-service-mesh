package main

import (
	"context"
	"net"
	"os/signal"
	"syscall"

	"google.golang.org/grpc"

	echov1pb "github.com/ramonberrutti/diy-service-mesh/protogen/apis/echo/v1"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Implement the EchoServiceServer interface
	// and run the gRPC server
	l, err := net.Listen("tcp", ":8080")
	if err != nil {
		panic(err)
	}

	s := grpc.NewServer()
	echov1pb.RegisterEchoServiceServer(s, &echoServiceServer{})

	go func() {
		if err := s.Serve(l); err != nil {
			panic(err)
		}
	}()

	<-ctx.Done()
	s.GracefulStop()
}

type echoServiceServer struct {
	echov1pb.UnimplementedEchoServiceServer
}

func (s *echoServiceServer) Echo(ctx context.Context, req *echov1pb.EchoRequest) (*echov1pb.EchoResponse, error) {
	return &echov1pb.EchoResponse{Message: req.Message}, nil
}
