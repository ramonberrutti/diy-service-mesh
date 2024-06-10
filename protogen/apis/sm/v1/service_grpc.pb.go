// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             (unknown)
// source: apis/sm/v1/service.proto

package smv1

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

const (
	ServiceMeshService_GetServices_FullMethodName     = "/sm.v1.ServiceMeshService/GetServices"
	ServiceMeshService_GetUpstreams_FullMethodName    = "/sm.v1.ServiceMeshService/GetUpstreams"
	ServiceMeshService_SignCertificate_FullMethodName = "/sm.v1.ServiceMeshService/SignCertificate"
)

// ServiceMeshServiceClient is the client API for ServiceMeshService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type ServiceMeshServiceClient interface {
	GetServices(ctx context.Context, in *GetServicesRequest, opts ...grpc.CallOption) (*GetServicesResponse, error)
	GetUpstreams(ctx context.Context, in *UpstreamRequest, opts ...grpc.CallOption) (ServiceMeshService_GetUpstreamsClient, error)
	// SignCertificate signs a certificate signing request (CSR) and returns the signed certificate.
	SignCertificate(ctx context.Context, in *SignCertificateRequest, opts ...grpc.CallOption) (*SignCertificateResponse, error)
}

type serviceMeshServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewServiceMeshServiceClient(cc grpc.ClientConnInterface) ServiceMeshServiceClient {
	return &serviceMeshServiceClient{cc}
}

func (c *serviceMeshServiceClient) GetServices(ctx context.Context, in *GetServicesRequest, opts ...grpc.CallOption) (*GetServicesResponse, error) {
	out := new(GetServicesResponse)
	err := c.cc.Invoke(ctx, ServiceMeshService_GetServices_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *serviceMeshServiceClient) GetUpstreams(ctx context.Context, in *UpstreamRequest, opts ...grpc.CallOption) (ServiceMeshService_GetUpstreamsClient, error) {
	stream, err := c.cc.NewStream(ctx, &ServiceMeshService_ServiceDesc.Streams[0], ServiceMeshService_GetUpstreams_FullMethodName, opts...)
	if err != nil {
		return nil, err
	}
	x := &serviceMeshServiceGetUpstreamsClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type ServiceMeshService_GetUpstreamsClient interface {
	Recv() (*UpstreamResponse, error)
	grpc.ClientStream
}

type serviceMeshServiceGetUpstreamsClient struct {
	grpc.ClientStream
}

func (x *serviceMeshServiceGetUpstreamsClient) Recv() (*UpstreamResponse, error) {
	m := new(UpstreamResponse)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *serviceMeshServiceClient) SignCertificate(ctx context.Context, in *SignCertificateRequest, opts ...grpc.CallOption) (*SignCertificateResponse, error) {
	out := new(SignCertificateResponse)
	err := c.cc.Invoke(ctx, ServiceMeshService_SignCertificate_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ServiceMeshServiceServer is the server API for ServiceMeshService service.
// All implementations should embed UnimplementedServiceMeshServiceServer
// for forward compatibility
type ServiceMeshServiceServer interface {
	GetServices(context.Context, *GetServicesRequest) (*GetServicesResponse, error)
	GetUpstreams(*UpstreamRequest, ServiceMeshService_GetUpstreamsServer) error
	// SignCertificate signs a certificate signing request (CSR) and returns the signed certificate.
	SignCertificate(context.Context, *SignCertificateRequest) (*SignCertificateResponse, error)
}

// UnimplementedServiceMeshServiceServer should be embedded to have forward compatible implementations.
type UnimplementedServiceMeshServiceServer struct {
}

func (UnimplementedServiceMeshServiceServer) GetServices(context.Context, *GetServicesRequest) (*GetServicesResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetServices not implemented")
}
func (UnimplementedServiceMeshServiceServer) GetUpstreams(*UpstreamRequest, ServiceMeshService_GetUpstreamsServer) error {
	return status.Errorf(codes.Unimplemented, "method GetUpstreams not implemented")
}
func (UnimplementedServiceMeshServiceServer) SignCertificate(context.Context, *SignCertificateRequest) (*SignCertificateResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SignCertificate not implemented")
}

// UnsafeServiceMeshServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to ServiceMeshServiceServer will
// result in compilation errors.
type UnsafeServiceMeshServiceServer interface {
	mustEmbedUnimplementedServiceMeshServiceServer()
}

func RegisterServiceMeshServiceServer(s grpc.ServiceRegistrar, srv ServiceMeshServiceServer) {
	s.RegisterService(&ServiceMeshService_ServiceDesc, srv)
}

func _ServiceMeshService_GetServices_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetServicesRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ServiceMeshServiceServer).GetServices(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ServiceMeshService_GetServices_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ServiceMeshServiceServer).GetServices(ctx, req.(*GetServicesRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ServiceMeshService_GetUpstreams_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(UpstreamRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(ServiceMeshServiceServer).GetUpstreams(m, &serviceMeshServiceGetUpstreamsServer{stream})
}

type ServiceMeshService_GetUpstreamsServer interface {
	Send(*UpstreamResponse) error
	grpc.ServerStream
}

type serviceMeshServiceGetUpstreamsServer struct {
	grpc.ServerStream
}

func (x *serviceMeshServiceGetUpstreamsServer) Send(m *UpstreamResponse) error {
	return x.ServerStream.SendMsg(m)
}

func _ServiceMeshService_SignCertificate_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SignCertificateRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ServiceMeshServiceServer).SignCertificate(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ServiceMeshService_SignCertificate_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ServiceMeshServiceServer).SignCertificate(ctx, req.(*SignCertificateRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// ServiceMeshService_ServiceDesc is the grpc.ServiceDesc for ServiceMeshService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var ServiceMeshService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "sm.v1.ServiceMeshService",
	HandlerType: (*ServiceMeshServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetServices",
			Handler:    _ServiceMeshService_GetServices_Handler,
		},
		{
			MethodName: "SignCertificate",
			Handler:    _ServiceMeshService_SignCertificate_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "GetUpstreams",
			Handler:       _ServiceMeshService_GetUpstreams_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "apis/sm/v1/service.proto",
}
