// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.31.0
// 	protoc        (unknown)
// source: apis/sm/v1/service.proto

package smv1

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type GetServicesRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Services []string `protobuf:"bytes,1,rep,name=services,proto3" json:"services,omitempty"`
}

func (x *GetServicesRequest) Reset() {
	*x = GetServicesRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_apis_sm_v1_service_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetServicesRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetServicesRequest) ProtoMessage() {}

func (x *GetServicesRequest) ProtoReflect() protoreflect.Message {
	mi := &file_apis_sm_v1_service_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetServicesRequest.ProtoReflect.Descriptor instead.
func (*GetServicesRequest) Descriptor() ([]byte, []int) {
	return file_apis_sm_v1_service_proto_rawDescGZIP(), []int{0}
}

func (x *GetServicesRequest) GetServices() []string {
	if x != nil {
		return x.Services
	}
	return nil
}

type GetServicesResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Services []*Service `protobuf:"bytes,1,rep,name=services,proto3" json:"services,omitempty"`
}

func (x *GetServicesResponse) Reset() {
	*x = GetServicesResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_apis_sm_v1_service_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetServicesResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetServicesResponse) ProtoMessage() {}

func (x *GetServicesResponse) ProtoReflect() protoreflect.Message {
	mi := &file_apis_sm_v1_service_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetServicesResponse.ProtoReflect.Descriptor instead.
func (*GetServicesResponse) Descriptor() ([]byte, []int) {
	return file_apis_sm_v1_service_proto_rawDescGZIP(), []int{1}
}

func (x *GetServicesResponse) GetServices() []*Service {
	if x != nil {
		return x.Services
	}
	return nil
}

type UpstreamRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ServiceName string `protobuf:"bytes,1,opt,name=serviceName,proto3" json:"serviceName,omitempty"`
}

func (x *UpstreamRequest) Reset() {
	*x = UpstreamRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_apis_sm_v1_service_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UpstreamRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UpstreamRequest) ProtoMessage() {}

func (x *UpstreamRequest) ProtoReflect() protoreflect.Message {
	mi := &file_apis_sm_v1_service_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UpstreamRequest.ProtoReflect.Descriptor instead.
func (*UpstreamRequest) Descriptor() ([]byte, []int) {
	return file_apis_sm_v1_service_proto_rawDescGZIP(), []int{2}
}

func (x *UpstreamRequest) GetServiceName() string {
	if x != nil {
		return x.ServiceName
	}
	return ""
}

type UpstreamResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Services []*Service `protobuf:"bytes,1,rep,name=services,proto3" json:"services,omitempty"`
}

func (x *UpstreamResponse) Reset() {
	*x = UpstreamResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_apis_sm_v1_service_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UpstreamResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UpstreamResponse) ProtoMessage() {}

func (x *UpstreamResponse) ProtoReflect() protoreflect.Message {
	mi := &file_apis_sm_v1_service_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UpstreamResponse.ProtoReflect.Descriptor instead.
func (*UpstreamResponse) Descriptor() ([]byte, []int) {
	return file_apis_sm_v1_service_proto_rawDescGZIP(), []int{3}
}

func (x *UpstreamResponse) GetServices() []*Service {
	if x != nil {
		return x.Services
	}
	return nil
}

type Service struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name       string              `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Namespace  string              `protobuf:"bytes,2,opt,name=namespace,proto3" json:"namespace,omitempty"`
	Ports      []*Service_Port     `protobuf:"bytes,3,rep,name=ports,proto3" json:"ports,omitempty"`
	ClusterIps []string            `protobuf:"bytes,4,rep,name=cluster_ips,json=clusterIps,proto3" json:"cluster_ips,omitempty"`
	Endpoints  []*Service_Endpoint `protobuf:"bytes,5,rep,name=endpoints,proto3" json:"endpoints,omitempty"`
	Canaries   []*Service_Canary   `protobuf:"bytes,6,rep,name=canaries,proto3" json:"canaries,omitempty"`
	// deleted
	Deleted bool `protobuf:"varint,7,opt,name=deleted,proto3" json:"deleted,omitempty"`
}

func (x *Service) Reset() {
	*x = Service{}
	if protoimpl.UnsafeEnabled {
		mi := &file_apis_sm_v1_service_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Service) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Service) ProtoMessage() {}

func (x *Service) ProtoReflect() protoreflect.Message {
	mi := &file_apis_sm_v1_service_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Service.ProtoReflect.Descriptor instead.
func (*Service) Descriptor() ([]byte, []int) {
	return file_apis_sm_v1_service_proto_rawDescGZIP(), []int{4}
}

func (x *Service) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *Service) GetNamespace() string {
	if x != nil {
		return x.Namespace
	}
	return ""
}

func (x *Service) GetPorts() []*Service_Port {
	if x != nil {
		return x.Ports
	}
	return nil
}

func (x *Service) GetClusterIps() []string {
	if x != nil {
		return x.ClusterIps
	}
	return nil
}

func (x *Service) GetEndpoints() []*Service_Endpoint {
	if x != nil {
		return x.Endpoints
	}
	return nil
}

func (x *Service) GetCanaries() []*Service_Canary {
	if x != nil {
		return x.Canaries
	}
	return nil
}

func (x *Service) GetDeleted() bool {
	if x != nil {
		return x.Deleted
	}
	return false
}

type SignCertificateRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name  string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Token string `protobuf:"bytes,2,opt,name=token,proto3" json:"token,omitempty"`
	Csr   []byte `protobuf:"bytes,3,opt,name=csr,proto3" json:"csr,omitempty"`
}

func (x *SignCertificateRequest) Reset() {
	*x = SignCertificateRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_apis_sm_v1_service_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignCertificateRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignCertificateRequest) ProtoMessage() {}

func (x *SignCertificateRequest) ProtoReflect() protoreflect.Message {
	mi := &file_apis_sm_v1_service_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignCertificateRequest.ProtoReflect.Descriptor instead.
func (*SignCertificateRequest) Descriptor() ([]byte, []int) {
	return file_apis_sm_v1_service_proto_rawDescGZIP(), []int{5}
}

func (x *SignCertificateRequest) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *SignCertificateRequest) GetToken() string {
	if x != nil {
		return x.Token
	}
	return ""
}

func (x *SignCertificateRequest) GetCsr() []byte {
	if x != nil {
		return x.Csr
	}
	return nil
}

type SignCertificateResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Cert []byte `protobuf:"bytes,1,opt,name=cert,proto3" json:"cert,omitempty"`
	Ca   []byte `protobuf:"bytes,2,opt,name=ca,proto3" json:"ca,omitempty"`
}

func (x *SignCertificateResponse) Reset() {
	*x = SignCertificateResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_apis_sm_v1_service_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignCertificateResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignCertificateResponse) ProtoMessage() {}

func (x *SignCertificateResponse) ProtoReflect() protoreflect.Message {
	mi := &file_apis_sm_v1_service_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignCertificateResponse.ProtoReflect.Descriptor instead.
func (*SignCertificateResponse) Descriptor() ([]byte, []int) {
	return file_apis_sm_v1_service_proto_rawDescGZIP(), []int{6}
}

func (x *SignCertificateResponse) GetCert() []byte {
	if x != nil {
		return x.Cert
	}
	return nil
}

func (x *SignCertificateResponse) GetCa() []byte {
	if x != nil {
		return x.Ca
	}
	return nil
}

type Service_Port struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name       string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Port       int32  `protobuf:"varint,2,opt,name=port,proto3" json:"port,omitempty"`
	TargetPort int32  `protobuf:"varint,3,opt,name=target_port,json=targetPort,proto3" json:"target_port,omitempty"`
	Protocol   string `protobuf:"bytes,4,opt,name=protocol,proto3" json:"protocol,omitempty"`
}

func (x *Service_Port) Reset() {
	*x = Service_Port{}
	if protoimpl.UnsafeEnabled {
		mi := &file_apis_sm_v1_service_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Service_Port) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Service_Port) ProtoMessage() {}

func (x *Service_Port) ProtoReflect() protoreflect.Message {
	mi := &file_apis_sm_v1_service_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Service_Port.ProtoReflect.Descriptor instead.
func (*Service_Port) Descriptor() ([]byte, []int) {
	return file_apis_sm_v1_service_proto_rawDescGZIP(), []int{4, 0}
}

func (x *Service_Port) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *Service_Port) GetPort() int32 {
	if x != nil {
		return x.Port
	}
	return 0
}

func (x *Service_Port) GetTargetPort() int32 {
	if x != nil {
		return x.TargetPort
	}
	return 0
}

func (x *Service_Port) GetProtocol() string {
	if x != nil {
		return x.Protocol
	}
	return ""
}

type Service_Endpoint struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Addresses []string `protobuf:"bytes,1,rep,name=addresses,proto3" json:"addresses,omitempty"`
	Ready     bool     `protobuf:"varint,2,opt,name=ready,proto3" json:"ready,omitempty"`
	// We are ignoring serving and terminating for now
	PodName string `protobuf:"bytes,3,opt,name=pod_name,json=podName,proto3" json:"pod_name,omitempty"`
}

func (x *Service_Endpoint) Reset() {
	*x = Service_Endpoint{}
	if protoimpl.UnsafeEnabled {
		mi := &file_apis_sm_v1_service_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Service_Endpoint) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Service_Endpoint) ProtoMessage() {}

func (x *Service_Endpoint) ProtoReflect() protoreflect.Message {
	mi := &file_apis_sm_v1_service_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Service_Endpoint.ProtoReflect.Descriptor instead.
func (*Service_Endpoint) Descriptor() ([]byte, []int) {
	return file_apis_sm_v1_service_proto_rawDescGZIP(), []int{4, 1}
}

func (x *Service_Endpoint) GetAddresses() []string {
	if x != nil {
		return x.Addresses
	}
	return nil
}

func (x *Service_Endpoint) GetReady() bool {
	if x != nil {
		return x.Ready
	}
	return false
}

func (x *Service_Endpoint) GetPodName() string {
	if x != nil {
		return x.PodName
	}
	return ""
}

type Service_Canary struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name      string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Namespace string `protobuf:"bytes,2,opt,name=namespace,proto3" json:"namespace,omitempty"` // Empty string means the same namespace as the service
	Port      int32  `protobuf:"varint,3,opt,name=port,proto3" json:"port,omitempty"`          // Empty string means the same port as the service
	Weight    int32  `protobuf:"varint,4,opt,name=weight,proto3" json:"weight,omitempty"`      // 0-100
}

func (x *Service_Canary) Reset() {
	*x = Service_Canary{}
	if protoimpl.UnsafeEnabled {
		mi := &file_apis_sm_v1_service_proto_msgTypes[9]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Service_Canary) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Service_Canary) ProtoMessage() {}

func (x *Service_Canary) ProtoReflect() protoreflect.Message {
	mi := &file_apis_sm_v1_service_proto_msgTypes[9]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Service_Canary.ProtoReflect.Descriptor instead.
func (*Service_Canary) Descriptor() ([]byte, []int) {
	return file_apis_sm_v1_service_proto_rawDescGZIP(), []int{4, 2}
}

func (x *Service_Canary) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *Service_Canary) GetNamespace() string {
	if x != nil {
		return x.Namespace
	}
	return ""
}

func (x *Service_Canary) GetPort() int32 {
	if x != nil {
		return x.Port
	}
	return 0
}

func (x *Service_Canary) GetWeight() int32 {
	if x != nil {
		return x.Weight
	}
	return 0
}

var File_apis_sm_v1_service_proto protoreflect.FileDescriptor

var file_apis_sm_v1_service_proto_rawDesc = []byte{
	0x0a, 0x18, 0x61, 0x70, 0x69, 0x73, 0x2f, 0x73, 0x6d, 0x2f, 0x76, 0x31, 0x2f, 0x73, 0x65, 0x72,
	0x76, 0x69, 0x63, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x05, 0x73, 0x6d, 0x2e, 0x76,
	0x31, 0x22, 0x30, 0x0a, 0x12, 0x47, 0x65, 0x74, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x1a, 0x0a, 0x08, 0x73, 0x65, 0x72, 0x76, 0x69,
	0x63, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x09, 0x52, 0x08, 0x73, 0x65, 0x72, 0x76, 0x69,
	0x63, 0x65, 0x73, 0x22, 0x41, 0x0a, 0x13, 0x47, 0x65, 0x74, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63,
	0x65, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x2a, 0x0a, 0x08, 0x73, 0x65,
	0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x0e, 0x2e, 0x73,
	0x6d, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x52, 0x08, 0x73, 0x65,
	0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x22, 0x33, 0x0a, 0x0f, 0x55, 0x70, 0x73, 0x74, 0x72, 0x65,
	0x61, 0x6d, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x20, 0x0a, 0x0b, 0x73, 0x65, 0x72,
	0x76, 0x69, 0x63, 0x65, 0x4e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b,
	0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x4e, 0x61, 0x6d, 0x65, 0x22, 0x3e, 0x0a, 0x10, 0x55,
	0x70, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12,
	0x2a, 0x0a, 0x08, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28,
	0x0b, 0x32, 0x0e, 0x2e, 0x73, 0x6d, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63,
	0x65, 0x52, 0x08, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x22, 0xbb, 0x04, 0x0a, 0x07,
	0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x1c, 0x0a, 0x09, 0x6e,
	0x61, 0x6d, 0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09,
	0x6e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x12, 0x29, 0x0a, 0x05, 0x70, 0x6f, 0x72,
	0x74, 0x73, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x13, 0x2e, 0x73, 0x6d, 0x2e, 0x76, 0x31,
	0x2e, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x50, 0x6f, 0x72, 0x74, 0x52, 0x05, 0x70,
	0x6f, 0x72, 0x74, 0x73, 0x12, 0x1f, 0x0a, 0x0b, 0x63, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x5f,
	0x69, 0x70, 0x73, 0x18, 0x04, 0x20, 0x03, 0x28, 0x09, 0x52, 0x0a, 0x63, 0x6c, 0x75, 0x73, 0x74,
	0x65, 0x72, 0x49, 0x70, 0x73, 0x12, 0x35, 0x0a, 0x09, 0x65, 0x6e, 0x64, 0x70, 0x6f, 0x69, 0x6e,
	0x74, 0x73, 0x18, 0x05, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x17, 0x2e, 0x73, 0x6d, 0x2e, 0x76, 0x31,
	0x2e, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x45, 0x6e, 0x64, 0x70, 0x6f, 0x69, 0x6e,
	0x74, 0x52, 0x09, 0x65, 0x6e, 0x64, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x73, 0x12, 0x31, 0x0a, 0x08,
	0x63, 0x61, 0x6e, 0x61, 0x72, 0x69, 0x65, 0x73, 0x18, 0x06, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x15,
	0x2e, 0x73, 0x6d, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x43,
	0x61, 0x6e, 0x61, 0x72, 0x79, 0x52, 0x08, 0x63, 0x61, 0x6e, 0x61, 0x72, 0x69, 0x65, 0x73, 0x12,
	0x18, 0x0a, 0x07, 0x64, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x64, 0x18, 0x07, 0x20, 0x01, 0x28, 0x08,
	0x52, 0x07, 0x64, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x64, 0x1a, 0x6b, 0x0a, 0x04, 0x50, 0x6f, 0x72,
	0x74, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x70, 0x6f, 0x72, 0x74, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x05, 0x52, 0x04, 0x70, 0x6f, 0x72, 0x74, 0x12, 0x1f, 0x0a, 0x0b, 0x74, 0x61, 0x72,
	0x67, 0x65, 0x74, 0x5f, 0x70, 0x6f, 0x72, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x05, 0x52, 0x0a,
	0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x50, 0x6f, 0x72, 0x74, 0x12, 0x1a, 0x0a, 0x08, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x1a, 0x59, 0x0a, 0x08, 0x45, 0x6e, 0x64, 0x70, 0x6f, 0x69,
	0x6e, 0x74, 0x12, 0x1c, 0x0a, 0x09, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x65, 0x73, 0x18,
	0x01, 0x20, 0x03, 0x28, 0x09, 0x52, 0x09, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x65, 0x73,
	0x12, 0x14, 0x0a, 0x05, 0x72, 0x65, 0x61, 0x64, 0x79, 0x18, 0x02, 0x20, 0x01, 0x28, 0x08, 0x52,
	0x05, 0x72, 0x65, 0x61, 0x64, 0x79, 0x12, 0x19, 0x0a, 0x08, 0x70, 0x6f, 0x64, 0x5f, 0x6e, 0x61,
	0x6d, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x70, 0x6f, 0x64, 0x4e, 0x61, 0x6d,
	0x65, 0x1a, 0x66, 0x0a, 0x06, 0x43, 0x61, 0x6e, 0x61, 0x72, 0x79, 0x12, 0x12, 0x0a, 0x04, 0x6e,
	0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12,
	0x1c, 0x0a, 0x09, 0x6e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x09, 0x6e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x12, 0x12, 0x0a,
	0x04, 0x70, 0x6f, 0x72, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x05, 0x52, 0x04, 0x70, 0x6f, 0x72,
	0x74, 0x12, 0x16, 0x0a, 0x06, 0x77, 0x65, 0x69, 0x67, 0x68, 0x74, 0x18, 0x04, 0x20, 0x01, 0x28,
	0x05, 0x52, 0x06, 0x77, 0x65, 0x69, 0x67, 0x68, 0x74, 0x22, 0x54, 0x0a, 0x16, 0x53, 0x69, 0x67,
	0x6e, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x74, 0x6f, 0x6b, 0x65, 0x6e,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x12, 0x10, 0x0a,
	0x03, 0x63, 0x73, 0x72, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x03, 0x63, 0x73, 0x72, 0x22,
	0x3d, 0x0a, 0x17, 0x53, 0x69, 0x67, 0x6e, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61,
	0x74, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x63, 0x65,
	0x72, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x63, 0x65, 0x72, 0x74, 0x12, 0x0e,
	0x0a, 0x02, 0x63, 0x61, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x02, 0x63, 0x61, 0x32, 0xf5,
	0x01, 0x0a, 0x12, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x4d, 0x65, 0x73, 0x68, 0x53, 0x65,
	0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x46, 0x0a, 0x0b, 0x47, 0x65, 0x74, 0x53, 0x65, 0x72, 0x76,
	0x69, 0x63, 0x65, 0x73, 0x12, 0x19, 0x2e, 0x73, 0x6d, 0x2e, 0x76, 0x31, 0x2e, 0x47, 0x65, 0x74,
	0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a,
	0x1a, 0x2e, 0x73, 0x6d, 0x2e, 0x76, 0x31, 0x2e, 0x47, 0x65, 0x74, 0x53, 0x65, 0x72, 0x76, 0x69,
	0x63, 0x65, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x12, 0x43, 0x0a,
	0x0c, 0x47, 0x65, 0x74, 0x55, 0x70, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x73, 0x12, 0x16, 0x2e,
	0x73, 0x6d, 0x2e, 0x76, 0x31, 0x2e, 0x55, 0x70, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x17, 0x2e, 0x73, 0x6d, 0x2e, 0x76, 0x31, 0x2e, 0x55, 0x70,
	0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00,
	0x30, 0x01, 0x12, 0x52, 0x0a, 0x0f, 0x53, 0x69, 0x67, 0x6e, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66,
	0x69, 0x63, 0x61, 0x74, 0x65, 0x12, 0x1d, 0x2e, 0x73, 0x6d, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x69,
	0x67, 0x6e, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x1a, 0x1e, 0x2e, 0x73, 0x6d, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x69, 0x67,
	0x6e, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x42, 0x92, 0x01, 0x0a, 0x09, 0x63, 0x6f, 0x6d, 0x2e, 0x73,
	0x6d, 0x2e, 0x76, 0x31, 0x42, 0x0c, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x50, 0x72, 0x6f,
	0x74, 0x6f, 0x50, 0x01, 0x5a, 0x42, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d,
	0x2f, 0x72, 0x61, 0x6d, 0x6f, 0x6e, 0x62, 0x65, 0x72, 0x72, 0x75, 0x74, 0x74, 0x69, 0x2f, 0x64,
	0x69, 0x79, 0x2d, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2d, 0x6d, 0x65, 0x73, 0x68, 0x2f,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x67, 0x65, 0x6e, 0x2f, 0x61, 0x70, 0x69, 0x73, 0x2f, 0x73, 0x6d,
	0x2f, 0x76, 0x31, 0x3b, 0x73, 0x6d, 0x76, 0x31, 0xa2, 0x02, 0x03, 0x53, 0x58, 0x58, 0xaa, 0x02,
	0x05, 0x53, 0x6d, 0x2e, 0x56, 0x31, 0xca, 0x02, 0x05, 0x53, 0x6d, 0x5c, 0x56, 0x31, 0xe2, 0x02,
	0x11, 0x53, 0x6d, 0x5c, 0x56, 0x31, 0x5c, 0x47, 0x50, 0x42, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61,
	0x74, 0x61, 0xea, 0x02, 0x06, 0x53, 0x6d, 0x3a, 0x3a, 0x56, 0x31, 0x62, 0x06, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x33,
}

var (
	file_apis_sm_v1_service_proto_rawDescOnce sync.Once
	file_apis_sm_v1_service_proto_rawDescData = file_apis_sm_v1_service_proto_rawDesc
)

func file_apis_sm_v1_service_proto_rawDescGZIP() []byte {
	file_apis_sm_v1_service_proto_rawDescOnce.Do(func() {
		file_apis_sm_v1_service_proto_rawDescData = protoimpl.X.CompressGZIP(file_apis_sm_v1_service_proto_rawDescData)
	})
	return file_apis_sm_v1_service_proto_rawDescData
}

var file_apis_sm_v1_service_proto_msgTypes = make([]protoimpl.MessageInfo, 10)
var file_apis_sm_v1_service_proto_goTypes = []interface{}{
	(*GetServicesRequest)(nil),      // 0: sm.v1.GetServicesRequest
	(*GetServicesResponse)(nil),     // 1: sm.v1.GetServicesResponse
	(*UpstreamRequest)(nil),         // 2: sm.v1.UpstreamRequest
	(*UpstreamResponse)(nil),        // 3: sm.v1.UpstreamResponse
	(*Service)(nil),                 // 4: sm.v1.Service
	(*SignCertificateRequest)(nil),  // 5: sm.v1.SignCertificateRequest
	(*SignCertificateResponse)(nil), // 6: sm.v1.SignCertificateResponse
	(*Service_Port)(nil),            // 7: sm.v1.Service.Port
	(*Service_Endpoint)(nil),        // 8: sm.v1.Service.Endpoint
	(*Service_Canary)(nil),          // 9: sm.v1.Service.Canary
}
var file_apis_sm_v1_service_proto_depIdxs = []int32{
	4, // 0: sm.v1.GetServicesResponse.services:type_name -> sm.v1.Service
	4, // 1: sm.v1.UpstreamResponse.services:type_name -> sm.v1.Service
	7, // 2: sm.v1.Service.ports:type_name -> sm.v1.Service.Port
	8, // 3: sm.v1.Service.endpoints:type_name -> sm.v1.Service.Endpoint
	9, // 4: sm.v1.Service.canaries:type_name -> sm.v1.Service.Canary
	0, // 5: sm.v1.ServiceMeshService.GetServices:input_type -> sm.v1.GetServicesRequest
	2, // 6: sm.v1.ServiceMeshService.GetUpstreams:input_type -> sm.v1.UpstreamRequest
	5, // 7: sm.v1.ServiceMeshService.SignCertificate:input_type -> sm.v1.SignCertificateRequest
	1, // 8: sm.v1.ServiceMeshService.GetServices:output_type -> sm.v1.GetServicesResponse
	3, // 9: sm.v1.ServiceMeshService.GetUpstreams:output_type -> sm.v1.UpstreamResponse
	6, // 10: sm.v1.ServiceMeshService.SignCertificate:output_type -> sm.v1.SignCertificateResponse
	8, // [8:11] is the sub-list for method output_type
	5, // [5:8] is the sub-list for method input_type
	5, // [5:5] is the sub-list for extension type_name
	5, // [5:5] is the sub-list for extension extendee
	0, // [0:5] is the sub-list for field type_name
}

func init() { file_apis_sm_v1_service_proto_init() }
func file_apis_sm_v1_service_proto_init() {
	if File_apis_sm_v1_service_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_apis_sm_v1_service_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetServicesRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_apis_sm_v1_service_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetServicesResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_apis_sm_v1_service_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UpstreamRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_apis_sm_v1_service_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UpstreamResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_apis_sm_v1_service_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Service); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_apis_sm_v1_service_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignCertificateRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_apis_sm_v1_service_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignCertificateResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_apis_sm_v1_service_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Service_Port); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_apis_sm_v1_service_proto_msgTypes[8].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Service_Endpoint); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_apis_sm_v1_service_proto_msgTypes[9].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Service_Canary); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_apis_sm_v1_service_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   10,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_apis_sm_v1_service_proto_goTypes,
		DependencyIndexes: file_apis_sm_v1_service_proto_depIdxs,
		MessageInfos:      file_apis_sm_v1_service_proto_msgTypes,
	}.Build()
	File_apis_sm_v1_service_proto = out.File
	file_apis_sm_v1_service_proto_rawDesc = nil
	file_apis_sm_v1_service_proto_goTypes = nil
	file_apis_sm_v1_service_proto_depIdxs = nil
}
