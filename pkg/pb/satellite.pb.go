// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: satellite.proto

package pb

import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"

import (
	context "golang.org/x/net/context"
	grpc "google.golang.org/grpc"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion2 // please upgrade the proto package

type FileFealthRequest struct {
	FileId               []byte   `protobuf:"bytes,1,opt,name=file_id,json=fileId,proto3" json:"file_id,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *FileFealthRequest) Reset()         { *m = FileFealthRequest{} }
func (m *FileFealthRequest) String() string { return proto.CompactTextString(m) }
func (*FileFealthRequest) ProtoMessage()    {}
func (*FileFealthRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_satellite_a33b94433832ab6f, []int{0}
}
func (m *FileFealthRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_FileFealthRequest.Unmarshal(m, b)
}
func (m *FileFealthRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_FileFealthRequest.Marshal(b, m, deterministic)
}
func (dst *FileFealthRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_FileFealthRequest.Merge(dst, src)
}
func (m *FileFealthRequest) XXX_Size() int {
	return xxx_messageInfo_FileFealthRequest.Size(m)
}
func (m *FileFealthRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_FileFealthRequest.DiscardUnknown(m)
}

var xxx_messageInfo_FileFealthRequest proto.InternalMessageInfo

func (m *FileFealthRequest) GetFileId() []byte {
	if m != nil {
		return m.FileId
	}
	return nil
}

type FileHealthResponse struct {
	Segments             []*FileHealthResponse_SegmentInfo `protobuf:"bytes,1,rep,name=segments,proto3" json:"segments,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                          `json:"-"`
	XXX_unrecognized     []byte                            `json:"-"`
	XXX_sizecache        int32                             `json:"-"`
}

func (m *FileHealthResponse) Reset()         { *m = FileHealthResponse{} }
func (m *FileHealthResponse) String() string { return proto.CompactTextString(m) }
func (*FileHealthResponse) ProtoMessage()    {}
func (*FileHealthResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_satellite_a33b94433832ab6f, []int{1}
}
func (m *FileHealthResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_FileHealthResponse.Unmarshal(m, b)
}
func (m *FileHealthResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_FileHealthResponse.Marshal(b, m, deterministic)
}
func (dst *FileHealthResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_FileHealthResponse.Merge(dst, src)
}
func (m *FileHealthResponse) XXX_Size() int {
	return xxx_messageInfo_FileHealthResponse.Size(m)
}
func (m *FileHealthResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_FileHealthResponse.DiscardUnknown(m)
}

var xxx_messageInfo_FileHealthResponse proto.InternalMessageInfo

func (m *FileHealthResponse) GetSegments() []*FileHealthResponse_SegmentInfo {
	if m != nil {
		return m.Segments
	}
	return nil
}

type FileHealthResponse_SegmentInfo struct {
	GoodNodes            int64    `protobuf:"varint,1,opt,name=good_nodes,json=goodNodes,proto3" json:"good_nodes,omitempty"`
	BadNodes             int64    `protobuf:"varint,2,opt,name=bad_nodes,json=badNodes,proto3" json:"bad_nodes,omitempty"`
	OfflineNodes         int64    `protobuf:"varint,3,opt,name=offline_nodes,json=offlineNodes,proto3" json:"offline_nodes,omitempty"`
	BelowRecover         int64    `protobuf:"varint,4,opt,name=below_recover,json=belowRecover,proto3" json:"below_recover,omitempty"`
	BelowRepair          int64    `protobuf:"varint,5,opt,name=below_repair,json=belowRepair,proto3" json:"below_repair,omitempty"`
	BelowSuccess         int64    `protobuf:"varint,6,opt,name=below_success,json=belowSuccess,proto3" json:"below_success,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *FileHealthResponse_SegmentInfo) Reset()         { *m = FileHealthResponse_SegmentInfo{} }
func (m *FileHealthResponse_SegmentInfo) String() string { return proto.CompactTextString(m) }
func (*FileHealthResponse_SegmentInfo) ProtoMessage()    {}
func (*FileHealthResponse_SegmentInfo) Descriptor() ([]byte, []int) {
	return fileDescriptor_satellite_a33b94433832ab6f, []int{1, 0}
}
func (m *FileHealthResponse_SegmentInfo) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_FileHealthResponse_SegmentInfo.Unmarshal(m, b)
}
func (m *FileHealthResponse_SegmentInfo) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_FileHealthResponse_SegmentInfo.Marshal(b, m, deterministic)
}
func (dst *FileHealthResponse_SegmentInfo) XXX_Merge(src proto.Message) {
	xxx_messageInfo_FileHealthResponse_SegmentInfo.Merge(dst, src)
}
func (m *FileHealthResponse_SegmentInfo) XXX_Size() int {
	return xxx_messageInfo_FileHealthResponse_SegmentInfo.Size(m)
}
func (m *FileHealthResponse_SegmentInfo) XXX_DiscardUnknown() {
	xxx_messageInfo_FileHealthResponse_SegmentInfo.DiscardUnknown(m)
}

var xxx_messageInfo_FileHealthResponse_SegmentInfo proto.InternalMessageInfo

func (m *FileHealthResponse_SegmentInfo) GetGoodNodes() int64 {
	if m != nil {
		return m.GoodNodes
	}
	return 0
}

func (m *FileHealthResponse_SegmentInfo) GetBadNodes() int64 {
	if m != nil {
		return m.BadNodes
	}
	return 0
}

func (m *FileHealthResponse_SegmentInfo) GetOfflineNodes() int64 {
	if m != nil {
		return m.OfflineNodes
	}
	return 0
}

func (m *FileHealthResponse_SegmentInfo) GetBelowRecover() int64 {
	if m != nil {
		return m.BelowRecover
	}
	return 0
}

func (m *FileHealthResponse_SegmentInfo) GetBelowRepair() int64 {
	if m != nil {
		return m.BelowRepair
	}
	return 0
}

func (m *FileHealthResponse_SegmentInfo) GetBelowSuccess() int64 {
	if m != nil {
		return m.BelowSuccess
	}
	return 0
}

func init() {
	proto.RegisterType((*FileFealthRequest)(nil), "satellite.FileFealthRequest")
	proto.RegisterType((*FileHealthResponse)(nil), "satellite.FileHealthResponse")
	proto.RegisterType((*FileHealthResponse_SegmentInfo)(nil), "satellite.FileHealthResponse.SegmentInfo")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// SatelliteClient is the client API for Satellite service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type SatelliteClient interface {
	Health(ctx context.Context, in *FileFealthRequest, opts ...grpc.CallOption) (*FileHealthResponse, error)
}

type satelliteClient struct {
	cc *grpc.ClientConn
}

func NewSatelliteClient(cc *grpc.ClientConn) SatelliteClient {
	return &satelliteClient{cc}
}

func (c *satelliteClient) Health(ctx context.Context, in *FileFealthRequest, opts ...grpc.CallOption) (*FileHealthResponse, error) {
	out := new(FileHealthResponse)
	err := c.cc.Invoke(ctx, "/satellite.Satellite/Health", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// SatelliteServer is the server API for Satellite service.
type SatelliteServer interface {
	Health(context.Context, *FileFealthRequest) (*FileHealthResponse, error)
}

func RegisterSatelliteServer(s *grpc.Server, srv SatelliteServer) {
	s.RegisterService(&_Satellite_serviceDesc, srv)
}

func _Satellite_Health_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(FileFealthRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SatelliteServer).Health(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/satellite.Satellite/Health",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SatelliteServer).Health(ctx, req.(*FileFealthRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _Satellite_serviceDesc = grpc.ServiceDesc{
	ServiceName: "satellite.Satellite",
	HandlerType: (*SatelliteServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Health",
			Handler:    _Satellite_Health_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "satellite.proto",
}

func init() { proto.RegisterFile("satellite.proto", fileDescriptor_satellite_a33b94433832ab6f) }

var fileDescriptor_satellite_a33b94433832ab6f = []byte{
	// 292 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x7c, 0x91, 0xcf, 0x4e, 0x83, 0x40,
	0x10, 0xc6, 0x05, 0x2a, 0x96, 0x01, 0x63, 0xdc, 0x8b, 0xa4, 0xda, 0xa4, 0xe2, 0xa5, 0x26, 0x86,
	0x43, 0x7d, 0x03, 0x13, 0xab, 0xbd, 0x78, 0x00, 0x4f, 0x5e, 0x08, 0x7f, 0x86, 0xba, 0xc9, 0xca,
	0x22, 0xbb, 0xd5, 0x67, 0xf3, 0x59, 0x7c, 0x19, 0xc3, 0xb2, 0xd0, 0xaa, 0x49, 0x8f, 0xfc, 0xbe,
	0xdf, 0x0c, 0x9b, 0x6f, 0xe0, 0x44, 0xa4, 0x12, 0x19, 0xa3, 0x12, 0xc3, 0xba, 0xe1, 0x92, 0x13,
	0x67, 0x00, 0xc1, 0x0d, 0x9c, 0x2e, 0x29, 0xc3, 0x25, 0xa6, 0x4c, 0xbe, 0x46, 0xf8, 0xbe, 0x41,
	0x21, 0xc9, 0x19, 0x1c, 0x95, 0x94, 0x61, 0x42, 0x0b, 0xdf, 0x98, 0x19, 0x73, 0x2f, 0xb2, 0xdb,
	0xcf, 0x55, 0x11, 0x7c, 0x99, 0x40, 0x5a, 0xfd, 0x51, 0xeb, 0xa2, 0xe6, 0x95, 0x40, 0x72, 0x0f,
	0x63, 0x81, 0xeb, 0x37, 0xac, 0xa4, 0xf0, 0x8d, 0x99, 0x35, 0x77, 0x17, 0xd7, 0xe1, 0xf6, 0x9f,
	0xff, 0x07, 0xc2, 0xb8, 0xb3, 0x57, 0x55, 0xc9, 0xa3, 0x61, 0x74, 0xf2, 0x6d, 0x80, 0xbb, 0x93,
	0x90, 0x29, 0xc0, 0x9a, 0xf3, 0x22, 0xa9, 0x78, 0x81, 0x42, 0xbd, 0xc4, 0x8a, 0x9c, 0x96, 0x3c,
	0xb5, 0x80, 0x9c, 0x83, 0x93, 0xa5, 0x7d, 0x6a, 0xaa, 0x74, 0x9c, 0xa5, 0x3a, 0xbc, 0x82, 0x63,
	0x5e, 0x96, 0x8c, 0x56, 0xa8, 0x05, 0x4b, 0x09, 0x9e, 0x86, 0x83, 0x94, 0x21, 0xe3, 0x9f, 0x49,
	0x83, 0x39, 0xff, 0xc0, 0xc6, 0x1f, 0x75, 0x92, 0x82, 0x51, 0xc7, 0xc8, 0x25, 0x78, 0xbd, 0x54,
	0xa7, 0xb4, 0xf1, 0x0f, 0x95, 0xe3, 0x6a, 0xa7, 0x45, 0xdb, 0x3d, 0x62, 0x93, 0xe7, 0x28, 0x84,
	0x6f, 0xef, 0xec, 0x89, 0x3b, 0xb6, 0x78, 0x06, 0x27, 0xee, 0x3b, 0x21, 0x0f, 0x60, 0x77, 0x95,
	0x90, 0x8b, 0x3f, 0x4d, 0xfd, 0xba, 0xc4, 0x64, 0xba, 0xb7, 0xc7, 0xe0, 0xe0, 0x6e, 0xf4, 0x62,
	0xd6, 0x59, 0x66, 0xab, 0xbb, 0xde, 0xfe, 0x04, 0x00, 0x00, 0xff, 0xff, 0xf6, 0xbd, 0xab, 0x0f,
	0xea, 0x01, 0x00, 0x00,
}
