// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: node.proto

package pb

import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"
import _ "github.com/gogo/protobuf/gogoproto"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion2 // please upgrade the proto package

// NodeType is an enum of possible node types
type NodeType int32

const (
	NodeType_INVALID   NodeType = 0
	NodeType_SATELLITE NodeType = 1
	NodeType_STORAGE   NodeType = 2
	NodeType_UPLINK    NodeType = 3
)

var NodeType_name = map[int32]string{
	0: "INVALID",
	1: "SATELLITE",
	2: "STORAGE",
	3: "UPLINK",
}
var NodeType_value = map[string]int32{
	"INVALID":   0,
	"SATELLITE": 1,
	"STORAGE":   2,
	"UPLINK":    3,
}

func (x NodeType) String() string {
	return proto.EnumName(NodeType_name, int32(x))
}
func (NodeType) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_node_442160371250321a, []int{0}
}

// NodeTransport is an enum of possible transports for the overlay network
type NodeTransport int32

const (
	NodeTransport_TCP_TLS_GRPC NodeTransport = 0
)

var NodeTransport_name = map[int32]string{
	0: "TCP_TLS_GRPC",
}
var NodeTransport_value = map[string]int32{
	"TCP_TLS_GRPC": 0,
}

func (x NodeTransport) String() string {
	return proto.EnumName(NodeTransport_name, int32(x))
}
func (NodeTransport) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_node_442160371250321a, []int{1}
}

//  NodeRestrictions contains all relevant data about a nodes ability to store data
type NodeRestrictions struct {
	FreeBandwidth        int64    `protobuf:"varint,1,opt,name=free_bandwidth,json=freeBandwidth,proto3" json:"free_bandwidth,omitempty"`
	FreeDisk             int64    `protobuf:"varint,2,opt,name=free_disk,json=freeDisk,proto3" json:"free_disk,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *NodeRestrictions) Reset()         { *m = NodeRestrictions{} }
func (m *NodeRestrictions) String() string { return proto.CompactTextString(m) }
func (*NodeRestrictions) ProtoMessage()    {}
func (*NodeRestrictions) Descriptor() ([]byte, []int) {
	return fileDescriptor_node_442160371250321a, []int{0}
}
func (m *NodeRestrictions) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_NodeRestrictions.Unmarshal(m, b)
}
func (m *NodeRestrictions) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_NodeRestrictions.Marshal(b, m, deterministic)
}
func (dst *NodeRestrictions) XXX_Merge(src proto.Message) {
	xxx_messageInfo_NodeRestrictions.Merge(dst, src)
}
func (m *NodeRestrictions) XXX_Size() int {
	return xxx_messageInfo_NodeRestrictions.Size(m)
}
func (m *NodeRestrictions) XXX_DiscardUnknown() {
	xxx_messageInfo_NodeRestrictions.DiscardUnknown(m)
}

var xxx_messageInfo_NodeRestrictions proto.InternalMessageInfo

func (m *NodeRestrictions) GetFreeBandwidth() int64 {
	if m != nil {
		return m.FreeBandwidth
	}
	return 0
}

func (m *NodeRestrictions) GetFreeDisk() int64 {
	if m != nil {
		return m.FreeDisk
	}
	return 0
}

// TODO move statdb.Update() stuff out of here
// Node represents a node in the overlay network
// Node is info for a updating a single storagenode, used in the Update rpc calls
type Node struct {
	Id                   NodeID            `protobuf:"bytes,1,opt,name=id,proto3,customtype=NodeID" json:"id"`
	Address              *NodeAddress      `protobuf:"bytes,2,opt,name=address" json:"address,omitempty"`
	Type                 NodeType          `protobuf:"varint,3,opt,name=type,proto3,enum=node.NodeType" json:"type,omitempty"`
	Restrictions         *NodeRestrictions `protobuf:"bytes,4,opt,name=restrictions" json:"restrictions,omitempty"`
	Reputation           *NodeStats        `protobuf:"bytes,5,opt,name=reputation" json:"reputation,omitempty"`
	Metadata             *NodeMetadata     `protobuf:"bytes,6,opt,name=metadata" json:"metadata,omitempty"`
	LatencyList          []int64           `protobuf:"varint,7,rep,packed,name=latency_list,json=latencyList" json:"latency_list,omitempty"`
	AuditSuccess         bool              `protobuf:"varint,8,opt,name=audit_success,json=auditSuccess,proto3" json:"audit_success,omitempty"`
	IsUp                 bool              `protobuf:"varint,9,opt,name=is_up,json=isUp,proto3" json:"is_up,omitempty"`
	UpdateLatency        bool              `protobuf:"varint,10,opt,name=update_latency,json=updateLatency,proto3" json:"update_latency,omitempty"`
	UpdateAuditSuccess   bool              `protobuf:"varint,11,opt,name=update_audit_success,json=updateAuditSuccess,proto3" json:"update_audit_success,omitempty"`
	UpdateUptime         bool              `protobuf:"varint,12,opt,name=update_uptime,json=updateUptime,proto3" json:"update_uptime,omitempty"`
	XXX_NoUnkeyedLiteral struct{}          `json:"-"`
	XXX_unrecognized     []byte            `json:"-"`
	XXX_sizecache        int32             `json:"-"`
}

func (m *Node) Reset()         { *m = Node{} }
func (m *Node) String() string { return proto.CompactTextString(m) }
func (*Node) ProtoMessage()    {}
func (*Node) Descriptor() ([]byte, []int) {
	return fileDescriptor_node_442160371250321a, []int{1}
}
func (m *Node) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Node.Unmarshal(m, b)
}
func (m *Node) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Node.Marshal(b, m, deterministic)
}
func (dst *Node) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Node.Merge(dst, src)
}
func (m *Node) XXX_Size() int {
	return xxx_messageInfo_Node.Size(m)
}
func (m *Node) XXX_DiscardUnknown() {
	xxx_messageInfo_Node.DiscardUnknown(m)
}

var xxx_messageInfo_Node proto.InternalMessageInfo

func (m *Node) GetAddress() *NodeAddress {
	if m != nil {
		return m.Address
	}
	return nil
}

func (m *Node) GetType() NodeType {
	if m != nil {
		return m.Type
	}
	return NodeType_INVALID
}

func (m *Node) GetRestrictions() *NodeRestrictions {
	if m != nil {
		return m.Restrictions
	}
	return nil
}

func (m *Node) GetReputation() *NodeStats {
	if m != nil {
		return m.Reputation
	}
	return nil
}

func (m *Node) GetMetadata() *NodeMetadata {
	if m != nil {
		return m.Metadata
	}
	return nil
}

func (m *Node) GetLatencyList() []int64 {
	if m != nil {
		return m.LatencyList
	}
	return nil
}

func (m *Node) GetAuditSuccess() bool {
	if m != nil {
		return m.AuditSuccess
	}
	return false
}

func (m *Node) GetIsUp() bool {
	if m != nil {
		return m.IsUp
	}
	return false
}

func (m *Node) GetUpdateLatency() bool {
	if m != nil {
		return m.UpdateLatency
	}
	return false
}

func (m *Node) GetUpdateAuditSuccess() bool {
	if m != nil {
		return m.UpdateAuditSuccess
	}
	return false
}

func (m *Node) GetUpdateUptime() bool {
	if m != nil {
		return m.UpdateUptime
	}
	return false
}

// NodeAddress contains the information needed to communicate with a node on the network
type NodeAddress struct {
	Transport            NodeTransport `protobuf:"varint,1,opt,name=transport,proto3,enum=node.NodeTransport" json:"transport,omitempty"`
	Address              string        `protobuf:"bytes,2,opt,name=address,proto3" json:"address,omitempty"`
	XXX_NoUnkeyedLiteral struct{}      `json:"-"`
	XXX_unrecognized     []byte        `json:"-"`
	XXX_sizecache        int32         `json:"-"`
}

func (m *NodeAddress) Reset()         { *m = NodeAddress{} }
func (m *NodeAddress) String() string { return proto.CompactTextString(m) }
func (*NodeAddress) ProtoMessage()    {}
func (*NodeAddress) Descriptor() ([]byte, []int) {
	return fileDescriptor_node_442160371250321a, []int{2}
}
func (m *NodeAddress) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_NodeAddress.Unmarshal(m, b)
}
func (m *NodeAddress) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_NodeAddress.Marshal(b, m, deterministic)
}
func (dst *NodeAddress) XXX_Merge(src proto.Message) {
	xxx_messageInfo_NodeAddress.Merge(dst, src)
}
func (m *NodeAddress) XXX_Size() int {
	return xxx_messageInfo_NodeAddress.Size(m)
}
func (m *NodeAddress) XXX_DiscardUnknown() {
	xxx_messageInfo_NodeAddress.DiscardUnknown(m)
}

var xxx_messageInfo_NodeAddress proto.InternalMessageInfo

func (m *NodeAddress) GetTransport() NodeTransport {
	if m != nil {
		return m.Transport
	}
	return NodeTransport_TCP_TLS_GRPC
}

func (m *NodeAddress) GetAddress() string {
	if m != nil {
		return m.Address
	}
	return ""
}

// NodeStats is the reputation characteristics of a node
type NodeStats struct {
	NodeId               NodeID   `protobuf:"bytes,1,opt,name=node_id,json=nodeId,proto3,customtype=NodeID" json:"node_id"`
	Latency_90           int64    `protobuf:"varint,2,opt,name=latency_90,json=latency90,proto3" json:"latency_90,omitempty"`
	AuditSuccessRatio    float64  `protobuf:"fixed64,3,opt,name=audit_success_ratio,json=auditSuccessRatio,proto3" json:"audit_success_ratio,omitempty"`
	UptimeRatio          float64  `protobuf:"fixed64,4,opt,name=uptime_ratio,json=uptimeRatio,proto3" json:"uptime_ratio,omitempty"`
	AuditCount           int64    `protobuf:"varint,5,opt,name=audit_count,json=auditCount,proto3" json:"audit_count,omitempty"`
	AuditSuccessCount    int64    `protobuf:"varint,6,opt,name=audit_success_count,json=auditSuccessCount,proto3" json:"audit_success_count,omitempty"`
	UptimeCount          int64    `protobuf:"varint,7,opt,name=uptime_count,json=uptimeCount,proto3" json:"uptime_count,omitempty"`
	UptimeSuccessCount   int64    `protobuf:"varint,8,opt,name=uptime_success_count,json=uptimeSuccessCount,proto3" json:"uptime_success_count,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *NodeStats) Reset()         { *m = NodeStats{} }
func (m *NodeStats) String() string { return proto.CompactTextString(m) }
func (*NodeStats) ProtoMessage()    {}
func (*NodeStats) Descriptor() ([]byte, []int) {
	return fileDescriptor_node_442160371250321a, []int{3}
}
func (m *NodeStats) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_NodeStats.Unmarshal(m, b)
}
func (m *NodeStats) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_NodeStats.Marshal(b, m, deterministic)
}
func (dst *NodeStats) XXX_Merge(src proto.Message) {
	xxx_messageInfo_NodeStats.Merge(dst, src)
}
func (m *NodeStats) XXX_Size() int {
	return xxx_messageInfo_NodeStats.Size(m)
}
func (m *NodeStats) XXX_DiscardUnknown() {
	xxx_messageInfo_NodeStats.DiscardUnknown(m)
}

var xxx_messageInfo_NodeStats proto.InternalMessageInfo

func (m *NodeStats) GetLatency_90() int64 {
	if m != nil {
		return m.Latency_90
	}
	return 0
}

func (m *NodeStats) GetAuditSuccessRatio() float64 {
	if m != nil {
		return m.AuditSuccessRatio
	}
	return 0
}

func (m *NodeStats) GetUptimeRatio() float64 {
	if m != nil {
		return m.UptimeRatio
	}
	return 0
}

func (m *NodeStats) GetAuditCount() int64 {
	if m != nil {
		return m.AuditCount
	}
	return 0
}

func (m *NodeStats) GetAuditSuccessCount() int64 {
	if m != nil {
		return m.AuditSuccessCount
	}
	return 0
}

func (m *NodeStats) GetUptimeCount() int64 {
	if m != nil {
		return m.UptimeCount
	}
	return 0
}

func (m *NodeStats) GetUptimeSuccessCount() int64 {
	if m != nil {
		return m.UptimeSuccessCount
	}
	return 0
}

type NodeMetadata struct {
	Email                string   `protobuf:"bytes,1,opt,name=email,proto3" json:"email,omitempty"`
	Wallet               string   `protobuf:"bytes,2,opt,name=wallet,proto3" json:"wallet,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *NodeMetadata) Reset()         { *m = NodeMetadata{} }
func (m *NodeMetadata) String() string { return proto.CompactTextString(m) }
func (*NodeMetadata) ProtoMessage()    {}
func (*NodeMetadata) Descriptor() ([]byte, []int) {
	return fileDescriptor_node_442160371250321a, []int{4}
}
func (m *NodeMetadata) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_NodeMetadata.Unmarshal(m, b)
}
func (m *NodeMetadata) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_NodeMetadata.Marshal(b, m, deterministic)
}
func (dst *NodeMetadata) XXX_Merge(src proto.Message) {
	xxx_messageInfo_NodeMetadata.Merge(dst, src)
}
func (m *NodeMetadata) XXX_Size() int {
	return xxx_messageInfo_NodeMetadata.Size(m)
}
func (m *NodeMetadata) XXX_DiscardUnknown() {
	xxx_messageInfo_NodeMetadata.DiscardUnknown(m)
}

var xxx_messageInfo_NodeMetadata proto.InternalMessageInfo

func (m *NodeMetadata) GetEmail() string {
	if m != nil {
		return m.Email
	}
	return ""
}

func (m *NodeMetadata) GetWallet() string {
	if m != nil {
		return m.Wallet
	}
	return ""
}

func init() {
	proto.RegisterType((*NodeRestrictions)(nil), "node.NodeRestrictions")
	proto.RegisterType((*Node)(nil), "node.Node")
	proto.RegisterType((*NodeAddress)(nil), "node.NodeAddress")
	proto.RegisterType((*NodeStats)(nil), "node.NodeStats")
	proto.RegisterType((*NodeMetadata)(nil), "node.NodeMetadata")
	proto.RegisterEnum("node.NodeType", NodeType_name, NodeType_value)
	proto.RegisterEnum("node.NodeTransport", NodeTransport_name, NodeTransport_value)
}

func init() { proto.RegisterFile("node.proto", fileDescriptor_node_442160371250321a) }

var fileDescriptor_node_442160371250321a = []byte{
	// 642 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x74, 0x94, 0xcf, 0x4e, 0xdb, 0x40,
	0x10, 0xc6, 0x49, 0x62, 0x9c, 0x78, 0xec, 0xa4, 0x66, 0x40, 0xc8, 0x6a, 0xd5, 0x12, 0x82, 0xaa,
	0x46, 0x54, 0x4a, 0x29, 0x3d, 0x51, 0x55, 0xaa, 0xc2, 0x1f, 0xa1, 0xa8, 0x2e, 0x45, 0x9b, 0xc0,
	0x81, 0x8b, 0x65, 0xe2, 0x2d, 0x5d, 0x11, 0x62, 0xcb, 0x5e, 0x0b, 0xf1, 0x86, 0x3d, 0xf4, 0x09,
	0x7a, 0xe0, 0x15, 0xfa, 0x0a, 0xd5, 0xce, 0x3a, 0xc4, 0x56, 0xd5, 0x5b, 0xf6, 0xfb, 0x7e, 0x9e,
	0xf1, 0xce, 0x37, 0x31, 0xc0, 0x3c, 0x8e, 0xf8, 0x20, 0x49, 0x63, 0x19, 0xa3, 0xa1, 0x7e, 0x3f,
	0x87, 0x9b, 0xf8, 0x26, 0xd6, 0x4a, 0xef, 0x12, 0xdc, 0xb3, 0x38, 0xe2, 0x8c, 0x67, 0x32, 0x15,
	0x53, 0x29, 0xe2, 0x79, 0x86, 0xaf, 0xa1, 0xf3, 0x3d, 0xe5, 0x3c, 0xb8, 0x0e, 0xe7, 0xd1, 0xbd,
	0x88, 0xe4, 0x0f, 0xaf, 0xd6, 0xad, 0xf5, 0x1b, 0xac, 0xad, 0xd4, 0xc3, 0x85, 0x88, 0x2f, 0xc0,
	0x22, 0x2c, 0x12, 0xd9, 0xad, 0x57, 0x27, 0xa2, 0xa5, 0x84, 0x63, 0x91, 0xdd, 0xf6, 0xfe, 0x34,
	0xc0, 0x50, 0x85, 0xf1, 0x15, 0xd4, 0x45, 0x44, 0x05, 0x9c, 0xc3, 0xce, 0xcf, 0xc7, 0xad, 0x95,
	0xdf, 0x8f, 0x5b, 0xa6, 0x72, 0x46, 0xc7, 0xac, 0x2e, 0x22, 0x7c, 0x0b, 0xcd, 0x30, 0x8a, 0x52,
	0x9e, 0x65, 0x54, 0xc3, 0xde, 0x5f, 0x1b, 0xd0, 0x0b, 0x2b, 0x64, 0xa8, 0x0d, 0xb6, 0x20, 0xb0,
	0x07, 0x86, 0x7c, 0x48, 0xb8, 0xd7, 0xe8, 0xd6, 0xfa, 0x9d, 0xfd, 0xce, 0x92, 0x9c, 0x3c, 0x24,
	0x9c, 0x91, 0x87, 0x1f, 0xc1, 0x49, 0x4b, 0xb7, 0xf1, 0x0c, 0xaa, 0xba, 0xb9, 0x64, 0xcb, 0x77,
	0x65, 0x15, 0x16, 0xdf, 0x01, 0xa4, 0x3c, 0xc9, 0x65, 0xa8, 0x8e, 0xde, 0x2a, 0x3d, 0xf9, 0x6c,
	0xf9, 0xe4, 0x58, 0x86, 0x32, 0x63, 0x25, 0x04, 0x07, 0xd0, 0xba, 0xe3, 0x32, 0x8c, 0x42, 0x19,
	0x7a, 0x26, 0xe1, 0xb8, 0xc4, 0xbf, 0x16, 0x0e, 0x7b, 0x62, 0x70, 0x1b, 0x9c, 0x59, 0x28, 0xf9,
	0x7c, 0xfa, 0x10, 0xcc, 0x44, 0x26, 0xbd, 0x66, 0xb7, 0xd1, 0x6f, 0x30, 0xbb, 0xd0, 0x7c, 0x91,
	0x49, 0xdc, 0x81, 0x76, 0x98, 0x47, 0x42, 0x06, 0x59, 0x3e, 0x9d, 0xaa, 0xb1, 0xb4, 0xba, 0xb5,
	0x7e, 0x8b, 0x39, 0x24, 0x8e, 0xb5, 0x86, 0xeb, 0xb0, 0x2a, 0xb2, 0x20, 0x4f, 0x3c, 0x8b, 0x4c,
	0x43, 0x64, 0x17, 0x89, 0xca, 0x2d, 0x4f, 0xa2, 0x50, 0xf2, 0xa0, 0xa8, 0xe7, 0x01, 0xb9, 0x6d,
	0xad, 0xfa, 0x5a, 0xc4, 0x3d, 0xd8, 0x28, 0xb0, 0x6a, 0x1f, 0x9b, 0x60, 0xd4, 0xde, 0xb0, 0xdc,
	0x6d, 0x07, 0x8a, 0x12, 0x41, 0x9e, 0x48, 0x71, 0xc7, 0x3d, 0x47, 0xbf, 0x92, 0x16, 0x2f, 0x48,
	0xeb, 0x5d, 0x81, 0x5d, 0xca, 0x0c, 0xdf, 0x83, 0x25, 0xd3, 0x70, 0x9e, 0x25, 0x71, 0x2a, 0x29,
	0xfe, 0xce, 0xfe, 0x7a, 0x29, 0xaf, 0x85, 0xc5, 0x96, 0x14, 0x7a, 0xd5, 0x55, 0xb0, 0x9e, 0x72,
	0xef, 0xfd, 0xaa, 0x83, 0xf5, 0x14, 0x00, 0xbe, 0x81, 0xa6, 0x2a, 0x14, 0xfc, 0x77, 0xaf, 0x4c,
	0x65, 0x8f, 0x22, 0x7c, 0x09, 0xb0, 0x98, 0xf6, 0xc1, 0x5e, 0xb1, 0xa2, 0x56, 0xa1, 0x1c, 0xec,
	0xe1, 0x00, 0xd6, 0x2b, 0x13, 0x08, 0x52, 0x15, 0x2a, 0x2d, 0x57, 0x8d, 0xad, 0x95, 0xe7, 0xcd,
	0x94, 0xa1, 0xc2, 0xd3, 0xf7, 0x2f, 0x40, 0x83, 0x40, 0x5b, 0x6b, 0x1a, 0xd9, 0x02, 0x5b, 0x97,
	0x9c, 0xc6, 0xf9, 0x5c, 0xd2, 0x06, 0x35, 0x18, 0x90, 0x74, 0xa4, 0x94, 0x7f, 0x7b, 0x6a, 0xd0,
	0x24, 0xb0, 0xd2, 0x53, 0xf3, 0xcb, 0x9e, 0x1a, 0x6c, 0x12, 0x58, 0xf4, 0xd4, 0x08, 0xe5, 0x49,
	0x48, 0xb5, 0x66, 0x8b, 0x50, 0xd4, 0x5e, 0xb9, 0x68, 0xef, 0x13, 0x38, 0xe5, 0xfd, 0xc4, 0x0d,
	0x58, 0xe5, 0x77, 0xa1, 0x98, 0xd1, 0x38, 0x2d, 0xa6, 0x0f, 0xb8, 0x09, 0xe6, 0x7d, 0x38, 0x9b,
	0x71, 0x59, 0xa4, 0x51, 0x9c, 0x76, 0x3f, 0x43, 0x6b, 0xf1, 0x97, 0x43, 0x1b, 0x9a, 0xa3, 0xb3,
	0xcb, 0xa1, 0x3f, 0x3a, 0x76, 0x57, 0xb0, 0x0d, 0xd6, 0x78, 0x38, 0x39, 0xf1, 0xfd, 0xd1, 0xe4,
	0xc4, 0xad, 0x29, 0x6f, 0x3c, 0xf9, 0xc6, 0x86, 0xa7, 0x27, 0x6e, 0x1d, 0x01, 0xcc, 0x8b, 0x73,
	0x7f, 0x74, 0xf6, 0xc5, 0x6d, 0xec, 0x6e, 0x43, 0xbb, 0xb2, 0x03, 0xe8, 0x82, 0x33, 0x39, 0x3a,
	0x0f, 0x26, 0xfe, 0x38, 0x38, 0x65, 0xe7, 0x47, 0xee, 0xca, 0xa1, 0x71, 0x55, 0x4f, 0xae, 0xaf,
	0x4d, 0xfa, 0x46, 0x7d, 0xf8, 0x1b, 0x00, 0x00, 0xff, 0xff, 0xa4, 0x40, 0x85, 0x29, 0xc3, 0x04,
	0x00, 0x00,
}
