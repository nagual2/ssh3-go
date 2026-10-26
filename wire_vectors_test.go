package ssh3

import (
	"encoding/hex"
	"fmt"
	"net"
	"testing"

	"github.com/francoismichel/ssh3/compress"
	"github.com/francoismichel/ssh3/message"
	"github.com/francoismichel/ssh3/util"
)

// TestDumpWireVectors prints the canonical byte encoding of the SSH3 wire
// structures the browser client re-implements in TypeScript. Run with
//
//	go test -run TestDumpWireVectors -v ./
//
// and paste the output into wasm-tunnel's test fixtures. The encoders are
// unexported, so the dumper has to live in the root package.
func TestDumpWireVectors(t *testing.T) {
	dump := func(name string, b []byte) {
		fmt.Printf("VECTOR %s = %s\n", name, hex.EncodeToString(b))
	}

	dump("varint_0", util.AppendVarInt(nil, 0))
	dump("varint_1", util.AppendVarInt(nil, 1))
	dump("varint_63", util.AppendVarInt(nil, 63))
	dump("varint_64", util.AppendVarInt(nil, 64))
	dump("varint_16383", util.AppendVarInt(nil, 16383))
	dump("varint_16384", util.AppendVarInt(nil, 16384))
	dump("varint_1073741823", util.AppendVarInt(nil, 1073741823))
	dump("varint_1073741824", util.AppendVarInt(nil, 1073741824))
	dump("varint_4611686018427387903", util.AppendVarInt(nil, 4611686018427387903))

	dump("sshstring_empty", sshString(t, ""))
	dump("sshstring_direct_tcp", sshString(t, "direct-tcp"))
	dump("sshstring_exec", sshString(t, "exec"))
	dump("sshstring_140", sshString(t, strings140()))

	// Channel header for a direct-tcp channel towards an IPv4 target.
	dump("channel_header_tcp_ipv4", buildHeader(
		4, "direct-tcp", 30000,
		buildForwardingChannelAdditionalBytes(net.ParseIP("192.0.2.10").To4(), 443),
	))
	// Same, but a large conversation stream id and an IPv6 target.
	dump("channel_header_tcp_ipv6", buildHeader(
		64, "direct-tcp", 65536,
		buildForwardingChannelAdditionalBytes(net.ParseIP("2001:db8::1").To16(), 8443),
	))
	// UDP forwarding channel, same layout.
	dump("channel_header_udp_ipv4", buildHeader(
		8, "direct-udp", 30000,
		buildForwardingChannelAdditionalBytes(net.ParseIP("192.0.2.10").To4(), 53),
	))
	// A plain session channel carries no address tail.
	dump("channel_header_session", buildHeader(0, "session", 30000, nil))

	dump("open_confirmation_30000", writeMessage(t, &message.ChannelOpenConfirmationMessage{MaxPacketSize: 30000}))
	dump("open_failure", writeMessage(t, &message.ChannelOpenFailureMessage{
		ReasonCode:       2,
		ErrorMessageUTF8: "connection refused",
		LanguageTag:      "",
	}))
	dump("channel_data", writeMessage(t, &message.DataOrExtendedDataMessage{
		DataType: message.SSH_EXTENDED_DATA_NONE,
		Data:     "hello",
	}))
	dump("channel_extended_data", writeMessage(t, &message.DataOrExtendedDataMessage{
		DataType: message.SSH_EXTENDED_DATA_STDERR,
		Data:     "err",
	}))
	// Zero-copy header: MarshalHeader(len) + payload must equal channel_data.
	dump("channel_data_header_5", (&message.DataOrExtendedDataMessage{
		DataType: message.SSH_EXTENDED_DATA_NONE,
	}).MarshalHeader(5))
	dump("channel_request_exec", writeMessage(t, &message.ChannelRequestMessage{
		WantReply:      false,
		ChannelRequest: &message.ExecRequest{Command: "uptime"},
	}))

	// Reverse forwarding (-R) payloads, carried as channel data on a
	// "reverse-forward" control channel.
	dump("channel_header_forwarded_tcp", buildHeader(
		4, "forwarded-tcp", 30000,
		buildForwardingChannelAdditionalBytes(net.ParseIP("127.0.0.1").To4(), 8080),
	))
	dump("reverse_forward_request_tcp", writeMessage(t, &message.RequestReverseForward{
		Protocol:      util.SSHForwardingProtocolTCP,
		BindAddress:   "127.0.0.1",
		BindPort:      8080,
		TargetAddress: "192.0.2.10",
		TargetPort:    80,
	}))
	dump("reverse_forward_request_udp_wildcard", writeMessage(t, &message.RequestReverseForward{
		Protocol:      util.SSHProtocolUDP,
		BindAddress:   "*",
		BindPort:      53,
		TargetAddress: "2001:db8::1",
		TargetPort:    53,
	}))
	dump("reverse_forward_reply_ok", writeMessage(t, &message.ReverseForwardReply{BoundPort: 8080}))
	dump("reverse_forward_reply_error", writeMessage(t, &message.ReverseForwardReply{
		BoundPort: 0,
		ErrorUTF8: "bind: address already in use",
	}))

	// Dynamic SOCKS forwarding (-D) payloads. Like the -R ones, they travel as
	// channel data behind a varint(version) | varint(kind) prefix: kind 1/2 on
	// the "dynamic-forward" control channel, kind 3/4 on each
	// "dynamic-forward-tcp" channel.
	dump("channel_header_dynamic_forward_control", buildHeader(4, message.ChannelTypeDynamicForward, 30000, nil))
	dump("channel_header_dynamic_forward_tcp", buildHeader(4, message.ChannelTypeDynamicForwardTCP, 30000, nil))
	dump("dynamic_forward_request", writeMessage(t, &message.RequestDynamicForward{
		BindAddress: "127.0.0.1",
		BindPort:    1080,
	}))
	dump("dynamic_forward_request_wildcard", writeMessage(t, &message.RequestDynamicForward{
		BindAddress: "*",
		BindPort:    0,
	}))
	dump("dynamic_forward_reply_ok", writeMessage(t, &message.DynamicForwardReply{BoundPort: 1080}))
	dump("dynamic_forward_reply_error", writeMessage(t, &message.DynamicForwardReply{
		BoundPort: 0,
		ErrorUTF8: "dynamic forwarding not requested",
	}))
	dump("dynamic_forward_target_hostname", writeMessage(t, &message.DynamicForwardTarget{
		Address: "example.com",
		Port:    443,
	}))
	dump("dynamic_forward_target_ipv4", writeMessage(t, &message.DynamicForwardTarget{
		Address: "192.0.2.10",
		Port:    80,
	}))
	dump("dynamic_forward_target_reply_ok", writeMessage(t, &message.DynamicForwardTargetReply{}))
	dump("dynamic_forward_target_reply_error", writeMessage(t, &message.DynamicForwardTargetReply{
		ErrorUTF8: "dial tcp 192.0.2.10:80: connect: connection refused",
	}))
	// The compression of the channel body (PLAN.md 9 B8): the compressed data
	// frame carries the algorithm id and the compressed payload as an SSH
	// string. The payload is the deflate codec output of a fixed input, so the
	// bytes are deterministic and both implementations can reproduce them.
	dump("channel_data_compressed_deflate", func() []byte {
		plain := []byte("hello compression payload")
		packed, ok := compress.Compress(compress.AlgorithmDeflate, plain)
		if !ok {
			t.Fatalf("the deflate codec refused the payload")
		}
		hdr := message.CompressedDataHeader(compress.AlgorithmDeflate, uint64(len(packed)))
		out := append([]byte{}, hdr...)
		out = append(out, packed...)
		return out
	}())
}

func strings140() string {
	b := make([]byte, 140)
	for i := range b {
		b[i] = byte('a' + i%26)
	}
	return string(b)
}

func sshString(t *testing.T, s string) []byte {
	t.Helper()
	buf := make([]byte, util.SSHStringLen(s))
	n, err := util.WriteSSHString(buf, s)
	if err != nil {
		t.Fatalf("WriteSSHString(%q): %v", s, err)
	}
	return buf[:n]
}

func writeMessage(t *testing.T, m message.Message) []byte {
	t.Helper()
	buf := make([]byte, m.Length()+64)
	n, err := m.Write(buf)
	if err != nil {
		t.Fatalf("Write(%T): %v", m, err)
	}
	return buf[:n]
}
