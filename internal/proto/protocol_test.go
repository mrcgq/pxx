package proto

import (
	"bytes"
	"testing"
)

func TestPackUnpackHeader(t *testing.T) {
	buf := make([]byte, HeaderLen)

	testCases := []struct {
		cmd      byte
		streamID uint32
		flags    byte
		length   int
	}{
		{CmdOpenTCP, 1, 0, 100},
		{CmdData, 12345, FlagPadding, 1000},
		{CmdClose, 65535, FlagAggregate | FlagPadding, 0},
		{CmdConnStatus, 0, 0, 1},
		{CmdData, 4294967295, FlagEncrypted, 65535},
	}

	for _, tc := range testCases {
		PackHeader(buf, tc.cmd, tc.streamID, tc.flags, tc.length)
		cmd, streamID, flags, length := UnpackHeader(buf)

		if cmd != tc.cmd || streamID != tc.streamID ||
			flags != tc.flags || length != tc.length {
			t.Errorf("Mismatch: got (%d,%d,%d,%d), want (%d,%d,%d,%d)",
				cmd, streamID, flags, length,
				tc.cmd, tc.streamID, tc.flags, tc.length)
		}
	}
}

func TestPackFrameAlloc(t *testing.T) {
	payload := []byte("Hello, World!")
	frame := PackFrameAlloc(CmdData, 42, payload)

	if len(frame) != HeaderLen+len(payload) {
		t.Errorf("Frame length mismatch: got %d, want %d", len(frame), HeaderLen+len(payload))
	}

	cmd, streamID, _, length := UnpackHeader(frame[:HeaderLen])
	if cmd != CmdData {
		t.Errorf("Cmd mismatch: got %d, want %d", cmd, CmdData)
	}
	if streamID != 42 {
		t.Errorf("StreamID mismatch: got %d, want %d", streamID, 42)
	}
	if length != len(payload) {
		t.Errorf("Length mismatch: got %d, want %d", length, len(payload))
	}

	if !bytes.Equal(frame[HeaderLen:], payload) {
		t.Errorf("Payload mismatch")
	}
}

func TestPaddingRoundTrip(t *testing.T) {
	original := []byte("Hello, World!")
	calc := NewPaddingCalculator(DefaultPaddingConfig())

	buf := make([]byte, 2048)
	n := PackFrameWithPadding(buf, CmdData, 1, 0, original, calc)

	_, _, _, payload, err := UnpackFrameWithPadding(buf[:n])
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(payload, original) {
		t.Errorf("Payload mismatch: got %d bytes, want %d bytes", len(payload), len(original))
	}
}

func TestPaddingRoundTripEmpty(t *testing.T) {
	calc := NewPaddingCalculator(DefaultPaddingConfig())

	buf := make([]byte, 1024)
	n := PackFrameWithPadding(buf, CmdClose, 1, 0, nil, calc)

	_, _, _, payload, err := UnpackFrameWithPadding(buf[:n])
	if err != nil {
		t.Fatal(err)
	}

	if len(payload) != 0 {
		t.Errorf("Payload should be empty, got %d bytes", len(payload))
	}
}

func TestRemovePaddingInvalid(t *testing.T) {
	testCases := []struct {
		name    string
		payload []byte
	}{
		{"empty", []byte{}},
		{"too short", []byte{10}},
		{"zero padding", append(make([]byte, 10), 0)},
	}

	for _, tc := range testCases {
		result := RemovePadding(tc.payload)
		_ = result // 避免 unused 警告
	}
}

func TestOpenPayload(t *testing.T) {
	host := "example.com"
	port := uint16(443)
	initData := []byte("GET / HTTP/1.1\r\n")

	payload := BuildOpenPayload(IPv4First, host, port, initData)

	strategy, parsedHost, parsedPort, parsedInit, err := ParseOpenPayload(payload)
	if err != nil {
		t.Fatal(err)
	}

	if strategy != IPv4First {
		t.Errorf("Strategy mismatch: got %d, want %d", strategy, IPv4First)
	}
	if parsedHost != host {
		t.Errorf("Host mismatch: got %s, want %s", parsedHost, host)
	}
	if parsedPort != port {
		t.Errorf("Port mismatch: got %d, want %d", parsedPort, port)
	}
	if !bytes.Equal(parsedInit, initData) {
		t.Errorf("InitData mismatch")
	}
}

func TestAggregatedData(t *testing.T) {
	agg := &AggregatedData{}
	agg.Items = append(agg.Items, struct {
		StreamID uint32
		Data     []byte
	}{1, []byte("hello")})
	agg.Items = append(agg.Items, struct {
		StreamID uint32
		Data     []byte
	}{2, []byte("world")})

	encoded := agg.Encode()

	decoded, err := DecodeAggregatedData(encoded)
	if err != nil {
		t.Fatal(err)
	}

	if len(decoded.Items) != 2 {
		t.Errorf("Items count mismatch: got %d, want 2", len(decoded.Items))
	}

	if decoded.Items[0].StreamID != 1 || !bytes.Equal(decoded.Items[0].Data, []byte("hello")) {
		t.Errorf("Item 0 mismatch")
	}
	if decoded.Items[1].StreamID != 2 || !bytes.Equal(decoded.Items[1].Data, []byte("world")) {
		t.Errorf("Item 1 mismatch")
	}
}

func TestPaddingCalculatorDistributions(t *testing.T) {
	distributions := []string{"uniform", "normal", "mimicry"}

	for _, dist := range distributions {
		cfg := &PaddingConfig{
			Enabled:      true,
			MinSize:      64,
			MaxPadding:   255,
			Distribution: dist,
		}
		calc := NewPaddingCalculator(cfg)

		for i := 0; i < 100; i++ {
			padding := calc.CalculatePadding(50)
			if padding < 0 {
				t.Errorf("%s: negative padding: %d", dist, padding)
			}
			if padding > 255 {
				t.Errorf("%s: padding exceeds max: %d > 255", dist, padding)
			}
		}
	}
}

// ==================== 基准测试 ====================

func BenchmarkPackHeader(b *testing.B) {
	buf := make([]byte, HeaderLen)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		PackHeader(buf, CmdData, 12345, FlagPadding, 1000)
	}
}

func BenchmarkUnpackHeader(b *testing.B) {
	buf := make([]byte, HeaderLen)
	PackHeader(buf, CmdData, 12345, FlagPadding, 1000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		UnpackHeader(buf)
	}
}

func BenchmarkPackFrame(b *testing.B) {
	buf := make([]byte, 65536)
	payload := make([]byte, 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		PackFrame(buf, CmdData, 1, 0, payload, 0)
	}
}

func BenchmarkPackFrameWithPadding(b *testing.B) {
	buf := make([]byte, 65536)
	payload := make([]byte, 1024)
	calc := NewPaddingCalculator(DefaultPaddingConfig())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		PackFrameWithPadding(buf, CmdData, 1, 0, payload, calc)
	}
}

func BenchmarkRemovePadding(b *testing.B) {
	calc := NewPaddingCalculator(DefaultPaddingConfig())
	buf := make([]byte, 2048)
	original := make([]byte, 1024)
	
	// 修复：使用 _ 忽略返回值，避免 "declared and not used" 错误
	_ = PackFrameWithPadding(buf, CmdData, 1, 0, original, calc)

	_, _, _, length := UnpackHeader(buf[:HeaderLen])
	payload := buf[HeaderLen : HeaderLen+length]

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		RemovePadding(payload)
	}
}

func BenchmarkAggregatedDataEncode(b *testing.B) {
	agg := &AggregatedData{}
	for i := 0; i < 10; i++ {
		agg.Items = append(agg.Items, struct {
			StreamID uint32
			Data     []byte
		}{uint32(i), make([]byte, 100)})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		agg.Encode()
	}
}

func BenchmarkAggregatedDataDecode(b *testing.B) {
	agg := &AggregatedData{}
	for i := 0; i < 10; i++ {
		agg.Items = append(agg.Items, struct {
			StreamID uint32
			Data     []byte
		}{uint32(i), make([]byte, 100)})
	}
	encoded := agg.Encode()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DecodeAggregatedData(encoded)
	}
}
