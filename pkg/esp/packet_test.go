package esp

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"testing"
)

func TestPackUnpack(t *testing.T) {
	key := make([]byte, 36)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatal(err)
	}

	bootTime := uint32(1700000000)
	c, err := NewCipher(key, bootTime)
	if err != nil {
		t.Fatal(err)
	}

	spi := uint32(0x100001)
	seq := uint32(42)

	testPayloads := [][]byte{
		{},
		{0x45},
		{0x45, 0x00},
		{0x45, 0x00, 0x00},
		{0x45, 0x00, 0x00, 0x54},
		bytes.Repeat([]byte{0xaa}, 1400),
	}

	for _, payload := range testPayloads {
		packed, err := c.Pack(spi, seq, ProtoIPv4, payload)
		if err != nil {
			t.Fatalf("Pack failed: %v", err)
		}

		if len(packed)%4 != 0 {
			t.Fatalf("packet length %d is not a multiple of 4", len(packed))
		}

		pSPI, err := PeekSPI(packed)
		if err != nil {
			t.Fatalf("PeekSPI failed: %v", err)
		}
		if pSPI != spi {
			t.Fatalf("SPI mismatch: expected %d, got %d", spi, pSPI)
		}

		bt, s, err := ExtractBootTimeAndSeq(packed)
		if err != nil {
			t.Fatalf("ExtractBootTimeAndSeq failed: %v", err)
		}
		if bt != bootTime || s != seq {
			t.Fatalf("bootTime/seq mismatch: got %d/%d, expected %d/%d", bt, s, bootTime, seq)
		}

		outProto, outPayload, err := c.Unpack(packed)
		if err != nil {
			t.Fatalf("Unpack failed: %v", err)
		}

		if outProto != ProtoIPv4 {
			t.Fatalf("proto mismatch")
		}
		if !bytes.Equal(outPayload, payload) {
			t.Fatalf("payload mismatch")
		}
	}
}

func TestAntiReplayBootTimeRestart(t *testing.T) {
	ar := NewAntiReplay()

	boot1 := uint32(1700000000)
	if !ar.Check(boot1, 1) {
		t.Fatalf("first packet must be valid")
	}
	ar.Update(boot1, 1)

	ar.Update(boot1, 10000)
	if ar.Check(boot1, 10000) {
		t.Fatalf("duplicate seq 10000 must be rejected")
	}
	if ar.Check(boot1, 9000) {
		t.Fatalf("old seq 9000 must be rejected")
	}

	boot2 := uint32(1700000010)
	if !ar.Check(boot2, 1) {
		t.Fatalf("restarted client with new bootTime and seq 1 must be valid")
	}
	ar.Update(boot2, 1)

	if !ar.Check(boot2, 2) {
		t.Fatalf("seq 2 on new session must be valid")
	}
	ar.Update(boot2, 2)

	if ar.Check(boot1, 5000) {
		t.Fatalf("packet from previous boot session must be rejected")
	}
	if ar.Check(boot1, 10001) {
		t.Fatalf("packet with older bootTime must be rejected even if seq is high")
	}
}

func TestHandshakeEncodeDecode(t *testing.T) {
	uuidStr := GenerateUUID()
	uuidBytes, err := ParseUUID(uuidStr)
	if err != nil {
		t.Fatalf("ParseUUID failed: %v", err)
	}

	bootTime := uint32(1730900000)
	reqBytes := EncodeHandshakeReq(bootTime, uuidBytes[:])
	req, err := DecodeHandshakeReq(reqBytes)
	if err != nil {
		t.Fatalf("DecodeHandshakeReq failed: %v", err)
	}
	if req.BootTime != bootTime {
		t.Fatalf("BootTime mismatch: got %d, expected %d", req.BootTime, bootTime)
	}
	if !bytes.Equal(req.UUID[:], uuidBytes[:]) {
		t.Fatalf("UUID mismatch")
	}

	assignedIP := net.ParseIP("10.99.12.34")
	gwIP := net.ParseIP("10.99.0.1")
	dnsIP := net.ParseIP("1.1.1.1")
	respBytes := EncodeHandshakeResp(assignedIP, gwIP, 16, 1360, dnsIP)
	resp, err := DecodeHandshakeResp(respBytes)
	if err != nil {
		t.Fatalf("DecodeHandshakeResp failed: %v", err)
	}
	if !resp.AssignedIP.Equal(assignedIP) {
		t.Fatalf("AssignedIP mismatch: got %v, expected %v", resp.AssignedIP, assignedIP)
	}
	if !resp.GatewayIP.Equal(gwIP) {
		t.Fatalf("GatewayIP mismatch: got %v, expected %v", resp.GatewayIP, gwIP)
	}
	if resp.CIDR != 16 {
		t.Fatalf("CIDR mismatch: got %d, expected 16", resp.CIDR)
	}
	if resp.MTU != 1360 {
		t.Fatalf("MTU mismatch: got %d, expected 1360", resp.MTU)
	}
	if !resp.DNS.Equal(dnsIP) {
		t.Fatalf("DNS mismatch: got %v, expected %v", resp.DNS, dnsIP)
	}
}

func TestRealityKeyDerivation(t *testing.T) {
	sharedSecret := []byte("01234567890123456789012345678901")
	uuidBytes, _ := ParseUUID("11111111-2222-3333-4444-555555555555")
	key, salt := DeriveRealitySessionKey(sharedSecret, uuidBytes[:])
	if len(key) != 32 {
		t.Fatalf("Key length expected 32, got %d", len(key))
	}
	if len(salt) != 4 {
		t.Fatalf("Salt length expected 4, got %d", len(salt))
	}
}
