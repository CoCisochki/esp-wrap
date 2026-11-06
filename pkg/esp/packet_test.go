package esp

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"net"
	"sync"
	"testing"
)

func TestDirectionalKeysAndNoncesDifferent(t *testing.T) {
	curve := ecdh.X25519()
	serverPriv, _ := curve.GenerateKey(rand.Reader)
	clientPriv, _ := curve.GenerateKey(rand.Reader)
	serverEphPriv, _ := curve.GenerateKey(rand.Reader)

	staticDH, err := clientPriv.ECDH(serverPriv.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	ephemeralDH, err := clientPriv.ECDH(serverEphPriv.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	uuidStr := GenerateUUID()
	uuidBytes, _ := ParseUUID(uuidStr)

	clientCiph, serverCiph, err := DeriveSessionCiphers(
		staticDH,
		ephemeralDH,
		serverPriv.PublicKey().Bytes(),
		clientPriv.PublicKey().Bytes(),
		serverEphPriv.PublicKey().Bytes(),
		uuidBytes,
	)
	if err != nil {
		t.Fatalf("DeriveSessionCiphers failed: %v", err)
	}

	if clientCiph.EncSalt() == clientCiph.DecSalt() {
		t.Fatalf("CRITICAL: encSalt and decSalt are identical! Nonce reuse vulnerability!")
	}
	if clientCiph.EncIVBase() == clientCiph.DecIVBase() {
		t.Fatalf("CRITICAL: encIVBase and decIVBase are identical!")
	}

	seq := uint32(1)
	clientEncNonce := clientCiph.ComputeNonce(true, seq)
	clientDecNonce := clientCiph.ComputeNonce(false, seq)
	if bytes.Equal(clientEncNonce[:], clientDecNonce[:]) {
		t.Fatalf("CRITICAL: c2s and s2c nonces are identical at seq=1! Nonce reuse vulnerability!")
	}

	serverEncNonce := serverCiph.ComputeNonce(true, seq)
	serverDecNonce := serverCiph.ComputeNonce(false, seq)
	if !bytes.Equal(clientEncNonce[:], serverDecNonce[:]) {
		t.Fatalf("client enc nonce must match server dec nonce")
	}
	if !bytes.Equal(serverEncNonce[:], clientDecNonce[:]) {
		t.Fatalf("server enc nonce must match client dec nonce")
	}
}

func TestHandshakeMac1AndDoSSafeguard(t *testing.T) {
	curve := ecdh.X25519()
	serverPriv, _ := curve.GenerateKey(rand.Reader)
	clientPriv, _ := curve.GenerateKey(rand.Reader)

	uuidStr := GenerateUUID()
	uuidBytes, _ := ParseUUID(uuidStr)

	serverPubBytes := serverPriv.PublicKey().Bytes()
	authSPI := DeriveAuthSPI(serverPubBytes, uuidBytes)
	mac1Key := DeriveMac1Key(serverPubBytes, uuidBytes)

	reqPkt, _, err := PackHandshakeReq(authSPI, clientPriv.PublicKey().Bytes(), mac1Key)
	if err != nil {
		t.Fatalf("PackHandshakeReq failed: %v", err)
	}

	junkPkt := make([]byte, len(reqPkt))
	copy(junkPkt, reqPkt)
	junkPkt[len(junkPkt)-1] ^= 0xFF // corrupt HMAC

	var lastNano int64
	var rateMu sync.Mutex

	_, _, err = UnpackHandshakeReq(junkPkt, mac1Key, &lastNano, &rateMu)
	if err == nil {
		t.Fatalf("junk packet with invalid mac1 MUST be rejected")
	}
	if err != ErrMacValidation {
		t.Fatalf("expected ErrMacValidation, got: %v", err)
	}

	pub, _, err := UnpackHandshakeReq(reqPkt, mac1Key, &lastNano, &rateMu)
	if err != nil {
		t.Fatalf("valid handshake req failed: %v", err)
	}
	if !bytes.Equal(pub, clientPriv.PublicKey().Bytes()) {
		t.Fatalf("client ephemeral pub mismatch")
	}

	// Replay check
	_, _, err = UnpackHandshakeReq(reqPkt, mac1Key, &lastNano, &rateMu)
	if err != ErrReplayDetected && err != ErrRateLimited {
		t.Fatalf("replayed handshake req MUST be rejected, got: %v", err)
	}
}

func TestFullHandshakeAndDataTransmission(t *testing.T) {
	curve := ecdh.X25519()
	serverPriv, _ := curve.GenerateKey(rand.Reader)

	uuidStr := GenerateUUID()
	uuidBytes, _ := ParseUUID(uuidStr)

	serverPubBytes := serverPriv.PublicKey().Bytes()
	authSPI := DeriveAuthSPI(serverPubBytes, uuidBytes)
	mac1Key := DeriveMac1Key(serverPubBytes, uuidBytes)

	clientEphPriv, _ := curve.GenerateKey(rand.Reader)
	reqPkt, _, err := PackHandshakeReq(authSPI, clientEphPriv.PublicKey().Bytes(), mac1Key)
	if err != nil {
		t.Fatal(err)
	}

	var lastNano int64
	var rateMu sync.Mutex
	clientEphPubBytes, _, err := UnpackHandshakeReq(reqPkt, mac1Key, &lastNano, &rateMu)
	if err != nil {
		t.Fatal(err)
	}

	clientEphPub, err := curve.NewPublicKey(clientEphPubBytes)
	if err != nil {
		t.Fatal(err)
	}

	serverStaticDH, err := serverPriv.ECDH(clientEphPub)
	if err != nil {
		t.Fatal(err)
	}

	serverEphPriv, _ := curve.GenerateKey(rand.Reader)
	serverEphDH, err := serverEphPriv.ECDH(clientEphPub)
	if err != nil {
		t.Fatal(err)
	}

	sessionSPI, _ := GenerateSessionSPI()
	respPayload := &HandshakeRespPayload{
		SessionSPI: sessionSPI,
		AssignedIP: net.ParseIP("10.99.1.5"),
		GatewayIP:  net.ParseIP("10.99.0.1"),
		CIDR:       16,
		MTU:        1360,
		DNS:        net.ParseIP("1.1.1.1"),
	}

	respPkt, err := PackHandshakeResp(authSPI, serverStaticDH, clientEphPubBytes, serverEphPriv.PublicKey().Bytes(), respPayload)
	if err != nil {
		t.Fatal(err)
	}

	clientStaticDH, err := clientEphPriv.ECDH(serverPriv.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	serverEphPubBytes, clientResp, err := UnpackHandshakeResp(respPkt, authSPI, clientStaticDH, clientEphPriv.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}

	if clientResp.SessionSPI != sessionSPI {
		t.Fatalf("session SPI mismatch: got %d, expected %d", clientResp.SessionSPI, sessionSPI)
	}
	if !clientResp.AssignedIP.Equal(respPayload.AssignedIP) {
		t.Fatalf("assigned IP mismatch: got %v, expected %v", clientResp.AssignedIP, respPayload.AssignedIP)
	}

	serverEphPub, err := curve.NewPublicKey(serverEphPubBytes)
	if err != nil {
		t.Fatal(err)
	}
	clientEphDH, err := clientEphPriv.ECDH(serverEphPub)
	if err != nil {
		t.Fatal(err)
	}

	clientCiph, serverCiph, err := DeriveSessionCiphers(
		clientStaticDH,
		clientEphDH,
		serverPubBytes,
		clientEphPriv.PublicKey().Bytes(),
		serverEphPubBytes,
		uuidBytes,
	)
	if err != nil {
		t.Fatal(err)
	}

	_, serverDerivedCiph, err := DeriveSessionCiphers(
		serverStaticDH,
		serverEphDH,
		serverPubBytes,
		clientEphPubBytes,
		serverEphPriv.PublicKey().Bytes(),
		uuidBytes,
	)
	if err != nil {
		t.Fatal(err)
	}

	testData := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	clientSeq := uint32(1)
	packedC2S, err := clientCiph.Pack(sessionSPI, clientSeq, ProtoIPv4, testData)
	if err != nil {
		t.Fatal(err)
	}

	proto, plain, err := serverDerivedCiph.Unpack(packedC2S)
	if err != nil {
		t.Fatalf("server unpack failed: %v", err)
	}
	if proto != ProtoIPv4 {
		t.Fatalf("proto mismatch")
	}
	if !bytes.Equal(plain, testData) {
		t.Fatalf("payload mismatch")
	}

	serverSeq := uint32(1)
	respData := []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
	packedS2C, err := serverCiph.Pack(sessionSPI, serverSeq, ProtoIPv4, respData)
	if err != nil {
		t.Fatal(err)
	}

	proto, plainResp, err := clientCiph.Unpack(packedS2C)
	if err != nil {
		t.Fatalf("client unpack failed: %v", err)
	}
	if proto != ProtoIPv4 {
		t.Fatalf("proto mismatch")
	}
	if !bytes.Equal(plainResp, respData) {
		t.Fatalf("payload mismatch")
	}
}

func TestAntiReplayProtection(t *testing.T) {
	ar := NewAntiReplay()

	if !ar.Check(1) {
		t.Fatalf("seq 1 must be valid")
	}
	ar.Update(1)

	if ar.Check(1) {
		t.Fatalf("duplicate seq 1 must be rejected")
	}

	ar.Update(100)
	if ar.Check(100) {
		t.Fatalf("duplicate seq 100 must be rejected")
	}
	if ar.Check(30) {
		t.Fatalf("seq 30 (diff > 64) must be rejected")
	}
	if !ar.Check(99) {
		t.Fatalf("seq 99 must be valid")
	}
	ar.Update(99)
	if ar.Check(99) {
		t.Fatalf("duplicate seq 99 must be rejected")
	}
}
