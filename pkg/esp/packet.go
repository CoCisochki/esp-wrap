package esp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
)

const (
	ProtoIPv4    = 4
	ProtoESP     = 50
	ProtoDummy   = 59
	ProtoControl = 253

	ControlHandshakeReq  = 1
	ControlHandshakeResp = 2
	ControlKeepalive     = 3

	HeaderSize    = 8
	ExplicitIVLen = 8
	TotalHeader   = HeaderSize + ExplicitIVLen
	TagSize       = 16
	MinTrailer    = 2
	MinPacketSize = TotalHeader + MinTrailer + TagSize

	HandshakeReqMinLen = 4 + 32 + 8 + 1 + 16
)

var (
	ErrPacketTooShort = errors.New("esp: packet too short")
	ErrInvalidPadding = errors.New("esp: invalid padding")
	ErrDecryption     = errors.New("esp: authentication or decryption failure")
	ErrReplayDetected = errors.New("esp: replay detected")
	ErrMacValidation  = errors.New("esp: handshake mac1 validation failed")
	ErrRateLimited    = errors.New("esp: handshake rate limited")
	ErrTimestampStale = errors.New("esp: handshake timestamp stale or skew")
)

type SessionCipher struct {
	encAEAD   cipher.AEAD
	decAEAD   cipher.AEAD
	encSalt   [4]byte
	decSalt   [4]byte
	encIVBase [8]byte
	decIVBase [8]byte
}

func NewSessionCipher(encKey, decKey []byte, encSalt, decSalt [4]byte, encIVBase, decIVBase [8]byte) (*SessionCipher, error) {
	encBlock, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	encAEAD, err := cipher.NewGCM(encBlock)
	if err != nil {
		return nil, err
	}

	decBlock, err := aes.NewCipher(decKey)
	if err != nil {
		return nil, err
	}
	decAEAD, err := cipher.NewGCM(decBlock)
	if err != nil {
		return nil, err
	}

	return &SessionCipher{
		encAEAD:   encAEAD,
		decAEAD:   decAEAD,
		encSalt:   encSalt,
		decSalt:   decSalt,
		encIVBase: encIVBase,
		decIVBase: decIVBase,
	}, nil
}

func (s *SessionCipher) EncSalt() [4]byte {
	return s.encSalt
}

func (s *SessionCipher) DecSalt() [4]byte {
	return s.decSalt
}

func (s *SessionCipher) EncIVBase() [8]byte {
	return s.encIVBase
}

func (s *SessionCipher) DecIVBase() [8]byte {
	return s.decIVBase
}

func (s *SessionCipher) ComputeNonce(isEnc bool, seq uint32) [12]byte {
	var nonce [12]byte
	var salt [4]byte
	var ivBase [8]byte
	if isEnc {
		salt = s.encSalt
		ivBase = s.encIVBase
	} else {
		salt = s.decSalt
		ivBase = s.decIVBase
	}
	copy(nonce[0:4], salt[:])
	baseUint := binary.BigEndian.Uint64(ivBase[:])
	binary.BigEndian.PutUint64(nonce[4:12], baseUint^uint64(seq))
	return nonce
}

var bufferPool = sync.Pool{
	New: func() any {
		b := make([]byte, 65536)
		return &b
	},
}

func (s *SessionCipher) Pack(spi uint32, seq uint32, nextHeader uint8, payload []byte) ([]byte, error) {
	return s.PackTo(nil, spi, seq, nextHeader, payload)
}

func (s *SessionCipher) PackTo(dst []byte, spi uint32, seq uint32, nextHeader uint8, payload []byte) ([]byte, error) {
	payloadLen := len(payload)
	basePad := (4 - ((payloadLen + 2) % 4)) % 4
	extraBlocks := int((seq^0x5a5a5a5a)&0x03) * 4
	padLen := basePad + extraBlocks
	plainLen := payloadLen + padLen + 2
	totalLen := TotalHeader + plainLen + TagSize

	if cap(dst) < totalLen {
		dst = make([]byte, TotalHeader, totalLen)
	} else {
		dst = dst[:TotalHeader]
	}

	binary.BigEndian.PutUint32(dst[0:4], spi)
	binary.BigEndian.PutUint32(dst[4:8], seq)

	baseUint := binary.BigEndian.Uint64(s.encIVBase[:])
	binary.BigEndian.PutUint64(dst[HeaderSize:TotalHeader], baseUint^uint64(seq))

	var nonce [12]byte
	copy(nonce[0:4], s.encSalt[:])
	copy(nonce[4:12], dst[HeaderSize:TotalHeader])

	plainPtr := bufferPool.Get().(*[]byte)
	plain := (*plainPtr)[:plainLen]
	copy(plain, payload)
	for i := 0; i < padLen; i++ {
		plain[payloadLen+i] = byte(i + 1)
	}
	plain[plainLen-2] = byte(padLen)
	plain[plainLen-1] = nextHeader

	aad := dst[0:8]
	out := s.encAEAD.Seal(dst, nonce[:], plain, aad)
	bufferPool.Put(plainPtr)

	return out, nil
}

func (s *SessionCipher) Unpack(packet []byte) (uint8, []byte, error) {
	return s.UnpackTo(nil, packet)
}

func (s *SessionCipher) UnpackTo(dst []byte, packet []byte) (uint8, []byte, error) {
	p := StripIPv4Header(packet)
	if len(p) < MinPacketSize {
		return 0, nil, ErrPacketTooShort
	}

	payloadWithTag := p[TotalHeader:]
	if len(payloadWithTag) < TagSize+MinTrailer {
		return 0, nil, ErrPacketTooShort
	}

	var nonce [12]byte
	copy(nonce[0:4], s.decSalt[:])
	copy(nonce[4:12], p[HeaderSize:TotalHeader])

	aad := p[0:8]

	var plain []byte
	var plainPtr *[]byte
	if cap(dst) >= len(payloadWithTag)-TagSize {
		plain = dst[:0]
	} else {
		plainPtr = bufferPool.Get().(*[]byte)
		plain = (*plainPtr)[:0]
	}

	var err error
	plain, err = s.decAEAD.Open(plain, nonce[:], payloadWithTag, aad)
	if err != nil {
		if plainPtr != nil {
			bufferPool.Put(plainPtr)
		}
		return 0, nil, ErrDecryption
	}

	if len(plain) < MinTrailer {
		if plainPtr != nil {
			bufferPool.Put(plainPtr)
		}
		return 0, nil, ErrPacketTooShort
	}

	padLen := int(plain[len(plain)-2])
	nextHeader := plain[len(plain)-1]

	if padLen+MinTrailer > len(plain) {
		if plainPtr != nil {
			bufferPool.Put(plainPtr)
		}
		return 0, nil, ErrInvalidPadding
	}

	payloadLen := len(plain) - MinTrailer - padLen
	res := plain[:payloadLen]

	if plainPtr != nil {
		out := make([]byte, payloadLen)
		copy(out, res)
		bufferPool.Put(plainPtr)
		return nextHeader, out, nil
	}

	return nextHeader, res, nil
}

func GenerateUUID() string {
	var buf [16]byte
	rand.Read(buf[:])
	buf[6] = (buf[6] & 0x0f) | 0x40
	buf[8] = (buf[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		binary.BigEndian.Uint32(buf[0:4]),
		binary.BigEndian.Uint16(buf[4:6]),
		binary.BigEndian.Uint16(buf[6:8]),
		binary.BigEndian.Uint16(buf[8:10]),
		buf[10:16],
	)
}

func ParseUUID(s string) ([16]byte, error) {
	var out [16]byte
	clean := strings.ReplaceAll(s, "-", "")
	if len(clean) != 32 {
		return out, errors.New("invalid uuid length")
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return out, err
	}
	copy(out[:], b)
	return out, nil
}

func DeriveAuthSPI(serverStaticPub []byte, uuid [16]byte) uint32 {
	h := sha256.New()
	h.Write([]byte("esp-auth-spi-v2"))
	h.Write(serverStaticPub)
	h.Write(uuid[:])
	sum := h.Sum(nil)
	return binary.BigEndian.Uint32(sum[:4])
}

func DeriveMac1Key(serverStaticPub []byte, uuid [16]byte) [32]byte {
	reader := hkdf.New(sha256.New, serverStaticPub, uuid[:], []byte("esp-mac1-v2"))
	var key [32]byte
	io.ReadFull(reader, key[:])
	return key
}

func ComputeMac1(mac1Key [32]byte, data []byte) [16]byte {
	mac := hmac.New(sha256.New, mac1Key[:])
	mac.Write(data)
	sum := mac.Sum(nil)
	var out [16]byte
	copy(out[:], sum[:16])
	return out
}

func DeriveSessionCiphers(staticDH, ephemeralDH, serverStaticPub, clientEphemeralPub, serverEphemeralPub []byte, uuid [16]byte) (clientCipher, serverCipher *SessionCipher, err error) {
	ikm := make([]byte, len(staticDH)+len(ephemeralDH))
	copy(ikm, staticDH)
	copy(ikm[len(staticDH):], ephemeralDH)

	saltHash := sha256.New()
	saltHash.Write(serverStaticPub)
	saltHash.Write(clientEphemeralPub)
	saltHash.Write(serverEphemeralPub)
	saltHash.Write(uuid[:])
	salt := saltHash.Sum(nil)

	prk := hkdf.Extract(sha256.New, ikm, salt)

	c2sReader := hkdf.Expand(sha256.New, prk, []byte("esp-wrap-v2-c2s"))
	var keyC2S [32]byte
	var saltC2S [4]byte
	var ivBaseC2S [8]byte
	if _, err := io.ReadFull(c2sReader, keyC2S[:]); err != nil {
		return nil, nil, err
	}
	if _, err := io.ReadFull(c2sReader, saltC2S[:]); err != nil {
		return nil, nil, err
	}
	if _, err := io.ReadFull(c2sReader, ivBaseC2S[:]); err != nil {
		return nil, nil, err
	}

	s2cReader := hkdf.Expand(sha256.New, prk, []byte("esp-wrap-v2-s2c"))
	var keyS2C [32]byte
	var saltS2C [4]byte
	var ivBaseS2C [8]byte
	if _, err := io.ReadFull(s2cReader, keyS2C[:]); err != nil {
		return nil, nil, err
	}
	if _, err := io.ReadFull(s2cReader, saltS2C[:]); err != nil {
		return nil, nil, err
	}
	if _, err := io.ReadFull(s2cReader, ivBaseS2C[:]); err != nil {
		return nil, nil, err
	}

	clientCipher, err = NewSessionCipher(keyC2S[:], keyS2C[:], saltC2S, saltS2C, ivBaseC2S, ivBaseS2C)
	if err != nil {
		return nil, nil, err
	}

	serverCipher, err = NewSessionCipher(keyS2C[:], keyC2S[:], saltS2C, saltC2S, ivBaseS2C, ivBaseC2S)
	if err != nil {
		return nil, nil, err
	}

	return clientCipher, serverCipher, nil
}

func PackHandshakeReq(authSPI uint32, clientEphemeralPub []byte, mac1Key [32]byte) ([]byte, int64, error) {
	nowNano := time.Now().UnixNano()

	var padLenByte [1]byte
	rand.Read(padLenByte[:])
	padLen := int(padLenByte[0]%24) + 8

	totalLen := 4 + 32 + 8 + 1 + padLen + 16
	buf := make([]byte, totalLen)

	binary.BigEndian.PutUint32(buf[0:4], authSPI)
	copy(buf[4:36], clientEphemeralPub)
	binary.BigEndian.PutUint64(buf[36:44], uint64(nowNano))
	buf[44] = byte(padLen)

	rand.Read(buf[45 : 45+padLen])

	macTag := ComputeMac1(mac1Key, buf[:45+padLen])
	copy(buf[45+padLen:totalLen], macTag[:])

	return buf, nowNano, nil
}

func UnpackHandshakeReq(packet []byte, mac1Key [32]byte, lastClientNano *int64, lastArrivalNano *int64, rateLimitMu *sync.Mutex) (clientEphemeralPub []byte, timestampNano int64, err error) {
	p := StripIPv4Header(packet)
	if len(p) < HandshakeReqMinLen {
		return nil, 0, ErrPacketTooShort
	}

	padLen := int(p[44])
	expectedLen := 45 + padLen + 16
	if len(p) != expectedLen {
		return nil, 0, ErrPacketTooShort
	}

	receivedMac := p[45+padLen : expectedLen]
	expectedMac := ComputeMac1(mac1Key, p[:45+padLen])
	if subtle.ConstantTimeCompare(receivedMac, expectedMac[:]) != 1 {
		return nil, 0, ErrMacValidation
	}

	pktNano := int64(binary.BigEndian.Uint64(p[36:44]))
	serverNowNano := time.Now().UnixNano()
	diff := serverNowNano - pktNano
	if diff < -300*int64(time.Second) || diff > 300*int64(time.Second) {
		return nil, 0, ErrTimestampStale
	}

	if rateLimitMu != nil {
		rateLimitMu.Lock()
		defer rateLimitMu.Unlock()
	}

	if lastArrivalNano != nil {
		if *lastArrivalNano > 0 && (serverNowNano-*lastArrivalNano) < int64(1*time.Second) {
			return nil, 0, ErrRateLimited
		}
	}

	if lastClientNano != nil {
		if *lastClientNano > 0 && pktNano <= *lastClientNano {
			return nil, 0, ErrReplayDetected
		}
	}

	if lastArrivalNano != nil {
		*lastArrivalNano = serverNowNano
	}
	if lastClientNano != nil {
		*lastClientNano = pktNano
	}

	pub := make([]byte, 32)
	copy(pub, p[4:36])
	return pub, pktNano, nil
}

type HandshakeRespPayload struct {
	SessionSPI uint32
	AssignedIP net.IP
	GatewayIP  net.IP
	CIDR       int
	MTU        int
	DNS        net.IP
}

func deriveHandshakeRespAEAD(staticDH, clientEphemeralPub, serverEphemeralPub []byte) (cipher.AEAD, [4]byte, error) {
	kdfReader := hkdf.New(sha256.New, staticDH, append(clientEphemeralPub, serverEphemeralPub...), []byte("esp-handshake-resp-v2"))
	var key [32]byte
	var salt [4]byte
	if _, err := io.ReadFull(kdfReader, key[:]); err != nil {
		return nil, salt, err
	}
	if _, err := io.ReadFull(kdfReader, salt[:]); err != nil {
		return nil, salt, err
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, salt, err
	}
	aead, err := cipher.NewGCM(block)
	return aead, salt, err
}

func PackHandshakeResp(authSPI uint32, staticDH, clientEphemeralPub, serverEphemeralPub []byte, resp *HandshakeRespPayload) ([]byte, error) {
	aead, salt, err := deriveHandshakeRespAEAD(staticDH, clientEphemeralPub, serverEphemeralPub)
	if err != nil {
		return nil, err
	}

	rawPayload := make([]byte, 19)
	binary.BigEndian.PutUint32(rawPayload[0:4], resp.SessionSPI)
	copy(rawPayload[4:8], resp.AssignedIP.To4())
	copy(rawPayload[8:12], resp.GatewayIP.To4())
	rawPayload[12] = byte(resp.CIDR)
	binary.BigEndian.PutUint16(rawPayload[13:15], uint16(resp.MTU))
	if resp.DNS != nil && resp.DNS.To4() != nil {
		copy(rawPayload[15:19], resp.DNS.To4())
	}

	var padByte [1]byte
	rand.Read(padByte[:])
	padLen := int(padByte[0]%16) + 4
	plain := make([]byte, len(rawPayload)+1+padLen)
	copy(plain, rawPayload)
	plain[len(rawPayload)] = byte(padLen)
	rand.Read(plain[len(rawPayload)+1:])

	var iv [8]byte
	rand.Read(iv[:])

	var nonce [12]byte
	copy(nonce[0:4], salt[:])
	copy(nonce[4:12], iv[:])

	aad := make([]byte, 4+32+8)
	binary.BigEndian.PutUint32(aad[0:4], authSPI)
	copy(aad[4:36], serverEphemeralPub)
	copy(aad[36:44], iv[:])

	cipherText := aead.Seal(nil, nonce[:], plain, aad)

	packet := make([]byte, 4+32+8+len(cipherText))
	binary.BigEndian.PutUint32(packet[0:4], authSPI)
	copy(packet[4:36], serverEphemeralPub)
	copy(packet[36:44], iv[:])
	copy(packet[44:], cipherText)

	return packet, nil
}

func UnpackHandshakeResp(packet []byte, authSPI uint32, staticDH, clientEphemeralPub []byte) (serverEphemeralPub []byte, resp *HandshakeRespPayload, err error) {
	p := StripIPv4Header(packet)
	if len(p) < 4+32+8+TagSize+20 {
		return nil, nil, ErrPacketTooShort
	}

	pktSPI := binary.BigEndian.Uint32(p[0:4])
	if pktSPI != authSPI {
		return nil, nil, errors.New("auth spi mismatch")
	}

	serverPub := p[4:36]
	iv := p[36:44]
	cipherTextWithTag := p[44:]

	aead, salt, err := deriveHandshakeRespAEAD(staticDH, clientEphemeralPub, serverPub)
	if err != nil {
		return nil, nil, err
	}

	var nonce [12]byte
	copy(nonce[0:4], salt[:])
	copy(nonce[4:12], iv)

	aad := p[0:44]
	plain, err := aead.Open(nil, nonce[:], cipherTextWithTag, aad)
	if err != nil {
		return nil, nil, ErrDecryption
	}

	if len(plain) < 20 {
		return nil, nil, ErrPacketTooShort
	}

	sessionSPI := binary.BigEndian.Uint32(plain[0:4])
	assignedIP := net.IPv4(plain[4], plain[5], plain[6], plain[7])
	gwIP := net.IPv4(plain[8], plain[9], plain[10], plain[11])
	cidr := int(plain[12])
	mtu := int(binary.BigEndian.Uint16(plain[13:15]))
	dns := net.IPv4(plain[15], plain[16], plain[17], plain[18])

	return serverPub, &HandshakeRespPayload{
		SessionSPI: sessionSPI,
		AssignedIP: assignedIP,
		GatewayIP:  gwIP,
		CIDR:       cidr,
		MTU:        mtu,
		DNS:        dns,
	}, nil
}

func GenerateSessionSPI() (uint32, error) {
	var b [4]byte
	for {
		if _, err := rand.Read(b[:]); err != nil {
			return 0, err
		}
		val := binary.BigEndian.Uint32(b[:])
		if val > 1000 && val != math.MaxUint32 {
			return val, nil
		}
	}
}

func StripIPv4Header(buf []byte) []byte {
	if len(buf) >= 20 && (buf[0]>>4) == 4 && buf[9] == ProtoESP {
		ihl := int(buf[0]&0x0F) * 4
		if ihl >= 20 && ihl <= len(buf) {
			return buf[ihl:]
		}
	}
	return buf
}

func PeekSPI(packet []byte) (uint32, error) {
	p := StripIPv4Header(packet)
	if len(p) < 4 {
		return 0, ErrPacketTooShort
	}
	return binary.BigEndian.Uint32(p[0:4]), nil
}

type AntiReplay struct {
	mu      sync.Mutex
	lastSeq uint32
	bitmap  uint64
}

func NewAntiReplay() *AntiReplay {
	return &AntiReplay{}
}

func (r *AntiReplay) Check(seq uint32) bool {
	if seq == 0 {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.lastSeq == 0 {
		return true
	}
	if seq > r.lastSeq {
		return true
	}
	diff := r.lastSeq - seq
	if diff >= 64 {
		return false
	}
	return (r.bitmap & (uint64(1) << diff)) == 0
}

func (r *AntiReplay) Update(seq uint32) bool {
	if seq == 0 {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.lastSeq == 0 {
		r.lastSeq = seq
		r.bitmap = 1
		return true
	}
	if seq > r.lastSeq {
		diff := seq - r.lastSeq
		if diff < 64 {
			r.bitmap = (r.bitmap << diff) | 1
		} else {
			r.bitmap = 1
		}
		r.lastSeq = seq
		return true
	}
	diff := r.lastSeq - seq
	if diff >= 64 {
		return false
	}
	if (r.bitmap & (uint64(1) << diff)) != 0 {
		return false
	}
	r.bitmap |= (uint64(1) << diff)
	return true
}

func (r *AntiReplay) CheckAndUpdate(seq uint32) bool {
	if seq == 0 {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.lastSeq == 0 {
		r.lastSeq = seq
		r.bitmap = 1
		return true
	}
	if seq > r.lastSeq {
		diff := seq - r.lastSeq
		if diff < 64 {
			r.bitmap = (r.bitmap << diff) | 1
		} else {
			r.bitmap = 1
		}
		r.lastSeq = seq
		return true
	}
	diff := r.lastSeq - seq
	if diff >= 64 {
		return false
	}
	if (r.bitmap & (uint64(1) << diff)) != 0 {
		return false
	}
	r.bitmap |= (uint64(1) << diff)
	return true
}

func GenerateX25519Key() (*ecdh.PrivateKey, error) {
	curve := ecdh.X25519()
	return curve.GenerateKey(rand.Reader)
}
