package esp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
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
)

var (
	ErrPacketTooShort = errors.New("esp: packet too short")
	ErrInvalidPadding = errors.New("esp: invalid padding")
	ErrDecryption     = errors.New("esp: authentication or decryption failure")
	ErrInvalidKey     = errors.New("esp: invalid key length")
	ErrReplayDetected = errors.New("esp: replay detected")
)

type Cipher struct {
	aead     cipher.AEAD
	salt     [4]byte
	bootTime uint32
}

func NewCipher(key []byte, bootTime uint32) (*Cipher, error) {
	var aesKey []byte
	var salt [4]byte

	switch len(key) {
	case 36:
		aesKey = key[:32]
		copy(salt[:], key[32:36])
	case 32:
		aesKey = key[:32]
		h := sha256.Sum256(key)
		copy(salt[:], h[:4])
	case 20:
		aesKey = key[:16]
		copy(salt[:], key[16:20])
	case 16:
		aesKey = key[:16]
		h := sha256.Sum256(key)
		copy(salt[:], h[:4])
	default:
		return nil, ErrInvalidKey
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if bootTime == 0 {
		bootTime = uint32(time.Now().Unix())
	}

	return &Cipher{
		aead:     gcm,
		salt:     salt,
		bootTime: bootTime,
	}, nil
}

func NewCipherWithKeySalt(aesKey []byte, salt [4]byte, bootTime uint32) (*Cipher, error) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if bootTime == 0 {
		bootTime = uint32(time.Now().Unix())
	}

	return &Cipher{
		aead:     gcm,
		salt:     salt,
		bootTime: bootTime,
	}, nil
}

func GenerateMasterKey() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func DecodeMasterKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == 32 {
		return b, nil
	}
	if b, err := hex.DecodeString(s); err == nil && len(b) == 32 {
		return b, nil
	}
	if len(s) == 32 {
		return []byte(s), nil
	}
	h := sha256.Sum256([]byte(s))
	return h[:], nil
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

func DeriveSPIFromUUID(uuidBytes []byte) uint32 {
	return (binary.BigEndian.Uint32(uuidBytes[0:4]) & 0x7FFFFFFF) | 0x10000000
}

func DeriveRealitySPI(uuidBytes []byte, serverPubBytes []byte) uint32 {
	h := sha256.New()
	h.Write(uuidBytes)
	h.Write(serverPubBytes)
	digest := h.Sum(nil)
	return (binary.BigEndian.Uint32(digest[:4]) & 0x7FFFFFFF) | 0x10000000
}

func DeriveRealitySessionKey(sharedSecret []byte, uuidBytes []byte) ([]byte, [4]byte) {
	mac := hmac.New(sha256.New, sharedSecret)
	mac.Write(uuidBytes)
	prk := mac.Sum(nil)

	mac = hmac.New(sha256.New, prk)
	mac.Write([]byte("esp-wrap-reality-v1"))
	mac.Write([]byte{0x01})
	t1 := mac.Sum(nil)

	mac = hmac.New(sha256.New, prk)
	mac.Write(t1)
	mac.Write([]byte("esp-wrap-reality-v1"))
	mac.Write([]byte{0x02})
	t2 := mac.Sum(nil)

	full := append(t1, t2...)
	var salt [4]byte
	copy(salt[:], full[32:36])
	return full[:32], salt
}

func DeriveUserKeyAndSalt(masterKey []byte, uuidBytes []byte) ([]byte, [4]byte) {
	mac := hmac.New(sha256.New, masterKey)
	mac.Write(uuidBytes)
	prk := mac.Sum(nil)

	mac = hmac.New(sha256.New, prk)
	mac.Write([]byte("esp-wrap-rfc4106-uuid-v1"))
	mac.Write([]byte{0x01})
	t1 := mac.Sum(nil)

	mac = hmac.New(sha256.New, prk)
	mac.Write(t1)
	mac.Write([]byte("esp-wrap-rfc4106-uuid-v1"))
	mac.Write([]byte{0x02})
	t2 := mac.Sum(nil)

	full := append(t1, t2...)
	var salt [4]byte
	copy(salt[:], full[32:36])
	return full[:32], salt
}

type HandshakeReq struct {
	BootTime uint32
	UUID     [16]byte
}

func EncodeHandshakeReq(bootTime uint32, uuidBytes []byte) []byte {
	buf := make([]byte, 21)
	buf[0] = ControlHandshakeReq
	binary.BigEndian.PutUint32(buf[1:5], bootTime)
	copy(buf[5:21], uuidBytes)
	return buf
}

func DecodeHandshakeReq(data []byte) (*HandshakeReq, error) {
	if len(data) < 21 || data[0] != ControlHandshakeReq {
		return nil, errors.New("invalid handshake req")
	}
	req := &HandshakeReq{
		BootTime: binary.BigEndian.Uint32(data[1:5]),
	}
	copy(req.UUID[:], data[5:21])
	return req, nil
}

type HandshakeResp struct {
	AssignedIP net.IP
	GatewayIP  net.IP
	CIDR       int
	MTU        int
	DNS        net.IP
}

func EncodeHandshakeResp(assignedIP, gatewayIP net.IP, cidr, mtu int, dns net.IP) []byte {
	buf := make([]byte, 16)
	buf[0] = ControlHandshakeResp
	copy(buf[1:5], assignedIP.To4())
	copy(buf[5:9], gatewayIP.To4())
	buf[9] = byte(cidr)
	binary.BigEndian.PutUint16(buf[10:12], uint16(mtu))
	if dns != nil && dns.To4() != nil {
		copy(buf[12:16], dns.To4())
	}
	return buf
}

func DecodeHandshakeResp(data []byte) (*HandshakeResp, error) {
	if len(data) < 16 || data[0] != ControlHandshakeResp {
		return nil, errors.New("invalid handshake resp")
	}
	resp := &HandshakeResp{
		AssignedIP: net.IPv4(data[1], data[2], data[3], data[4]),
		GatewayIP:  net.IPv4(data[5], data[6], data[7], data[8]),
		CIDR:       int(data[9]),
		MTU:        int(binary.BigEndian.Uint16(data[10:12])),
		DNS:        net.IPv4(data[12], data[13], data[14], data[15]),
	}
	return resp, nil
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

func ExtractBootTimeAndSeq(packet []byte) (uint32, uint32, error) {
	p := StripIPv4Header(packet)
	if len(p) < TotalHeader {
		return 0, 0, ErrPacketTooShort
	}
	seq := binary.BigEndian.Uint32(p[4:8])
	bootTime := binary.BigEndian.Uint32(p[HeaderSize : HeaderSize+4])
	return bootTime, seq, nil
}

func (c *Cipher) PackHandshakeReq(spi uint32, seq uint32, ephemeralPub []byte, uuidBytes []byte) ([]byte, error) {
	payload := EncodeHandshakeReq(c.bootTime, uuidBytes)
	payloadLen := len(payload)
	padLen := (4 - ((payloadLen + 2) % 4)) % 4
	plainLen := payloadLen + padLen + 2

	totalLen := TotalHeader + 32 + plainLen + TagSize
	buf := make([]byte, TotalHeader+32, totalLen)
	binary.BigEndian.PutUint32(buf[0:4], spi)
	binary.BigEndian.PutUint32(buf[4:8], seq)
	binary.BigEndian.PutUint32(buf[HeaderSize:HeaderSize+4], c.bootTime)
	binary.BigEndian.PutUint32(buf[HeaderSize+4:TotalHeader], seq)
	copy(buf[TotalHeader:TotalHeader+32], ephemeralPub)

	var nonce [12]byte
	copy(nonce[0:4], c.salt[:])
	copy(nonce[4:12], buf[HeaderSize:TotalHeader])

	plain := make([]byte, plainLen)
	copy(plain, payload)
	for i := 0; i < padLen; i++ {
		plain[payloadLen+i] = byte(i + 1)
	}
	plain[plainLen-2] = byte(padLen)
	plain[plainLen-1] = ProtoControl

	aad := buf[0:8]
	cipherText := c.aead.Seal(nil, nonce[:], plain, aad)
	buf = append(buf, cipherText...)
	return buf, nil
}

func UnpackHandshakeReq(packet []byte, serverPriv *ecdh.PrivateKey, expectedUUID [16]byte) (*Cipher, *HandshakeReq, error) {
	p := StripIPv4Header(packet)
	if len(p) < TotalHeader+32+MinTrailer+TagSize {
		return nil, nil, ErrPacketTooShort
	}

	bootTime := binary.BigEndian.Uint32(p[HeaderSize : HeaderSize+4])
	ephemeralPubBytes := p[TotalHeader : TotalHeader+32]
	cipherTextWithTag := p[TotalHeader+32:]

	curve := ecdh.X25519()
	ephemeralPub, err := curve.NewPublicKey(ephemeralPubBytes)
	if err != nil {
		return nil, nil, err
	}

	sharedSecret, err := serverPriv.ECDH(ephemeralPub)
	if err != nil {
		return nil, nil, err
	}

	aesKey, salt := DeriveRealitySessionKey(sharedSecret, expectedUUID[:])
	ciph, err := NewCipherWithKeySalt(aesKey, salt, bootTime)
	if err != nil {
		return nil, nil, err
	}

	var nonce [12]byte
	copy(nonce[0:4], salt[:])
	copy(nonce[4:12], p[HeaderSize:TotalHeader])

	aad := p[0:8]
	plain, err := ciph.aead.Open(nil, nonce[:], cipherTextWithTag, aad)
	if err != nil {
		return nil, nil, ErrDecryption
	}

	if len(plain) < MinTrailer {
		return nil, nil, ErrPacketTooShort
	}

	padLen := int(plain[len(plain)-2])
	nextHdr := plain[len(plain)-1]
	if nextHdr != ProtoControl {
		return nil, nil, errors.New("invalid next header")
	}
	if padLen+MinTrailer > len(plain) {
		return nil, nil, ErrInvalidPadding
	}

	payloadLen := len(plain) - MinTrailer - padLen
	req, err := DecodeHandshakeReq(plain[:payloadLen])
	if err != nil {
		return nil, nil, err
	}
	if req.UUID != expectedUUID {
		return nil, nil, errors.New("uuid mismatch")
	}

	return ciph, req, nil
}

func (c *Cipher) Pack(spi uint32, seq uint32, nextHeader uint8, payload []byte) ([]byte, error) {
	payloadLen := len(payload)
	padLen := (4 - ((payloadLen + 2) % 4)) % 4
	plainLen := payloadLen + padLen + 2

	buf := make([]byte, TotalHeader, TotalHeader+plainLen+TagSize)
	binary.BigEndian.PutUint32(buf[0:4], spi)
	binary.BigEndian.PutUint32(buf[4:8], seq)

	binary.BigEndian.PutUint32(buf[HeaderSize:HeaderSize+4], c.bootTime)
	binary.BigEndian.PutUint32(buf[HeaderSize+4:TotalHeader], seq)

	var nonce [12]byte
	copy(nonce[0:4], c.salt[:])
	copy(nonce[4:12], buf[HeaderSize:TotalHeader])

	plain := make([]byte, plainLen)
	copy(plain, payload)
	for i := 0; i < padLen; i++ {
		plain[payloadLen+i] = byte(i + 1)
	}
	plain[plainLen-2] = byte(padLen)
	plain[plainLen-1] = nextHeader

	aad := buf[0:8]
	cipherText := c.aead.Seal(nil, nonce[:], plain, aad)
	buf = append(buf, cipherText...)

	return buf, nil
}

func (c *Cipher) Unpack(packet []byte) (uint8, []byte, error) {
	p := StripIPv4Header(packet)
	if len(p) < MinPacketSize {
		return 0, nil, ErrPacketTooShort
	}

	payloadWithTag := p[TotalHeader:]
	if len(payloadWithTag) < TagSize+MinTrailer {
		return 0, nil, ErrPacketTooShort
	}

	var nonce [12]byte
	copy(nonce[0:4], c.salt[:])
	copy(nonce[4:12], p[HeaderSize:TotalHeader])

	aad := p[0:8]
	plain, err := c.aead.Open(nil, nonce[:], payloadWithTag, aad)
	if err != nil {
		return 0, nil, ErrDecryption
	}

	if len(plain) < MinTrailer {
		return 0, nil, ErrPacketTooShort
	}

	padLen := int(plain[len(plain)-2])
	nextHeader := plain[len(plain)-1]

	if padLen+MinTrailer > len(plain) {
		return 0, nil, ErrInvalidPadding
	}

	payloadLen := len(plain) - MinTrailer - padLen
	for i := 0; i < padLen; i++ {
		if plain[payloadLen+i] != byte(i+1) {
			return 0, nil, ErrInvalidPadding
		}
	}

	return nextHeader, plain[:payloadLen], nil
}

type AntiReplay struct {
	mu           sync.Mutex
	lastBootTime uint32
	lastSeq      uint32
	bitmap       uint64
}

func NewAntiReplay() *AntiReplay {
	return &AntiReplay{}
}

func (r *AntiReplay) LastBootTime() uint32 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastBootTime
}

func (r *AntiReplay) Check(bootTime uint32, seq uint32) bool {
	if seq == 0 {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.lastBootTime == 0 {
		return true
	}
	if bootTime < r.lastBootTime {
		return false
	}
	if bootTime > r.lastBootTime {
		return true
	}
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

func (r *AntiReplay) Update(bootTime uint32, seq uint32) bool {
	if seq == 0 {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.lastBootTime == 0 || bootTime > r.lastBootTime {
		r.lastBootTime = bootTime
		r.lastSeq = seq
		r.bitmap = 1
		return true
	}
	if bootTime < r.lastBootTime {
		return false
	}
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
