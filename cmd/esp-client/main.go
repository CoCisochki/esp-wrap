package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/songgao/water"

	"esp-wrap/pkg/esp"
)

type Config struct {
	ServerAddr       string          `json:"server_addr"`
	ServerPubKey     string          `json:"server_public_key,omitempty"`
	UUID             string          `json:"uuid,omitempty"`
	PrivateKey       string          `json:"private_key,omitempty"`
	Key              string          `json:"key,omitempty"`
	ServerKey        string          `json:"server_key,omitempty"`
	BindInterface    string          `json:"bind_interface"`
	Gateway          string          `json:"gateway"`
	TunName          string          `json:"tun_name"`
	TunIP            string          `json:"tun_ip,omitempty"`
	TunCIDR          int             `json:"tun_cidr,omitempty"`
	TunMTU           int             `json:"tun_mtu,omitempty"`
	DisableTun       bool            `json:"disable_tun,omitempty"`
	DisableSocks     bool            `json:"disable_socks,omitempty"`
	SPI              json.RawMessage `json:"spi,omitempty"`
	KeepaliveSeconds int             `json:"keepalive_seconds"`
	SocksListen      string          `json:"socks_listen"`
}

func parseSPI(raw json.RawMessage) (uint32, error) {
	var strVal string
	if err := json.Unmarshal(raw, &strVal); err == nil {
		val, err := strconv.ParseUint(strVal, 0, 32)
		return uint32(val), err
	}
	var numVal uint64
	if err := json.Unmarshal(raw, &numVal); err == nil {
		return uint32(numVal), nil
	}
	return 0, errors.New("invalid spi format")
}

func configureFirewall() {
	exec.Command("iptables", "-C", "INPUT", "-p", "esp", "-j", "ACCEPT").Run()
	exec.Command("iptables", "-I", "INPUT", "-p", "esp", "-j", "ACCEPT").Run()

	exec.Command("iptables", "-C", "OUTPUT", "-p", "icmp", "--icmp-type", "3/2", "-j", "DROP").Run()
	exec.Command("iptables", "-I", "OUTPUT", "-p", "icmp", "--icmp-type", "3/2", "-j", "DROP").Run()
}

func cleanupFirewall() {
	exec.Command("iptables", "-D", "INPUT", "-p", "esp", "-j", "ACCEPT").Run()
	exec.Command("iptables", "-D", "OUTPUT", "-p", "icmp", "--icmp-type", "3/2", "-j", "DROP").Run()
}

func setupRoute(serverAddr, iface, gateway string) bool {
	if iface == "" || serverAddr == "" {
		return false
	}
	var args []string
	if gateway != "" {
		args = []string{"route", "replace", serverAddr, "via", gateway, "dev", iface, "metric", "50"}
	} else {
		args = []string{"route", "replace", serverAddr, "dev", iface, "metric", "50"}
	}
	if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
		log.Printf("route add warning: %v (%s)", err, out)
		return false
	}
	return true
}

func cleanupRoute(serverAddr, iface string) {
	if iface == "" || serverAddr == "" {
		return
	}
	exec.Command("ip", "route", "del", serverAddr, "dev", iface).Run()
}

func setupClientRouting(tunName, tunIP, gatewayIP string) {
	exec.Command("sysctl", "-w", "net.ipv4.conf.all.rp_filter=0").Run()
	exec.Command("sysctl", "-w", "net.ipv4.conf.default.rp_filter=0").Run()
	exec.Command("sysctl", "-w", fmt.Sprintf("net.ipv4.conf.%s.rp_filter=0", tunName)).Run()

	gw := gatewayIP
	if gw == "" {
		gw = "10.99.0.1"
	}
	exec.Command("ip", "route", "replace", "default", "via", gw, "dev", tunName, "table", "150").Run()
	exec.Command("ip", "rule", "del", "from", fmt.Sprintf("%s/32", tunIP), "table", "150").Run()
	exec.Command("ip", "rule", "add", "from", fmt.Sprintf("%s/32", tunIP), "table", "150", "priority", "150").Run()
}

func cleanupClientRouting(tunName, tunIP string) {
	exec.Command("ip", "rule", "del", "from", fmt.Sprintf("%s/32", tunIP), "table", "150").Run()
	exec.Command("ip", "route", "del", "default", "dev", tunName, "table", "150").Run()
}

type ClientCipherState struct {
	mu           sync.RWMutex
	cipher       *esp.Cipher
	ephemeralPub []byte
}

func (s *ClientCipherState) Get() (*esp.Cipher, []byte) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cipher, s.ephemeralPub
}

func (s *ClientCipherState) Set(c *esp.Cipher, pub []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cipher = c
	s.ephemeralPub = pub
}

func handleSocksClient(clientConn net.Conn, socksListen string, getTunIP func() string, tunName, dnsIP string) {
	defer clientConn.Close()

	buf := make([]byte, 262)
	if _, err := io.ReadFull(clientConn, buf[:2]); err != nil {
		return
	}
	if buf[0] != 0x05 {
		return
	}

	numMethods := int(buf[1])
	methods := make([]byte, numMethods)
	if _, err := io.ReadFull(clientConn, methods); err != nil {
		return
	}

	if _, err := clientConn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	reqHdr := make([]byte, 4)
	if _, err := io.ReadFull(clientConn, reqHdr); err != nil {
		return
	}
	if reqHdr[0] != 0x05 || reqHdr[1] != 0x01 {
		clientConn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var targetHost string
	switch reqHdr[3] {
	case 0x01:
		ipBuf := make([]byte, 4)
		if _, err := io.ReadFull(clientConn, ipBuf); err != nil {
			return
		}
		targetHost = net.IP(ipBuf).String()
	case 0x03:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(clientConn, lenBuf); err != nil {
			return
		}
		domainLen := int(lenBuf[0])
		domainBuf := make([]byte, domainLen)
		if _, err := io.ReadFull(clientConn, domainBuf); err != nil {
			return
		}
		targetHost = string(domainBuf)
	case 0x04:
		ipBuf := make([]byte, 16)
		if _, err := io.ReadFull(clientConn, ipBuf); err != nil {
			return
		}
		targetHost = net.IP(ipBuf).String()
	default:
		clientConn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(clientConn, portBuf); err != nil {
		return
	}
	targetPort := binary.BigEndian.Uint16(portBuf)
	targetAddr := fmt.Sprintf("%s:%d", targetHost, targetPort)

	targetDNS := dnsIP
	if targetDNS == "" {
		targetDNS = "8.8.8.8"
	}

	currentIP := getTunIP()
	if currentIP == "" {
		clientConn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	localTCPAddr := &net.TCPAddr{IP: net.ParseIP(currentIP)}
	dialer := &net.Dialer{
		LocalAddr: localTCPAddr,
		Timeout:   10 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, tunName)
			})
		},
		Resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					LocalAddr: &net.UDPAddr{IP: net.ParseIP(getTunIP())},
					Timeout:   5 * time.Second,
					Control: func(network, address string, c syscall.RawConn) error {
						return c.Control(func(fd uintptr) {
							syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, tunName)
						})
					},
				}
				return d.DialContext(ctx, "udp", net.JoinHostPort(targetDNS, "53"))
			},
		},
	}

	targetConn, err := dialer.DialContext(context.Background(), "tcp", targetAddr)
	if err != nil {
		clientConn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer targetConn.Close()

	resp := []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if parsed := net.ParseIP(currentIP).To4(); parsed != nil {
		copy(resp[4:8], parsed)
	}
	if tcpLocal, ok := targetConn.LocalAddr().(*net.TCPAddr); ok {
		if ip4 := tcpLocal.IP.To4(); ip4 != nil {
			copy(resp[4:8], ip4)
			binary.BigEndian.PutUint16(resp[8:10], uint16(tcpLocal.Port))
		}
	}
	if _, err := clientConn.Write(resp); err != nil {
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(targetConn, clientConn)
		if tc, ok := targetConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		io.Copy(clientConn, targetConn)
		if cc, ok := clientConn.(*net.TCPConn); ok {
			cc.CloseWrite()
		}
	}()
	wg.Wait()
}

func startSocksServer(ctx context.Context, socksListen string, getTunIP func() string, tunName, dnsIP string) {
	if socksListen == "" {
		return
	}
	ln, err := net.Listen("tcp", socksListen)
	if err != nil {
		log.Printf("socks5 listener failed: %v", err)
		return
	}
	defer ln.Close()

	log.Printf("embedded socks5 proxy listening on %s (bound to %s)", socksListen, tunName)

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}
		go handleSocksClient(conn, socksListen, getTunIP, tunName, dnsIP)
	}
}

func main() {
	configPath := flag.String("c", "client.json", "path to client.json")
	ifaceFlag := flag.String("i", "", "bind to specific physical interface (e.g. enp4s0, eth0, wlan0)")
	noTunFlag := flag.Bool("no-tun", false, "disable TUN interface creation and routing")
	noSocksFlag := flag.Bool("no-socks", false, "disable embedded SOCKS5 proxy")
	genKeyFlag := flag.Bool("gen-key", false, "generate X25519 keypair and exit")
	genUUIDFlag := flag.Bool("gen-uuid", false, "generate client UUID and exit")
	flag.Parse()

	if *genKeyFlag {
		curve := ecdh.X25519()
		priv, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			log.Fatalf("failed to generate key: %v", err)
		}
		privB64 := base64.StdEncoding.EncodeToString(priv.Bytes())
		pubB64 := base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes())
		fmt.Printf("PrivateKey: %s\n", privB64)
		fmt.Printf("PublicKey:  %s\n", pubB64)
		return
	}

	if *genUUIDFlag {
		fmt.Printf("UUID: %s\n", esp.GenerateUUID())
		return
	}

	data, err := os.ReadFile(*configPath)
	if err != nil {
		log.Fatalf("failed to read config: %v", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Fatalf("failed to parse config: %v", err)
	}

	if *ifaceFlag != "" {
		cfg.BindInterface = *ifaceFlag
	}
	if *noTunFlag {
		cfg.DisableTun = true
	}
	if *noSocksFlag {
		cfg.DisableSocks = true
	}

	if cfg.TunName == "" {
		cfg.TunName = "tun-esp0"
	}
	if cfg.TunMTU <= 0 {
		cfg.TunMTU = 1360
	}
	if cfg.KeepaliveSeconds <= 0 {
		cfg.KeepaliveSeconds = 15
	}
	if !cfg.DisableSocks && cfg.SocksListen == "" {
		cfg.SocksListen = "127.0.0.1:10951"
	}

	if cfg.BindInterface == "" || cfg.Gateway == "" {
		out, err := exec.Command("ip", "-4", "route", "show", "default").Output()
		if err == nil {
			lines := strings.Split(string(out), "\n")
			for _, line := range lines {
				fields := strings.Fields(line)
				var dev, gw string
				for i, f := range fields {
					if f == "dev" && i+1 < len(fields) {
						dev = fields[i+1]
					}
					if f == "via" && i+1 < len(fields) {
						gw = fields[i+1]
					}
				}
				if dev != "" && gw != "" {
					if _, err := os.Stat("/sys/class/net/" + dev + "/device"); err == nil {
						if cfg.BindInterface == "" {
							cfg.BindInterface = dev
						}
						if cfg.Gateway == "" {
							cfg.Gateway = gw
						}
						break
					} else if cfg.BindInterface == "" {
						cfg.BindInterface = dev
						if cfg.Gateway == "" {
							cfg.Gateway = gw
						}
					}
				}
			}
		}
	}
	if cfg.Gateway == "" && cfg.BindInterface != "" {
		out, err := exec.Command("ip", "-4", "route", "show", "default", "dev", cfg.BindInterface).Output()
		if err == nil {
			fields := strings.Fields(string(out))
			for i, f := range fields {
				if f == "via" && i+1 < len(fields) {
					cfg.Gateway = fields[i+1]
					break
				}
			}
		}
	}

	clientBootTime := uint32(time.Now().Unix())
	curve := ecdh.X25519()

	var spiVal uint32
	var uuidBytes [16]byte
	var serverPubKey *ecdh.PublicKey
	cipherState := &ClientCipherState{}

	if cfg.ServerPubKey != "" && cfg.UUID != "" {
		pubB, err := base64.StdEncoding.DecodeString(cfg.ServerPubKey)
		if err != nil || len(pubB) != 32 {
			log.Fatalf("invalid server_public_key: %v", err)
		}
		sp, err := curve.NewPublicKey(pubB)
		if err != nil {
			log.Fatalf("invalid server curve point: %v", err)
		}
		serverPubKey = sp

		ub, err := esp.ParseUUID(cfg.UUID)
		if err != nil {
			log.Fatalf("invalid uuid: %v", err)
		}
		uuidBytes = ub
		spiVal = esp.DeriveRealitySPI(ub[:], pubB)

		renewCipher := func() error {
			ePriv, err := curve.GenerateKey(rand.Reader)
			if err != nil {
				return err
			}
			ePub := ePriv.PublicKey()
			sec, err := ePriv.ECDH(serverPubKey)
			if err != nil {
				return err
			}
			sKey, sSalt := esp.DeriveRealitySessionKey(sec, uuidBytes[:])
			ciph, err := esp.NewCipherWithKeySalt(sKey, sSalt, clientBootTime)
			if err != nil {
				return err
			}
			cipherState.Set(ciph, ePub.Bytes())
			return nil
		}

		if err := renewCipher(); err != nil {
			log.Fatalf("cipher initialization failed: %v", err)
		}
	} else if cfg.UUID != "" && (cfg.PrivateKey != "" || cfg.Key != "" || cfg.ServerKey != "") {
		kStr := cfg.PrivateKey
		if kStr == "" {
			kStr = cfg.Key
		}
		if kStr == "" {
			kStr = cfg.ServerKey
		}
		ub, err := esp.ParseUUID(cfg.UUID)
		if err != nil {
			log.Fatalf("invalid uuid: %v", err)
		}
		uuidBytes = ub
		spiVal = esp.DeriveSPIFromUUID(ub[:])

		masterKeyBytes, err := esp.DecodeMasterKey(kStr)
		if err != nil {
			log.Fatalf("failed to decode master key: %v", err)
		}
		aesKey, salt := esp.DeriveUserKeyAndSalt(masterKeyBytes, ub[:])
		ciph, err := esp.NewCipherWithKeySalt(aesKey, salt, clientBootTime)
		if err != nil {
			log.Fatalf("cipher initialization failed: %v", err)
		}
		cipherState.Set(ciph, nil)
	} else if cfg.Key != "" {
		spi, err := parseSPI(cfg.SPI)
		if err != nil {
			log.Fatalf("invalid spi: %v", err)
		}
		spiVal = spi
		keyBytes, err := hex.DecodeString(cfg.Key)
		if err != nil {
			log.Fatalf("invalid hex key: %v", err)
		}
		ciph, err := esp.NewCipher(keyBytes, clientBootTime)
		if err != nil {
			log.Fatalf("cipher initialization failed: %v", err)
		}
		cipherState.Set(ciph, nil)
	} else {
		log.Fatalf("config must provide 'server_public_key' and 'uuid'")
	}

	serverIP := net.ParseIP(cfg.ServerAddr)
	if serverIP == nil {
		log.Fatalf("invalid server address: %s", cfg.ServerAddr)
	}
	serverRemoteAddr := &net.IPAddr{IP: serverIP}

	configureFirewall()
	defer cleanupFirewall()

	rawConn, err := net.ListenPacket("ip4:50", "0.0.0.0")
	if err != nil {
		log.Fatalf("failed to open raw esp socket: %v", err)
	}
	defer rawConn.Close()

	if cfg.BindInterface != "" {
		rawSys, err := rawConn.(*net.IPConn).SyscallConn()
		if err == nil {
			rawSys.Control(func(fd uintptr) {
				syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, cfg.BindInterface)
			})
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	var tunDev *water.Interface
	var tunMu sync.Mutex
	var assignedTunIP string
	handshakeDone := make(chan struct{})
	var handshakeOnce sync.Once
	var lastServerPacket atomic.Int64

	go func() {
		<-sigChan
		log.Printf("shutting down client...")
		cancel()
		rawConn.Close()
		tunMu.Lock()
		if tunDev != nil {
			cleanupClientRouting(cfg.TunName, assignedTunIP)
			tunDev.Close()
			exec.Command("ip", "link", "del", cfg.TunName).Run()
		}
		tunMu.Unlock()
	}()

	var seq atomic.Uint32

	getTunIP := func() string {
		tunMu.Lock()
		defer tunMu.Unlock()
		return assignedTunIP
	}

	initTunDevice := func(tunIP, gatewayIP string, cidr, mtu int, dnsIP string) {
		tunMu.Lock()
		defer tunMu.Unlock()

		assignedTunIP = tunIP
		if cfg.DisableTun {
			log.Printf("TUN creation disabled by configuration (no-tun mode). Dynamic IP: %s", tunIP)
			return
		}

		if tunDev != nil {
			if assignedTunIP != tunIP {
				cleanupClientRouting(cfg.TunName, assignedTunIP)
				if assignedTunIP != "" {
					exec.Command("ip", "addr", "del", fmt.Sprintf("%s/%d", assignedTunIP, cidr), "dev", cfg.TunName).Run()
				}
				cidrStr := fmt.Sprintf("%s/%d", tunIP, cidr)
				exec.Command("ip", "addr", "add", cidrStr, "dev", cfg.TunName).Run()
				setupClientRouting(cfg.TunName, tunIP, gatewayIP)
				log.Printf("assigned dynamic IP updated: %s", tunIP)
			}
			return
		}

		var err error
		tunDev, err = water.New(water.Config{
			DeviceType: water.TUN,
			PlatformSpecificParams: water.PlatformSpecificParams{
				Name: cfg.TunName,
			},
		})
		if err != nil {
			exec.Command("ip", "link", "del", cfg.TunName).Run()
			tunDev, err = water.New(water.Config{
				DeviceType: water.TUN,
				PlatformSpecificParams: water.PlatformSpecificParams{
					Name: cfg.TunName,
				},
			})
			if err != nil {
				log.Fatalf("failed to create tun device %s: %v", cfg.TunName, err)
			}
		}

		exec.Command("ip", "addr", "flush", "dev", cfg.TunName).Run()
		cidrStr := fmt.Sprintf("%s/%d", tunIP, cidr)
		if out, err := exec.Command("ip", "addr", "add", cidrStr, "dev", cfg.TunName).CombinedOutput(); err != nil {
			log.Fatalf("failed to assign ip to tun: %v, out: %s", err, string(out))
		}
		if out, err := exec.Command("ip", "link", "set", "dev", cfg.TunName, "mtu", strconv.Itoa(mtu), "up").CombinedOutput(); err != nil {
			log.Fatalf("failed to bring tun up: %v, out: %s", err, string(out))
		}

		setupClientRouting(cfg.TunName, tunIP, gatewayIP)
		if !cfg.DisableSocks && cfg.SocksListen != "" && cfg.SocksListen != "none" {
			go startSocksServer(ctx, cfg.SocksListen, getTunIP, cfg.TunName, dnsIP)
		}
	}

	isReady := func() bool {
		tunMu.Lock()
		defer tunMu.Unlock()
		if cfg.DisableTun {
			return assignedTunIP != ""
		}
		return tunDev != nil
	}

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(time.Duration(cfg.KeepaliveSeconds) * time.Second)
		defer ticker.Stop()

		handshakeTicker := time.NewTicker(1 * time.Second)
		defer handshakeTicker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-handshakeTicker.C:
				ready := isReady()
				if !ready {
					ciph, epub := cipherState.Get()
					if ciph != nil {
						pSeq := seq.Add(1)
						var packed []byte
						if len(epub) == 32 {
							packed, err = ciph.PackHandshakeReq(spiVal, pSeq, epub, uuidBytes[:])
						} else {
							reqData := esp.EncodeHandshakeReq(clientBootTime, uuidBytes[:])
							packed, err = ciph.Pack(spiVal, pSeq, esp.ProtoControl, reqData)
						}
						if err == nil {
							rawConn.WriteTo(packed, serverRemoteAddr)
						}
					}
				}
			case <-ticker.C:
				ready := isReady()
				if ready {
					now := time.Now().Unix()
					last := lastServerPacket.Load()
					if last > 0 && now-last > 60 && serverPubKey != nil {
						log.Printf("session inactive >60s, renewing Reality handshake...")
						lastServerPacket.Store(now)
						newBootTime := uint32(time.Now().Unix())
						ePriv, err := curve.GenerateKey(rand.Reader)
						if err == nil {
							ePub := ePriv.PublicKey()
							sec, err := ePriv.ECDH(serverPubKey)
							if err == nil {
								sKey, sSalt := esp.DeriveRealitySessionKey(sec, uuidBytes[:])
								ciph, err := esp.NewCipherWithKeySalt(sKey, sSalt, newBootTime)
								if err == nil {
									cipherState.Set(ciph, ePub.Bytes())
									pSeq := seq.Add(1)
									packed, err := ciph.PackHandshakeReq(spiVal, pSeq, ePub.Bytes(), uuidBytes[:])
									if err == nil {
										rawConn.WriteTo(packed, serverRemoteAddr)
									}
								}
							}
						}
						continue
					}

					ciph, _ := cipherState.Get()
					if ciph != nil {
						pSeq := seq.Add(1)
						packed, err := ciph.Pack(spiVal, pSeq, esp.ProtoControl, []byte{esp.ControlKeepalive})
						if err == nil {
							rawConn.WriteTo(packed, serverRemoteAddr)
						}
					}
				}
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 65535)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			n, _, err := rawConn.ReadFrom(buf)
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					continue
				}
			}

			if n < esp.MinPacketSize {
				continue
			}

			packet := esp.StripIPv4Header(buf[:n])
			if len(packet) < esp.MinPacketSize {
				continue
			}

			packetSPI, err := esp.PeekSPI(packet)
			if err != nil || packetSPI != spiVal {
				continue
			}

			ciph, _ := cipherState.Get()
			if ciph == nil {
				continue
			}

			nextHdr, inner, err := ciph.Unpack(packet)
			if err != nil {
				continue
			}

			lastServerPacket.Store(time.Now().Unix())

			if nextHdr == esp.ProtoControl {
				if len(inner) > 0 && inner[0] == esp.ControlHandshakeResp {
					resp, err := esp.DecodeHandshakeResp(inner)
					if err == nil {
						assignedIPStr := resp.AssignedIP.String()
						gatewayIPStr := resp.GatewayIP.String()
						dnsStr := resp.DNS.String()
						initTunDevice(assignedIPStr, gatewayIPStr, resp.CIDR, resp.MTU, dnsStr)
						handshakeOnce.Do(func() {
							log.Printf("handshake completed! Assigned Dynamic IP: %s/16, Gateway: %s", assignedIPStr, gatewayIPStr)
							close(handshakeDone)
						})
					}
				}
				continue
			}

			if nextHdr == esp.ProtoIPv4 && len(inner) > 0 {
				tunMu.Lock()
				dev := tunDev
				tunMu.Unlock()
				if dev != nil {
					dev.Write(inner)
				}
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		select {
		case <-ctx.Done():
			return
		case <-handshakeDone:
		}

		tunMu.Lock()
		dev := tunDev
		tunMu.Unlock()
		if dev == nil {
			return
		}

		buf := make([]byte, 65535)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			n, err := dev.Read(buf)
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					continue
				}
			}

			if n == 0 {
				continue
			}

			ciph, _ := cipherState.Get()
			if ciph == nil {
				continue
			}

			pSeq := seq.Add(1)
			packed, err := ciph.Pack(spiVal, pSeq, esp.ProtoIPv4, buf[:n])
			if err != nil {
				continue
			}

			if _, err := rawConn.WriteTo(packed, serverRemoteAddr); err != nil {
				select {
				case <-ctx.Done():
					return
				default:
				}
			}
		}
	}()

	tunState := cfg.TunName
	if cfg.DisableTun {
		tunState = "disabled (no-tun)"
	}
	if cfg.BindInterface != "" {
		log.Printf("esp-client running. Target: %s, spi: 0x%08x, tun: %s, dev: %s", cfg.ServerAddr, spiVal, tunState, cfg.BindInterface)
	} else {
		log.Printf("esp-client running. Target: %s, spi: 0x%08x, tun: %s", cfg.ServerAddr, spiVal, tunState)
	}
	wg.Wait()

	tunMu.Lock()
	if tunDev != nil {
		cleanupClientRouting(cfg.TunName, assignedTunIP)
		tunDev.Close()
		exec.Command("ip", "link", "del", cfg.TunName).Run()
	}
	tunMu.Unlock()

	log.Printf("client exited cleanly")
}
