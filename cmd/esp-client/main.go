package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
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
	ServerAddr       string `json:"server_addr"`
	ServerPubKey     string `json:"server_public_key"`
	UUID             string `json:"uuid"`
	BindInterface    string `json:"bind_interface"`
	Gateway          string `json:"gateway"`
	TunName          string `json:"tun_name"`
	TunMTU           int    `json:"tun_mtu,omitempty"`
	DisableTun       bool   `json:"disable_tun,omitempty"`
	DisableSocks     bool   `json:"disable_socks,omitempty"`
	KeepaliveSeconds int    `json:"keepalive_seconds"`
	SocksListen      string `json:"socks_listen"`
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

type SessionStateManager struct {
	mu               sync.RWMutex
	activeSPI        uint32
	activeCipher     *esp.SessionCipher
	activeAntiReplay *esp.AntiReplay

	prevSPI        uint32
	prevCipher     *esp.SessionCipher
	prevAntiReplay *esp.AntiReplay
	prevExpiry     time.Time
}

func (s *SessionStateManager) GetActive() (uint32, *esp.SessionCipher) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.activeSPI, s.activeCipher
}

func (s *SessionStateManager) ActiveSPI() uint32 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.activeSPI
}

func (s *SessionStateManager) Rotate(newSPI uint32, newCipher *esp.SessionCipher) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.activeSPI != 0 && s.activeCipher != nil {
		s.prevSPI = s.activeSPI
		s.prevCipher = s.activeCipher
		s.prevAntiReplay = s.activeAntiReplay
		s.prevExpiry = time.Now().Add(30 * time.Second)
	}

	s.activeSPI = newSPI
	s.activeCipher = newCipher
	s.activeAntiReplay = esp.NewAntiReplay()
}

func (s *SessionStateManager) LookupInbound(spi uint32) (*esp.SessionCipher, *esp.AntiReplay, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if spi == s.activeSPI && s.activeCipher != nil {
		return s.activeCipher, s.activeAntiReplay, true
	}
	if spi == s.prevSPI && s.prevCipher != nil && time.Now().Before(s.prevExpiry) {
		return s.prevCipher, s.prevAntiReplay, true
	}
	return nil, nil, false
}

func handleSocksClient(ctx context.Context, clientConn net.Conn, socksListen string, getTunIP func() string, tunName, dnsIP string) {
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
				bindToDevice(fd, tunName)
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
							bindToDevice(fd, tunName)
						})
					},
				}
				return d.DialContext(ctx, "udp", net.JoinHostPort(targetDNS, "53"))
			},
		},
	}

	targetConn, err := dialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		clientConn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer targetConn.Close()

	resp := []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if parsed := net.ParseIP(currentIP).To4(); parsed != nil {
		copy(resp[4:8], parsed)
	}
	if _, err := clientConn.Write(resp); err != nil {
		return
	}

	errChan := make(chan error, 2)
	go func() {
		_, err := io.Copy(targetConn, clientConn)
		errChan <- err
	}()
	go func() {
		_, err := io.Copy(clientConn, targetConn)
		errChan <- err
	}()

	select {
	case <-errChan:
	case <-ctx.Done():
	}
}

func startSocksServer(ctx context.Context, socksListen string, getTunIP func() string, tunName, dnsIP string) {
	if socksListen == "" || socksListen == "none" {
		return
	}
	ln, err := net.Listen("tcp", socksListen)
	if err != nil {
		log.Printf("socks5 listen failed on %s: %v", socksListen, err)
		return
	}
	defer ln.Close()

	log.Printf("embedded SOCKS5 proxy listening on %s (routed via %s)", socksListen, tunName)
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
		go handleSocksClient(ctx, conn, socksListen, getTunIP, tunName, dnsIP)
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

	curve := ecdh.X25519()

	if cfg.ServerPubKey == "" || cfg.UUID == "" {
		log.Fatalf("server_public_key and uuid are required in %s", *configPath)
	}

	pubB, err := base64.StdEncoding.DecodeString(cfg.ServerPubKey)
	if err != nil || len(pubB) != 32 {
		log.Fatalf("invalid server_public_key: %v", err)
	}
	serverPubKey, err := curve.NewPublicKey(pubB)
	if err != nil {
		log.Fatalf("invalid server public key point: %v", err)
	}

	uuidBytes, err := esp.ParseUUID(cfg.UUID)
	if err != nil {
		log.Fatalf("invalid uuid: %v", err)
	}

	authSPI := esp.DeriveAuthSPI(pubB, uuidBytes)
	mac1Key := esp.DeriveMac1Key(pubB, uuidBytes)

	configureFirewall()
	defer cleanupFirewall()

	if cfg.BindInterface != "" {
		setupRoute(cfg.ServerAddr, cfg.BindInterface, cfg.Gateway)
		defer cleanupRoute(cfg.ServerAddr, cfg.BindInterface)
	}

	rawConn, err := net.ListenPacket("ip4:50", "0.0.0.0")
	if err != nil {
		log.Fatalf("failed to open raw socket: %v (run with sudo / CAP_NET_RAW)", err)
	}
	defer rawConn.Close()

	if cfg.BindInterface != "" {
		rawConnFile, err := rawConn.(*net.IPConn).File()
		if err == nil {
			fd := rawConnFile.Fd()
			_ = bindToDevice(fd, cfg.BindInterface)
			rawConnFile.Close()
		}
	}

	serverRemoteAddr, err := net.ResolveIPAddr("ip4", cfg.ServerAddr)
	if err != nil {
		log.Fatalf("failed to resolve server addr %s: %v", cfg.ServerAddr, err)
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
	var seq atomic.Uint32
	var lastRekeyTime atomic.Int64

	sessionState := &SessionStateManager{}

	var currentEphPrivMu sync.RWMutex
	var currentEphPriv *ecdh.PrivateKey

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
		tunDev, err = esp.CreateTun(cfg.TunName)
		if err != nil {
			exec.Command("ip", "link", "del", cfg.TunName).Run()
			tunDev, err = esp.CreateTun(cfg.TunName)
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

	sendHandshake := func() {
		ePriv, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			log.Printf("failed to generate ephemeral key: %v", err)
			return
		}
		currentEphPrivMu.Lock()
		currentEphPriv = ePriv
		currentEphPrivMu.Unlock()

		reqPkt, _, err := esp.PackHandshakeReq(authSPI, ePriv.PublicKey().Bytes(), mac1Key)
		if err == nil {
			rawConn.WriteTo(reqPkt, serverRemoteAddr)
		}
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
				if sessionState.ActiveSPI() == 0 {
					sendHandshake()
				}
			case <-ticker.C:
				sSPI, ciph := sessionState.GetActive()
				if sSPI != 0 {
					now := time.Now().Unix()
					last := lastServerPacket.Load()
					rekeyTime := lastRekeyTime.Load()

					if rekeyTime > 0 && (now-rekeyTime > 7200 || seq.Load() >= (1<<30)) {
						log.Printf("initiating periodic rekey (2h session or seq threshold)...")
						sendHandshake()
						continue
					}

					if last > 0 && now-last > 60 {
						log.Printf("session inactive >60s, renewing handshake...")
						lastServerPacket.Store(now)
						sendHandshake()
						continue
					}

					if ciph != nil {
						pSeq := seq.Add(1)
						packed, err := ciph.Pack(sSPI, pSeq, esp.ProtoControl, []byte{esp.ControlKeepalive})
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

			if n < 4 {
				continue
			}

			packet := esp.StripIPv4Header(buf[:n])
			if len(packet) < 4 {
				continue
			}

			packetSPI, err := esp.PeekSPI(packet)
			if err != nil {
				continue
			}

			if packetSPI == authSPI {
				currentEphPrivMu.RLock()
				ePriv := currentEphPriv
				currentEphPrivMu.RUnlock()

				if ePriv == nil {
					continue
				}

				staticDH, err := ePriv.ECDH(serverPubKey)
				if err != nil {
					continue
				}

				serverEphPubBytes, resp, err := esp.UnpackHandshakeResp(packet, authSPI, staticDH, ePriv.PublicKey().Bytes())
				if err != nil {
					continue
				}

				serverEphPub, err := curve.NewPublicKey(serverEphPubBytes)
				if err != nil {
					continue
				}

				ephemeralDH, err := ePriv.ECDH(serverEphPub)
				if err != nil {
					continue
				}

				clientCipher, _, err := esp.DeriveSessionCiphers(
					staticDH,
					ephemeralDH,
					pubB,
					ePriv.PublicKey().Bytes(),
					serverEphPubBytes,
					uuidBytes,
				)
				if err != nil {
					continue
				}

				sessionState.Rotate(resp.SessionSPI, clientCipher)
				seq.Store(0)
				lastRekeyTime.Store(time.Now().Unix())
				lastServerPacket.Store(time.Now().Unix())

				assignedIPStr := resp.AssignedIP.String()
				gatewayIPStr := resp.GatewayIP.String()
				dnsStr := resp.DNS.String()

				initTunDevice(assignedIPStr, gatewayIPStr, resp.CIDR, resp.MTU, dnsStr)
				handshakeOnce.Do(func() {
					log.Printf("handshake completed! SessionSPI: 0x%08x, Assigned Dynamic IP: %s/16, Gateway: %s", resp.SessionSPI, assignedIPStr, gatewayIPStr)
					close(handshakeDone)
				})
				continue
			}

			ciph, ar, ok := sessionState.LookupInbound(packetSPI)
			if !ok {
				continue
			}

			if len(packet) < esp.MinPacketSize {
				continue
			}

			pktSeq := binary.BigEndian.Uint32(packet[4:8])
			if !ar.Check(pktSeq) {
				continue
			}

			nextHdr, inner, err := ciph.Unpack(packet)
			if err != nil {
				continue
			}

			ar.Update(pktSeq)
			lastServerPacket.Store(time.Now().Unix())

			if nextHdr == esp.ProtoControl {
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

			sSPI, ciph := sessionState.GetActive()
			if ciph == nil || sSPI == 0 {
				continue
			}

			pSeq := seq.Add(1)
			packed, err := ciph.Pack(sSPI, pSeq, esp.ProtoIPv4, buf[:n])
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
		log.Printf("esp-client running. Target: %s, AuthSPI: 0x%08x, tun: %s, dev: %s", cfg.ServerAddr, authSPI, tunState, cfg.BindInterface)
	} else {
		log.Printf("esp-client running. Target: %s, AuthSPI: 0x%08x, tun: %s", cfg.ServerAddr, authSPI, tunState)
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
